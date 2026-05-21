"""SonarQube MCP 服务。

将 sonar-scanner CLI + SonarQube Web API 封装为 MCP tool。
相比于 Semgrep（一次性输出 JSON），SonarQube 的流程更复杂：

提供的工具：
  - get_sonar_scanner_command_preview：预览 scanner 命令（调试用）
  - scan_project_with_sonarqube：完整扫描流程
  - get_sonarqube_project_summary：读取已有分析结果（跳过扫描）

完整扫描流程：
  1. 校验项目路径 & 加载配置
  2. 自动编译 Java 项目（Maven / Gradle）
  3. 运行 sonar-scanner 上传分析
  4. 如失败，尝试跳过 JS/TS/CSS 降级重试
  5. 轮询 SonarQube Compute Engine 任务完成
  6. 通过 Web API 获取质量门禁、指标、问题
  7. 归一化结果返回
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from ccamp.shared.constants import (
    JS_TS_CSS_EXCLUSIONS,
    LOCAL_NO_PROXY,
    SONAR_DEFAULT_METRICS,
    SONAR_EXCLUDES,
)
from ccamp.shared.env import get_env_int, get_required_env, load_project_env
from ccamp.shared.paths import resolve_project_path
from ccamp.shared.stats import count_by
from ccamp.shared.text import tail_text


# ============================================================================
# MCP 实例 & 环境初始化
# ============================================================================

mcp = FastMCP("sonarqube_mcp")

os.environ.setdefault("NO_PROXY", LOCAL_NO_PROXY)
os.environ.setdefault("no_proxy", LOCAL_NO_PROXY)

# 在模块加载时读取 .env，确保 SONAR_HOST_URL / SONAR_TOKEN 等变量可用。
# MCP 服务器是独立进程，需要自己加载项目 .env。
load_project_env()


# ============================================================================
# 工具链定位
# ============================================================================


def get_required_env(name: str) -> str:
    """读取必需环境变量；缺失时给出明确错误信息。"""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def find_sonar_scanner() -> str:
    """定位 sonar-scanner 可执行文件。

    优先用 .env 里的 SONAR_SCANNER_BIN（Windows 下 SonarScanner 通常是
    解压出来的 ZIP 目录，不一定在 PATH 里）。
    如果没配置，再尝试 PATH 查找 sonar-scanner 或 sonar-scanner.bat。
    """
    configured = os.getenv("SONAR_SCANNER_BIN")
    if configured and Path(configured).exists():
        return configured

    for candidate in ["sonar-scanner", "sonar-scanner.bat"]:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved

    raise RuntimeError(
        "SonarScanner executable not found. Set SONAR_SCANNER_BIN in .env."
    )


# ============================================================================
# 命令构造
# ============================================================================


def get_js_node_maxspace() -> int:
    """返回 SonarQube JS/TS 分析器的 Node.js 最大堆内存 (MB)。

    大型 Node/TypeScript 项目（如 Juice Shop）会触发 SonarQube JS bridge,
    默认内存可能不够，表现为 WebSocket connection closed abnormally。
    可通过 .env 的 SONAR_JS_NODE_MAXSPACE 覆盖，默认 8192 MB。
    """
    raw_value = os.getenv("SONAR_JS_NODE_MAXSPACE", "8192")
    try:
        return max(1024, int(raw_value))
    except ValueError:
        return 8192


def get_sonar_exclusions() -> list[str]:
    """返回 SonarScanner 排除规则。

    基础排除项 (SONAR_EXCLUDES) 放通用排除（node_modules 等）。
    对于特定靶场项目（如 Juice Shop 的 data/static/codefixes/**），
    可以通过 .env 的 SONAR_EXCLUSIONS 追加额外规则（逗号分隔）。
    """
    extra = [
        item.strip()
        for item in os.getenv("SONAR_EXCLUSIONS", "").split(",")
        if item.strip()
    ]
    return SONAR_EXCLUDES + extra


def build_scanner_command(
    project_dir: Path,
    project_key: str,
    project_name: str,
    host_url: str,
    token: str,
    sources: str,
    exclusions: list[str],
    java_binaries: list[Path] | None = None,
) -> list[str]:
    """构造 sonar-scanner 命令行。

    每个参数独立作为一个列表元素 — 不拼成 shell 字符串。
    这样路径中的空格、特殊字符不会被 cmd.exe/PowerShell 二次解释，
    也避免了 token 被 shell history 暴露的风险。
    """
    command = [
        find_sonar_scanner(),
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.projectName={project_name}",
        f"-Dsonar.sources={sources}",
        f"-Dsonar.host.url={host_url}",
        f"-Dsonar.token={token}",
        f"-Dsonar.projectBaseDir={project_dir}",
        f"-Dsonar.exclusions={','.join(exclusions)}",
        "-Dsonar.sourceEncoding=UTF-8",
        f"-Dsonar.javascript.node.maxspace={get_js_node_maxspace()}",
    ]

    # 如果指定了自定义 Node.js 路径（如项目需要特定版本），使用 SONAR_NODEJS_EXECUTABLE
    node_executable = os.getenv("SONAR_NODEJS_EXECUTABLE")
    if node_executable:
        command.append(f"-Dsonar.nodejs.executable={node_executable}")

    # Java 项目需要 classpath — 告诉 SonarQube 编译产物的位置
    if java_binaries:
        command.append(
            "-Dsonar.java.binaries="
            + ",".join(str(path) for path in java_binaries)
        )

    return command


# ============================================================================
# Java 项目自动构建
# ============================================================================


def has_java_sources(project_dir: Path) -> bool:
    """判断项目中是否存在 Java 源码（在 src/ 下）。"""
    return any((project_dir / "src").glob("**/*.java"))


def detect_java_binaries(project_dir: Path) -> list[Path]:
    """查找 Java 编译产物目录。

    SonarJava 分析 .java 文件时需要 classpath 环境。
    常见位置：
    - Maven:  target/classes
    - Gradle: build/classes/java/main
    """
    candidates = [
        project_dir / "target" / "classes",
        project_dir / "build" / "classes" / "java" / "main",
    ]
    return [path for path in candidates if path.exists()]


def build_java_project(
    project_dir: Path, timeout_seconds: int
) -> subprocess.CompletedProcess[str] | None:
    """扫描前自动编译 Java 项目。

    如果项目没有 Java 源码，或者 class 文件已存在，直接返回 None。
    自动检测构建工具：Maven Wrapper > Maven > Gradle Wrapper > Gradle。
    编译只到 class 阶段（跳过测试），因为 SonarQube 只需要 classpath。
    """
    if not has_java_sources(project_dir) or detect_java_binaries(project_dir):
        return None

    # 按优先级尝试构建工具
    if (project_dir / "mvnw.cmd").exists():
        command = [str(project_dir / "mvnw.cmd"), "-DskipTests", "compile"]
    elif shutil.which("mvn"):
        command = ["mvn", "-DskipTests", "compile"]
    elif (project_dir / "gradlew.bat").exists():
        command = [str(project_dir / "gradlew.bat"), "classes"]
    elif shutil.which("gradle"):
        command = ["gradle", "classes"]
    else:
        return None

    return subprocess.run(
        command,
        cwd=str(project_dir),
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
    )


# ============================================================================
# JS/TS 降级重试判断
# ============================================================================


def should_retry_without_js_ts(process: subprocess.CompletedProcess[str]) -> bool:
    """判断是否需要跳过 JS/TS/CSS 重试。

    SonarQube 的 JS/TS 分析器通过 WebSocket 与 Node.js bridge 通信。
    某些大型项目（Juice Shop 等）会触发 WebSocket 异常导致扫描中断。
    如果用户没有通过 SONAR_RETRY_WITHOUT_JS_TS 显式关闭，就在检测到
    这类失败时自动降级 — 牺牲 JS/TS 分析覆盖度，换取其他语言的完整结果。

    可通过 .env 设置 SONAR_RETRY_WITHOUT_JS_TS=false 禁用此行为。
    """
    enabled = os.getenv("SONAR_RETRY_WITHOUT_JS_TS", "true").lower()
    if enabled in {"0", "false", "no", "off"}:
        return False

    combined_output = f"{process.stdout or ''}\n{process.stderr or ''}"
    return (
        "Analysis of JS/TS files failed" in combined_output
        or "WebSocket connection closed abnormally" in combined_output
        or "Sensor JavaScript/TypeScript/CSS analysis" in combined_output
    )


# ============================================================================
# 扫描执行
# ============================================================================


def run_sonar_scanner(
    command: list[str],
    project_dir: Path,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    """执行 sonar-scanner 并返回完整进程结果。"""
    return subprocess.run(
        command,
        cwd=str(project_dir),
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
    )


# ============================================================================
# SonarQube Web API 调用
# ============================================================================


def sonar_api_get(
    path: str,
    params: dict[str, Any] | None = None,
    host_url: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """调用 SonarQube Web API (GET)。

    使用 HTTP Basic Auth（token 作为用户名，密码留空）。
    直接使用 urllib 避免引入额外依赖 — SonarQube API 只需要 GET 请求。

    Args:
        path:     API 路径，如 "/api/qualitygates/project_status"
        params:   URL 查询参数
        host_url: SonarQube 服务器地址（默认从环境变量读取）
        token:    SonarQube token（默认从环境变量读取）
    """
    host = (host_url or get_required_env("SONAR_HOST_URL")).rstrip("/")
    sonar_token = token or get_required_env("SONAR_TOKEN")

    query = urllib.parse.urlencode(params or {}, doseq=True)
    url = f"{host}{path}"
    if query:
        url = f"{url}?{query}"

    # SonarQube 用 Basic Auth: token 作为用户名，密码留空
    credentials = base64.b64encode(
        f"{sonar_token}:".encode("utf-8")
    ).decode("ascii")

    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"SonarQube API HTTP {exc.code} for {url}: {body}"
        ) from exc


# ============================================================================
# Compute Engine 任务轮询
# ============================================================================


def read_report_task(project_dir: Path) -> dict[str, str]:
    """读取 sonar-scanner 生成的 report-task.txt。

    scanner 结束只代表"分析报告已上传到 SonarQube"，不代表服务端已经
    处理完成。ceTaskId 在这个文件里，后续用它轮询 Compute Engine 状态。
    """
    task_file = project_dir / ".scannerwork" / "report-task.txt"
    if not task_file.exists():
        return {}

    task_info: dict[str, str] = {}
    for raw_line in task_file.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        task_info[key.strip()] = value.strip()
    return task_info


def wait_for_ce_task(
    project_dir: Path,
    host_url: str,
    token: str,
    timeout_seconds: int = 120,
    interval_seconds: float = 2.0,
) -> dict[str, Any]:
    """轮询等待 SonarQube Compute Engine 处理完成。

    不等待 CE 任务就查 issues/metrics 会拿到旧数据或空数据 —
    因为 scanner 只负责上传，真正的分析在服务端异步完成。

    轮询间隔 2 秒是为了在等待时间和 API 请求频率之间平衡。
    120 秒超时通常足够中小型项目；非常大的项目可能需要更长时间。
    """
    task_info = read_report_task(project_dir)
    task_id = task_info.get("ceTaskId")
    if not task_id:
        return {"waited": False, "reason": "missing ceTaskId"}

    deadline = time.time() + timeout_seconds
    last_response: dict[str, Any] = {}

    while time.time() < deadline:
        last_response = sonar_api_get(
            "/api/ce/task",
            {"id": task_id},
            host_url=host_url,
            token=token,
        )
        task = last_response.get("task", {})
        status = task.get("status")

        if status in {"SUCCESS", "FAILED", "CANCELED"}:
            return {
                "waited": True,
                "task_id": task_id,
                "status": status,
                "analysis_id": task.get("analysisId"),
                "raw": task,
            }

        time.sleep(interval_seconds)

    return {
        "waited": True,
        "task_id": task_id,
        "status": "TIMEOUT",
        "raw": last_response.get("task", {}),
    }


# ============================================================================
# 结果归一化
# ============================================================================


def normalize_issue(issue: dict[str, Any]) -> dict[str, Any]:
    """把一条 SonarQube issue 转成稳定结构。

    SonarQube API 返回的 issue 对象包含大量内部字段（tags, debt,
    textRange 等）。只保留报告需要的关键字段，控制 token 消耗。
    """
    text_range = issue.get("textRange") or {}
    return {
        "key": issue.get("key"),
        "rule": issue.get("rule"),
        "severity": issue.get("severity"),
        "type": issue.get("type"),       # BUG / VULNERABILITY / CODE_SMELL
        "status": issue.get("status"),
        "resolution": issue.get("resolution"),
        "component": issue.get("component"),
        "project": issue.get("project"),
        "line": issue.get("line"),
        "start_line": text_range.get("startLine"),
        "end_line": text_range.get("endLine"),
        "message": issue.get("message"),
        "effort": issue.get("effort"),
        "debt": issue.get("debt"),
        "tags": issue.get("tags", []),
        "creation_date": issue.get("creationDate"),
        "update_date": issue.get("updateDate"),
    }


def fetch_sonar_issues(
    project_key: str,
    max_issues: int,
    host_url: str,
    token: str,
) -> dict[str, Any]:
    """Read SonarQube issues with pagination.

    SonarQube limits one API page to 500 items. max_issues <= 0 means return all
    issues available from the server.
    """
    requested_limit = max_issues if max_issues > 0 else None
    page_size = 500
    page = 1
    total = 0
    raw_issues: list[dict[str, Any]] = []

    while True:
        if requested_limit is None:
            current_page_size = page_size
        else:
            remaining = requested_limit - len(raw_issues)
            if remaining <= 0:
                break
            current_page_size = min(page_size, remaining)

        response = sonar_api_get(
            "/api/issues/search",
            {
                "componentKeys": project_key,
                "resolved": "false",
                "p": page,
                "ps": current_page_size,
            },
            host_url=host_url,
            token=token,
        )
        total = response.get("total", total)
        page_issues = response.get("issues", [])
        raw_issues.extend(page_issues)

        if not page_issues or len(raw_issues) >= total:
            break
        if requested_limit is not None and len(raw_issues) >= requested_limit:
            break

        page += 1

    issues = [normalize_issue(issue) for issue in raw_issues]
    return {
        "total": total or len(issues),
        "issues": issues,
        "truncated": (total or len(issues)) > len(issues),
    }


def normalize_metrics(raw: dict[str, Any]) -> dict[str, str]:
    """把 SonarQube measures 列表转成 {metric: value} 字典。

    API 返回的是 component.measures 列表，每个元素是 {metric, value}。
    转成简单的 key-value 映射方便后续处理和 JSON 序列化。
    """
    component = raw.get("component") or {}
    measures = component.get("measures") or []
    return {
        measure.get("metric"): measure.get("value")
        for measure in measures
        if measure.get("metric") is not None
    }


# ============================================================================
# MCP 工具
# ============================================================================


@mcp.tool
def get_sonar_scanner_command_preview(
    project_path: str,
    project_key: str,
    project_name: str | None = None,
    sources: str = ".",
) -> dict[str, Any]:
    """预览实际会执行的 sonar-scanner 命令。

    token 会被脱敏为 <redacted> — 此工具输出可能进入日志或聊天记录。
    用于调试路径、排除规则、Java classpath 等问题，不会真正启动扫描。
    """
    project_dir = resolve_project_path(project_path)
    host_url = get_required_env("SONAR_HOST_URL")
    token = get_required_env("SONAR_TOKEN")

    command = build_scanner_command(
        project_dir=project_dir,
        project_key=project_key,
        project_name=project_name or project_key,
        host_url=host_url,
        token=token,
        sources=sources,
        exclusions=get_sonar_exclusions(),
        java_binaries=detect_java_binaries(project_dir),
    )

    # 脱敏 — 替换 token 参数的内容
    redacted_command = [
        "-Dsonar.token=<redacted>"
        if item.startswith("-Dsonar.token=")
        else item
        for item in command
    ]

    return {
        "project_path": str(project_dir),
        "project_key": project_key,
        "host_url": host_url,
        "command": redacted_command,
        "exclusions": get_sonar_exclusions(),
    }


@mcp.tool
def scan_project_with_sonarqube(
    project_path: str,
    project_key: str,
    project_name: str | None = None,
    sources: str = ".",
    timeout_seconds: int = 900,
    ce_wait_seconds: int = 600,
    max_issues: int = 0,
) -> dict[str, Any]:
    """对本地项目运行 sonar-scanner，返回完整审计数据。

    完整流程：
    1. 自动编译 Java 项目（如有必要）
    2. 运行 sonar-scanner 上传分析
    3. 如失败且符合条件，降级跳过 JS/TS/CSS 重试
    4. 轮询 CE 任务直到完成
    5. 通过 Web API 获取质量门禁、指标、问题
    6. 归一化并返回

    Args:
        project_path:    本地项目目录路径。
        project_key:     SonarQube 项目 key（用于 API 查询和报告标识）。
        project_name:    SonarQube 项目显示名（默认同 project_key）。
        sources:         源码相对路径（默认 "."）。
        timeout_seconds: scanner 和 CE 等待的总超时。
        max_issues:      最多返回的问题数。

    Returns:
        包含 tool 标识、质量门禁、指标、问题列表的字典。
    """
    project_dir = resolve_project_path(project_path)
    host_url = get_required_env("SONAR_HOST_URL")
    token = get_required_env("SONAR_TOKEN")

    # ---- 自动编译 Java 项目 ----
    build_process = build_java_project(project_dir, timeout_seconds)
    if build_process is not None and build_process.returncode != 0:
        raise RuntimeError({
            "message": "Java project build failed before SonarScanner.",
            "project_path": str(project_dir),
            "returncode": build_process.returncode,
            "stdout_tail": tail_text(build_process.stdout, 4000),
            "stderr_tail": tail_text(build_process.stderr, 4000),
        })

    java_binaries = detect_java_binaries(project_dir)
    command = build_scanner_command(
        project_dir=project_dir,
        project_key=project_key,
        project_name=project_name or project_key,
        host_url=host_url,
        token=token,
        sources=sources,
        exclusions=get_sonar_exclusions(),
        java_binaries=java_binaries,
    )

    # ---- 运行 scanner（可能 retry 一次） ----
    scan_mode = "full"
    first_failure: dict[str, Any] | None = None

    try:
        process = run_sonar_scanner(command, project_dir, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"SonarScanner timed out after {timeout_seconds}s for {project_dir}"
        ) from exc

    if process.returncode != 0:
        # 检查是否为 JS/TS/CSS 分析器故障 —
        # 如果是，排除 JS/TS/CSS 文件重新扫描
        if should_retry_without_js_ts(process):
            first_failure = {
                "returncode": process.returncode,
                "stdout_tail": tail_text(process.stdout, 4000),
                "stderr_tail": tail_text(process.stderr, 4000),
            }
            scan_mode = "fallback_without_js_ts_css"
            fallback_command = build_scanner_command(
                project_dir=project_dir,
                project_key=project_key,
                project_name=project_name or project_key,
                host_url=host_url,
                token=token,
                sources=sources,
                exclusions=get_sonar_exclusions() + JS_TS_CSS_EXCLUSIONS,
                java_binaries=java_binaries,
            )
            process = run_sonar_scanner(
                fallback_command, project_dir, timeout_seconds
            )

        if process.returncode != 0:
            raise RuntimeError({
                "message": "SonarScanner execution failed.",
                "project_path": str(project_dir),
                "returncode": process.returncode,
                "scan_mode": scan_mode,
                "first_failure": first_failure,
                "stdout_tail": tail_text(process.stdout, 4000),
                "stderr_tail": tail_text(process.stderr, 4000),
            })

    # ---- 等待 SonarQube 后台处理完成 ----
    ce_task = wait_for_ce_task(
        project_dir=project_dir,
        host_url=host_url,
        token=token,
        timeout_seconds=ce_wait_seconds,
    )
    if ce_task.get("status") in {"FAILED", "CANCELED", "TIMEOUT"}:
        raise RuntimeError({
            "message": "SonarQube Compute Engine task did not finish.",
            "project_path": str(project_dir),
            "ce_task": ce_task,
        })

    # ---- 从 Web API 获取报告数据 ----
    quality_gate = sonar_api_get(
        "/api/qualitygates/project_status",
        {"projectKey": project_key},
        host_url=host_url,
        token=token,
    )
    metrics = sonar_api_get(
        "/api/measures/component",
        {
            "component": project_key,
            "metricKeys": ",".join(SONAR_DEFAULT_METRICS),
        },
        host_url=host_url,
        token=token,
    )
    issues_response = fetch_sonar_issues(
        project_key=project_key,
        max_issues=max_issues,
        host_url=host_url,
        token=token,
    )
    issues = issues_response["issues"]

    return {
        "tool": "sonarqube",
        "project_path": str(project_dir),
        "project_key": project_key,
        "host_url": host_url,
        "quality_gate": quality_gate.get("projectStatus", {}),
        "metrics": normalize_metrics(metrics),
        "total_issues": issues_response["total"],
        "returned_issues": len(issues),
        "truncated": issues_response["truncated"],
        "issue_count_by_severity": count_by(issues, "severity"),
        "issue_count_by_type": count_by(issues, "type"),
        "issues": issues,
        "scan_mode": scan_mode,
        "first_failure": first_failure,
        "ce_task": ce_task,
        "java_binaries": [str(path) for path in java_binaries],
        "java_build_ran": build_process is not None,
        "scanner_returncode": process.returncode,
        "stdout_tail": tail_text(process.stdout, 2000),
        "stderr_tail": tail_text(process.stderr, 2000),
    }


@mcp.tool
def get_sonarqube_project_summary(
    project_key: str,
    max_issues: int = 0,
) -> dict[str, Any]:
    """读取已分析过的 SonarQube 项目的指标、质量门禁和问题。

    不运行 sonar-scanner — 直接从 API 读取服务端已有数据。
    适用场景：scanner 已经跑过，只想读取服务端已有结果。

    Args:
        project_key: SonarQube 项目 key。
        max_issues:  最多返回的问题数。

    Returns:
        与 scan_project_with_sonarqube 结构相同的摘要（无 scanner 相关信息）。
    """
    host_url = get_required_env("SONAR_HOST_URL")
    token = get_required_env("SONAR_TOKEN")

    quality_gate = sonar_api_get(
        "/api/qualitygates/project_status",
        {"projectKey": project_key},
        host_url=host_url,
        token=token,
    )
    metrics = sonar_api_get(
        "/api/measures/component",
        {
            "component": project_key,
            "metricKeys": ",".join(SONAR_DEFAULT_METRICS),
        },
        host_url=host_url,
        token=token,
    )
    issues_response = fetch_sonar_issues(
        project_key=project_key,
        max_issues=max_issues,
        host_url=host_url,
        token=token,
    )
    issues = issues_response["issues"]

    return {
        "tool": "sonarqube",
        "project_key": project_key,
        "host_url": host_url,
        "quality_gate": quality_gate.get("projectStatus", {}),
        "metrics": normalize_metrics(metrics),
        "total_issues": issues_response["total"],
        "returned_issues": len(issues),
        "truncated": issues_response["truncated"],
        "issue_count_by_severity": count_by(issues, "severity"),
        "issue_count_by_type": count_by(issues, "type"),
        "issues": issues,
    }


# ============================================================================
# 入口
# ============================================================================

if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=get_required_env("SONAR_MCP_HOST"),
        port=get_env_int("SONAR_MCP_PORT"),
        path=get_required_env("SONAR_MCP_PATH"),
    )
