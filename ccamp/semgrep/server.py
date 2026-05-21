"""Semgrep MCP 服务。

将本地的 semgrep CLI 封装为 MCP tool，通过 streamable HTTP 暴露给 AI 编排器。

提供的工具：
  - get_semgrep_command_preview：预览实际会执行的 Semgrep 命令（调试用）
  - scan_project_with_semgrep：执行扫描并返回归一化的问题列表

整体流程：
  1. 校验项目路径
  2. 定位 semgrep 可执行文件
  3. 构造命令行
  4. subprocess 执行扫描
  5. 解析 JSON 报告
  6. 归一化 finding 结构
  7. 返回精简结果给调用方
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from ccamp.shared.constants import (
    DEFAULT_EXCLUDES,
    LOCAL_NO_PROXY,
    SEMGREP_DEFAULT_CONFIGS,
)
from ccamp.shared.env import get_env_int, get_required_env, load_project_env
from ccamp.shared.paths import resolve_project_path
from ccamp.shared.stats import count_by_severity
from ccamp.shared.text import tail_text


# ============================================================================
# MCP 实例
# ============================================================================

mcp = FastMCP("semgrep_mcp")
load_project_env()

# ============================================================================
# 环境初始化
# ============================================================================
# 梯子/代理工具经常会全局设置 HTTP_PROXY。MCP 服务只监听 127.0.0.1,
# 不走代理；如果被代理拦截会报错 502。这里显式设置 NO_PROXY 规避。
os.environ.setdefault("NO_PROXY", LOCAL_NO_PROXY)
os.environ.setdefault("no_proxy", LOCAL_NO_PROXY)

# ============================================================================
# 二进制文件定位
# ============================================================================

SEMGREP_BIN = "semgrep"


def find_semgrep_binary() -> str:
    """定位 semgrep 可执行文件。

    Windows 下通过 pipx install semgrep 安装后，semgrep.exe 通常在
    %USERPROFILE%\\.local\\bin，而当前 shell 的 PATH 可能尚未刷新。
    因此先查 PATH，再查 pipx 的常见安装位置。
    """
    configured = os.getenv("SEMGREP_BIN")
    if configured and Path(configured).exists():
        return configured

    semgrep_path = shutil.which(SEMGREP_BIN)
    if semgrep_path:
        return semgrep_path

    # pipx 在 Windows 上的默认安装路径
    windows_pipx_path = Path.home() / ".local" / "bin" / "semgrep.exe"
    if windows_pipx_path.exists():
        return str(windows_pipx_path)

    raise RuntimeError(
        "Semgrep executable not found. "
        "Make sure `semgrep --version` works, "
        "or set SEMGREP_BIN to your semgrep.exe path."
    )


# ============================================================================
# 命令构造
# ============================================================================


def build_semgrep_command(output_file: Path) -> list[str]:
    """构造 Semgrep CE 命令行。

    每个参数作为独立列表元素传给 subprocess（不是拼成 shell 字符串），
    避免路径中的空格或特殊字符被 cmd.exe 二次解释。
    """
    command = [find_semgrep_binary(), "scan"]

    for config in SEMGREP_DEFAULT_CONFIGS:
        command.extend(["--config", config])

    for exclude in DEFAULT_EXCLUDES:
        command.extend(["--exclude", exclude])

    command.extend([
        ".",
        "--json",
        "--output",
        str(output_file),
    ])
    return command


# ============================================================================
# 结果解析与归一化
# ============================================================================


def load_semgrep_report(report_path: Path) -> dict[str, Any]:
    """读取 Semgrep 生成的 JSON 报告。

    处理两种常见问题：
    - UTF-8 BOM 头部（utf-8-sig）
    - 部分 Windows 项目路径/源码片段混入非 UTF-8 字节（用 replacement char 兜底）
    """
    try:
        return json.loads(report_path.read_text(encoding="utf-8-sig"))
    except UnicodeDecodeError:
        return json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Failed to parse Semgrep JSON report: {report_path}"
        ) from exc


def normalize_result(result: dict[str, Any]) -> dict[str, Any]:
    """把一条 Semgrep 原始 finding 转成稳定结构。

    Semgrep 原始 JSON 包含大量 metadata。这里只保留对报告生成有用的字段：
    位置、规则 ID、严重级别、CWE/OWASP 映射、置信度、影响、可能性、参考链接。
    这样做的目的是：
    1. 减少 token 消耗（丢弃 profiling、路径扫描列表等噪音字段）
    2. 提供稳定的数据契约 — 无论 Semgrep 版本如何变化，报告总是拿到相同结构
    """
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    start = result.get("start", {})
    end = result.get("end", {})

    return {
        "rule_id": result.get("check_id"),
        "severity": extra.get("severity"),
        "file": result.get("path"),
        "start_line": start.get("line"),
        "start_col": start.get("col"),
        "end_line": end.get("line"),
        "end_col": end.get("col"),
        "message": extra.get("message"),
        "category": metadata.get("category"),
        "technology": metadata.get("technology", []),
        "cwe": metadata.get("cwe", []),
        "owasp": metadata.get("owasp", []),
        "confidence": metadata.get("confidence"),
        "impact": metadata.get("impact"),
        "likelihood": metadata.get("likelihood"),
        "vulnerability_class": metadata.get("vulnerability_class", []),
        "references": metadata.get("references", []),
        "source": metadata.get("source"),
    }


# ============================================================================
# MCP 工具
# ============================================================================


@mcp.tool
def get_semgrep_command_preview(project_path: str) -> dict[str, Any]:
    """预览项目扫描时实际会执行的 Semgrep 命令。

    纯只读操作 — 不会真正启动扫描。
    用于调试路径、规则配置、排除目录等问题。
    """
    project_dir = resolve_project_path(project_path)
    output_file = project_dir / "reports" / "semgrep.json"

    return {
        "project_path": str(project_dir),
        "output_file": str(output_file),
        "command": build_semgrep_command(output_file),
        "configs": SEMGREP_DEFAULT_CONFIGS,
        "excludes": DEFAULT_EXCLUDES,
    }


@mcp.tool
def scan_project_with_semgrep(
    project_path: str,
    timeout_seconds: int = 900,
    max_findings: int = 0,
    keep_raw_report: bool = True,
) -> dict[str, Any]:
    """使用 Semgrep CE 扫描本地项目，返回归一化 finding。

    关键设计决策 — 临时目录隔离：
    Semgrep 输出先写到被扫描项目外的临时目录，扫描完成后再复制到
    reports/ 目录。如果一开始就写到项目内，Semgrep 可能把自己刚生成
    的 .json 报告也纳入扫描范围，造成嵌套扫描和异常。

    Args:
        project_path:     本地项目目录路径。
        timeout_seconds:  Semgrep 扫描超时（秒）。
        max_findings:     最多返回的问题数量。0 表示返回全部。
        keep_raw_report:  是否把原始 semgrep.json 保存到项目 reports 目录。

    Returns:
        包含 tool 标识、版本、扫描摘要、归一化 finding 列表的字典。
    """
    project_dir = resolve_project_path(project_path)

    # 先将输出写到项目外的临时目录，避免 Semgrep 递归扫描自己的输出
    temp_dir = Path(tempfile.mkdtemp(prefix="semgrep-mcp-"))
    output_file = temp_dir / "semgrep.json"
    raw_report_path: Path | None = None

    if keep_raw_report:
        report_dir = project_dir / "reports"
        report_dir.mkdir(exist_ok=True)
        raw_report_path = report_dir / "semgrep.json"

    command = build_semgrep_command(output_file)

    try:
        process = subprocess.run(
            command,
            cwd=str(project_dir),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"Semgrep scan timed out after {timeout_seconds}s for {project_dir}"
        ) from exc

    # 扫描失败时可以没有输出文件（如语法错误导致 Semgrep 提前退出）。
    # 此时返回详细的错误信息而不是崩溃，方便调试。
    if not output_file.exists():
        raise RuntimeError(
            {
                "message": "Semgrep did not produce a JSON report.",
                "project_path": str(project_dir),
                "command": command,
                "returncode": process.returncode,
                "stdout_tail": tail_text(process.stdout, 4000),
                "stderr_tail": tail_text(process.stderr, 4000),
            }
        )

    raw_report = load_semgrep_report(output_file)
    if raw_report_path is not None:
        shutil.copyfile(output_file, raw_report_path)

    raw_results = raw_report.get("results", [])
    findings = [normalize_result(result) for result in raw_results]

    if max_findings > 0:
        truncated = len(findings) > max_findings
        returned_findings = findings[:max_findings]
    else:
        truncated = False
        returned_findings = findings

    return {
        "tool": "semgrep",
        "semgrep_version": raw_report.get("version"),
        "project_path": str(project_dir),
        "raw_report_path": (
            str(raw_report_path) if raw_report_path is not None else None
        ),
        "configs": SEMGREP_DEFAULT_CONFIGS,
        "excludes": DEFAULT_EXCLUDES,
        "scanned_paths": raw_report.get("paths", {}).get("scanned", []),
        "errors": raw_report.get("errors", []),
        "total_findings": len(findings),
        "returned_findings": len(returned_findings),
        "truncated": truncated,
        "severity_count": count_by_severity(findings),
        "findings": returned_findings,
        "semgrep_returncode": process.returncode,
        "stdout_tail": tail_text(process.stdout, 2000),
        "stderr_tail": tail_text(process.stderr, 2000),
    }


# ============================================================================
# 入口
# ============================================================================

if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=get_required_env("SEMGREP_MCP_HOST"),
        port=get_env_int("SEMGREP_MCP_PORT"),
        path=get_required_env("SEMGREP_MCP_PATH"),
    )
