"""OpenGrep MCP 服务。

将 opengrep CLI 封装为 MCP tool。OpenGrep 是 Semgrep 的替代品,
使用 semgrep-rules 规则仓库，支持 30 种语言的规则目录。

提供的工具：
  - get_opengrep_command_preview：预览 OpenGrep 命令（调试用）
  - scan_project_with_opengrep：执行扫描并返回归一化问题列表

关键差异 vs Semgrep：
  - 规则来自 semgrep-rules 仓库的 30 个语言目录
  - 支持 --jobs 和 --timeout 参数控制并发和单规则超时
  - 规则目录根可能包含非规则 YAML（如 .pre-commit-config.yaml），需要过滤
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
    OPENGREP_DEFAULT_RULESET_DIRS,
)
from ccamp.shared.env import get_env_int, get_required_env, load_project_env
from ccamp.shared.paths import resolve_project_path
from ccamp.shared.stats import count_by_severity
from ccamp.shared.text import tail_text


# ============================================================================
# MCP 实例 & 环境初始化
# ============================================================================

mcp = FastMCP("opengrep_mcp")

os.environ.setdefault("NO_PROXY", LOCAL_NO_PROXY)
os.environ.setdefault("no_proxy", LOCAL_NO_PROXY)

load_project_env()

# ============================================================================
# 二进制文件定位
# ============================================================================

OPENGREP_BIN = "opengrep"


def find_opengrep_binary() -> str:
    """定位 opengrep 可执行文件。

    查找优先级：
    1. .env 中指定的 OPENGREP_BIN 路径
    2. PATH 中的 opengrep / opengrep.exe / opengrep_windows_x86.exe
    """
    # 显式配置优先
    configured = os.getenv("OPENGREP_BIN")
    if configured and Path(configured).exists():
        return configured

    # PATH 查找
    for candidate in [OPENGREP_BIN, "opengrep.exe", "opengrep_windows_x86.exe"]:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved

    raise RuntimeError(
        "OpenGrep executable not found. "
        "Make sure `opengrep --version` works, "
        "or set OPENGREP_BIN to your opengrep.exe path."
    )


# ============================================================================
# 规则路径管理
# ============================================================================


def default_rules_root() -> Path:
    """返回 semgrep-rules 仓库的根目录。

    可通过 OPENGREP_RULES_DIR 覆盖，否则用默认路径。
    """
    configured = os.getenv("OPENGREP_RULES_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    raise RuntimeError("Missing required environment variable: OPENGREP_RULES_DIR")


def has_yaml_rules(path: Path) -> bool:
    """判断路径是否包含 YAML 规则文件。

    文件: 检查后缀是否为 .yaml / .yml
    目录: 递归检查是否包含任何 .yaml / .yml
    """
    if path.is_file():
        return path.suffix.lower() in {".yaml", ".yml"}
    if not path.is_dir():
        return False
    return any(path.rglob("*.yaml")) or any(path.rglob("*.yml"))


def expand_rule_paths(rule_paths: list[str] | None = None) -> list[Path]:
    """将用户传入的规则路径展开为实际可用的规则目录列表。

    展开逻辑：
    1. 如果传入了 rule_paths，解析每一项
    2. 否则检查 OPENGREP_RULE_PATHS 环境变量（分号分隔）
    3. 都没指定则用 default_rules_root + 30 个语言目录

    特殊处理 semgrep-rules 仓库根目录：
    仓库根包含 .pre-commit-config.yaml 等非规则文件，直接传根目录
    给 opengrep 会导致解析错误。这里检测到根目录后，自动展开为
    已知的 30 个语言规则子目录。

    Args:
        rule_paths: 用户指定的规则路径列表（文件或目录）。

    Returns:
        已验证存在且包含 YAML 规则的目录/文件列表。

    Raises:
        ValueError: 指定的路径不存在，或找不到任何规则文件。
    """
    # 确定原始路径来源
    if rule_paths:
        raw_paths = [
            Path(item).expanduser().resolve()
            for item in rule_paths
            if item.strip()
        ]
    else:
        env_paths = [
            item.strip()
            for item in os.getenv("OPENGREP_RULE_PATHS", "").split(";")
            if item.strip()
        ]
        raw_paths = [
            Path(item).expanduser().resolve() for item in env_paths
        ]

    # 都没指定则使用默认规则目录集
    if not raw_paths:
        root = default_rules_root()
        raw_paths = [root / dirname for dirname in OPENGREP_DEFAULT_RULESET_DIRS]

    expanded: list[Path] = []
    for path in raw_paths:
        if not path.exists():
            raise ValueError(f"OpenGrep rule path does not exist: {path}")

        # 检测 semgrep-rules 仓库根目录 —
        # .pre-commit-config.yaml 是其特征文件，说明当前路径是仓库根而非规则目录
        if path.is_dir() and (path / ".pre-commit-config.yaml").exists():
            for dirname in OPENGREP_DEFAULT_RULESET_DIRS:
                child = path / dirname
                if child.exists() and has_yaml_rules(child):
                    expanded.append(child)
            continue

        if has_yaml_rules(path):
            expanded.append(path)

    if not expanded:
        raise ValueError("No OpenGrep YAML rule files were found.")

    return expanded


# ============================================================================
# 命令构造
# ============================================================================


def build_opengrep_command(
    output_file: Path,
    rule_paths: list[str] | None = None,
    extra_excludes: list[str] | None = None,
    jobs: int | None = None,
    timeout_per_rule: int | None = None,
) -> list[str]:
    """构造 opengrep 扫描命令。

    参数独立传入 subprocess（不拼 shell 字符串），避免特殊字符问题。
    --json 和 --json-output 是 opengrep 特有的输出参数。
    """
    command = [find_opengrep_binary(), "scan"]

    for rule_path in expand_rule_paths(rule_paths):
        command.extend(["--config", str(rule_path)])

    excludes = DEFAULT_EXCLUDES + (extra_excludes or [])
    for exclude in excludes:
        command.extend(["--exclude", exclude])

    if jobs is not None:
        command.extend(["--jobs", str(jobs)])

    if timeout_per_rule is not None:
        command.extend(["--timeout", str(timeout_per_rule)])

    command.extend([
        ".",
        "--json",
        "--json-output",
        str(output_file),
    ])
    return command


# ============================================================================
# 结果解析与归一化
# ============================================================================


def load_opengrep_report(report_path: Path) -> dict[str, Any]:
    """读取 OpenGrep 生成的 JSON 报告。

    OpenGrep 基于 Semgrep 引擎，输出格式和已知问题相同：
    - UTF-8 BOM 头部
    - 可能的非 UTF-8 字节混入
    """
    try:
        return json.loads(report_path.read_text(encoding="utf-8-sig"))
    except UnicodeDecodeError:
        return json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Failed to parse OpenGrep JSON report: {report_path}"
        ) from exc


def normalize_result(result: dict[str, Any]) -> dict[str, Any]:
    """把一条 OpenGrep 原始 finding 转成稳定结构。

    OpenGrep 的输出格式与 Semgrep 高度相似，但 severity 和 fix 字段
    可能在顶层而不是 extra 里 — 这里做了兼容处理。
    """
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    start = result.get("start", {})
    end = result.get("end", {})

    return {
        "rule_id": result.get("check_id"),
        "severity": result.get("severity") or extra.get("severity"),
        "file": result.get("path"),
        "start_line": start.get("line"),
        "start_col": start.get("col"),
        "end_line": end.get("line"),
        "end_col": end.get("col"),
        "message": extra.get("message") or result.get("message"),
        "category": metadata.get("category"),
        "technology": metadata.get("technology", []),
        "cwe": metadata.get("cwe", []),
        "owasp": metadata.get("owasp", []),
        "confidence": metadata.get("confidence"),
        "impact": metadata.get("impact"),
        "likelihood": metadata.get("likelihood"),
        "vulnerability_class": metadata.get("vulnerability_class", []),
        "references": metadata.get("references", []),
        "lines": result.get("lines"),          # OpenGrep 特有: 问题行内容
        "fix": extra.get("fix") or result.get("fix"),  # OpenGrep 特有: 修复建议
    }


# ============================================================================
# MCP 工具
# ============================================================================


@mcp.tool
def get_opengrep_command_preview(
    project_path: str,
    rule_paths: list[str] | None = None,
    extra_excludes: list[str] | None = None,
    jobs: int | None = None,
    timeout_per_rule: int | None = None,
) -> dict[str, Any]:
    """预览 OpenGrep 扫描命令（纯只读，不执行扫描）。

    用于调试规则路径展开、排除目录、并发参数等配置。
    """
    project_dir = resolve_project_path(project_path)
    output_file = project_dir / "reports" / "opengrep.json"
    resolved_rule_paths = [
        str(path) for path in expand_rule_paths(rule_paths)
    ]

    return {
        "project_path": str(project_dir),
        "output_file": str(output_file),
        "opengrep_binary": find_opengrep_binary(),
        "rule_paths": resolved_rule_paths,
        "excludes": DEFAULT_EXCLUDES + (extra_excludes or []),
        "command": build_opengrep_command(
            output_file=output_file,
            rule_paths=rule_paths,
            extra_excludes=extra_excludes,
            jobs=jobs,
            timeout_per_rule=timeout_per_rule,
        ),
    }


@mcp.tool
def scan_project_with_opengrep(
    project_path: str,
    rule_paths: list[str] | None = None,
    extra_excludes: list[str] | None = None,
    timeout_seconds: int = 900,
    max_findings: int = 0,
    keep_raw_report: bool = True,
    jobs: int | None = None,
    timeout_per_rule: int | None = None,
) -> dict[str, Any]:
    """使用 OpenGrep 扫描本地项目，返回归一化 finding。

    与 Semgrep 扫描类似，但规则来自 semgrep-rules 仓库。
    使用 tempfile.TemporaryDirectory 确保扫描输出先写到项目外，
    避免 OpenGrep 递归扫描自己的报告文件。
    """
    project_dir = resolve_project_path(project_path)
    resolved_rule_paths = [
        str(path) for path in expand_rule_paths(rule_paths)
    ]

    raw_report_path: Path | None = None
    if keep_raw_report:
        report_dir = project_dir / "reports"
        report_dir.mkdir(exist_ok=True)
        raw_report_path = report_dir / "opengrep.json"

    # 临时目录隔离 — 与 Semgrep 相同的策略
    with tempfile.TemporaryDirectory(prefix="opengrep-mcp-") as temp_dir_name:
        output_file = Path(temp_dir_name) / "opengrep.json"
        command = build_opengrep_command(
            output_file=output_file,
            rule_paths=rule_paths,
            extra_excludes=extra_excludes,
            jobs=jobs,
            timeout_per_rule=timeout_per_rule,
        )

        try:
            process = subprocess.run(
                command,
                cwd=str(project_dir),
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"OpenGrep scan timed out after {timeout_seconds}s for {project_dir}"
            ) from exc

        if not output_file.exists():
            raise RuntimeError({
                "message": "OpenGrep did not produce a JSON report.",
                "project_path": str(project_dir),
                "command": command,
                "returncode": process.returncode,
                "stdout_tail": tail_text(process.stdout, 4000),
                "stderr_tail": tail_text(process.stderr, 4000),
            })

        raw_report = load_opengrep_report(output_file)
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
        "tool": "opengrep",
        "opengrep_version": raw_report.get("version"),
        "project_path": str(project_dir),
        "raw_report_path": (
            str(raw_report_path) if raw_report_path is not None else None
        ),
        "rule_paths": resolved_rule_paths,
        "excludes": DEFAULT_EXCLUDES + (extra_excludes or []),
        "scanned_paths": raw_report.get("paths", {}).get("scanned", []),
        "errors": raw_report.get("errors", []),
        "total_findings": len(findings),
        "returned_findings": len(returned_findings),
        "truncated": truncated,
        "severity_count": count_by_severity(findings),
        "findings": returned_findings,
        "opengrep_returncode": process.returncode,
        "stdout_tail": tail_text(process.stdout, 2000),
        "stderr_tail": tail_text(process.stderr, 2000),
    }


# ============================================================================
# 入口
# ============================================================================

if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=get_required_env("OPENGREP_MCP_HOST"),
        port=get_env_int("OPENGREP_MCP_PORT"),
        path=get_required_env("OPENGREP_MCP_PATH"),
    )
