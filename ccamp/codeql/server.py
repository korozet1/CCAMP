from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from ccamp.shared.constants import LOCAL_NO_PROXY
from ccamp.shared.env import get_env_int, get_required_env, load_project_env
from ccamp.shared.paths import resolve_project_path
from ccamp.shared.stats import count_by_severity
from ccamp.shared.text import tail_text


mcp = FastMCP("codeql_mcp")

os.environ.setdefault("NO_PROXY", LOCAL_NO_PROXY)
os.environ.setdefault("no_proxy", LOCAL_NO_PROXY)

load_project_env()

CODEQL_BIN = "codeql"
DEFAULT_DATABASE_DIR = "codeql_db"
DEFAULT_OUTPUT_FORMAT = "csv"
CODEQL_CSV_COLUMNS = [
    "Name",
    "Description",
    "Severity",
    "Message",
    "Path",
    "Start line",
    "Start column",
    "End line",
    "End column",
]


def find_codeql_binary() -> str:
    configured = os.getenv("CODEQL_BIN")
    if configured and Path(configured).exists():
        return configured

    for candidate in [CODEQL_BIN, "codeql.exe"]:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved

    raise RuntimeError(
        "CodeQL executable not found. Make sure `codeql version` works, "
        "or set CODEQL_BIN to your codeql.exe path."
    )


def default_database_name() -> str:
    return os.getenv("CODEQL_DEFAULT_DATABASE", DEFAULT_DATABASE_DIR)


def default_output_format() -> str:
    return os.getenv("CODEQL_DEFAULT_FORMAT", DEFAULT_OUTPUT_FORMAT)


def default_queries_for_language(language: str) -> str:
    configured = os.getenv("CODEQL_QUERIES")
    if configured:
        return configured
    return f"codeql/{language}-queries"


def output_suffix(output_format: str) -> str:
    if output_format in {"sarif", "sarif-latest"}:
        return "sarif"
    if output_format == "json":
        return "json"
    return "csv"


def resolve_database_path(project_dir: Path, database_path: str | None) -> Path:
    if database_path:
        path = Path(database_path).expanduser()
        if not path.is_absolute():
            path = project_dir / path
        return path.resolve()
    return (project_dir / default_database_name()).resolve()


def resolve_output_path(
    project_dir: Path,
    output_file: str | None,
    output_format: str,
) -> Path:
    if output_file:
        path = Path(output_file).expanduser()
        if not path.is_absolute():
            path = project_dir / path
        return path.resolve()

    report_dir = project_dir / "reports"
    return (report_dir / f"codeql-result.{output_suffix(output_format)}").resolve()


def build_database_create_command(
    project_dir: Path,
    database_dir: Path,
    language: str,
    source_root: str,
    build_mode: str,
    overwrite: bool,
    no_run_unnecessary_builds: bool,
) -> list[str]:
    command = [
        find_codeql_binary(),
        "database",
        "create",
        str(database_dir),
        f"--language={language}",
        f"--source-root={source_root}",
        f"--build-mode={build_mode}",
    ]

    if no_run_unnecessary_builds:
        command.append("--no-run-unnecessary-builds")
    if overwrite:
        command.append("--overwrite")

    return command


def build_database_analyze_command(
    database_dir: Path,
    queries: str,
    output_format: str,
    output_file: Path,
) -> list[str]:
    return [
        find_codeql_binary(),
        "database",
        "analyze",
        str(database_dir),
        queries,
        f"--format={output_format}",
        f"--output={output_file}",
    ]


def run_command(
    command: list[str],
    cwd: Path,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout_seconds,
    )


def normalize_codeql_path(path: str | None) -> str | None:
    if not path:
        return None
    # CodeQL CSV often writes project-relative paths as "/dir/file.py".
    # Keep Windows drive paths intact, but make project-relative paths match
    # the Semgrep/OpenGrep style.
    if path.startswith(("/", "\\")) and not Path(path).drive:
        return path.lstrip("/\\")
    return path


def normalize_severity(severity: str | None) -> str | None:
    if not severity:
        return None
    return severity.upper()


def normalize_csv_result(row: dict[str, str]) -> dict[str, Any]:
    def int_value(name: str) -> int | None:
        raw = row.get(name, "")
        try:
            return int(raw) if raw else None
        except ValueError:
            return None

    return {
        "rule_id": row.get("Name"),
        "name": row.get("Name"),
        "description": row.get("Description"),
        "severity": normalize_severity(row.get("Severity")),
        "message": row.get("Message"),
        "file": normalize_codeql_path(row.get("Path")),
        "start_line": int_value("Start line"),
        "start_col": int_value("Start column"),
        "end_line": int_value("End line"),
        "end_col": int_value("End column"),
        "category": "security",
        "technology": [],
        "cwe": [],
        "owasp": [],
        "confidence": None,
        "impact": None,
        "likelihood": None,
        "vulnerability_class": [],
        "references": [],
        "source": "codeql",
    }


def csv_has_header(row: list[str]) -> bool:
    normalized = {item.strip() for item in row}
    return {"Name", "Description", "Severity", "Message", "Path"}.issubset(normalized)


def load_csv_results(output_file: Path) -> list[dict[str, Any]]:
    if not output_file.exists() or output_file.stat().st_size == 0:
        return []

    with output_file.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        rows = list(csv.reader(handle))

    rows = [row for row in rows if any(cell.strip() for cell in row)]
    if not rows:
        return []

    if csv_has_header(rows[0]):
        fieldnames = rows[0]
        data_rows = rows[1:]
    else:
        fieldnames = CODEQL_CSV_COLUMNS
        data_rows = rows

    results: list[dict[str, Any]] = []
    for values in data_rows:
        padded = values + [""] * max(0, len(fieldnames) - len(values))
        row = dict(zip(fieldnames, padded))
        results.append(normalize_csv_result(row))
    return results


def summarize_output(output_file: Path, output_format: str) -> dict[str, Any]:
    if output_format == "csv":
        findings = load_csv_results(output_file)
        return {
            "findings": findings,
            "total_findings": len(findings),
        }

    if output_format in {"sarif", "sarif-latest", "json"} and output_file.exists():
        try:
            raw = json.loads(output_file.read_text(encoding="utf-8-sig", errors="replace"))
        except json.JSONDecodeError:
            return {"findings": [], "total_findings": None}

        if output_format in {"sarif", "sarif-latest"}:
            runs = raw.get("runs", [])
            total = sum(len(run.get("results", [])) for run in runs)
            return {"findings": [], "total_findings": total}

    return {"findings": [], "total_findings": None}


@mcp.tool
def get_codeql_command_preview(
    project_path: str,
    language: str = "python",
    queries: str | None = None,
    database_path: str | None = None,
    output_file: str | None = None,
    output_format: str | None = None,
    source_root: str = ".",
    build_mode: str = "none",
    overwrite_database: bool = True,
    no_run_unnecessary_builds: bool = True,
) -> dict[str, Any]:
    project_dir = resolve_project_path(project_path)
    resolved_output_format = output_format or default_output_format()
    database_dir = resolve_database_path(project_dir, database_path)
    result_file = resolve_output_path(project_dir, output_file, resolved_output_format)
    resolved_queries = queries or default_queries_for_language(language)

    return {
        "project_path": str(project_dir),
        "codeql_binary": find_codeql_binary(),
        "language": language,
        "queries": resolved_queries,
        "database_path": str(database_dir),
        "output_file": str(result_file),
        "output_format": resolved_output_format,
        "database_create_command": build_database_create_command(
            project_dir=project_dir,
            database_dir=database_dir,
            language=language,
            source_root=source_root,
            build_mode=build_mode,
            overwrite=overwrite_database,
            no_run_unnecessary_builds=no_run_unnecessary_builds,
        ),
        "database_analyze_command": build_database_analyze_command(
            database_dir=database_dir,
            queries=resolved_queries,
            output_format=resolved_output_format,
            output_file=result_file,
        ),
    }


@mcp.tool
def scan_project_with_codeql(
    project_path: str,
    language: str = "python",
    queries: str | None = None,
    database_path: str | None = None,
    output_file: str | None = None,
    output_format: str | None = None,
    source_root: str = ".",
    build_mode: str = "none",
    overwrite_database: bool = True,
    no_run_unnecessary_builds: bool = True,
    timeout_seconds: int = 900,
    max_results: int = 0,
) -> dict[str, Any]:
    project_dir = resolve_project_path(project_path)
    resolved_output_format = output_format or default_output_format()
    database_dir = resolve_database_path(project_dir, database_path)
    result_file = resolve_output_path(project_dir, output_file, resolved_output_format)
    resolved_queries = queries or default_queries_for_language(language)

    result_file.parent.mkdir(parents=True, exist_ok=True)

    create_command = build_database_create_command(
        project_dir=project_dir,
        database_dir=database_dir,
        language=language,
        source_root=source_root,
        build_mode=build_mode,
        overwrite=overwrite_database,
        no_run_unnecessary_builds=no_run_unnecessary_builds,
    )
    analyze_command = build_database_analyze_command(
        database_dir=database_dir,
        queries=resolved_queries,
        output_format=resolved_output_format,
        output_file=result_file,
    )

    try:
        create_process = run_command(create_command, project_dir, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"CodeQL database create timed out after {timeout_seconds}s for {project_dir}"
        ) from exc

    if create_process.returncode != 0:
        raise RuntimeError({
            "message": "CodeQL database create failed.",
            "project_path": str(project_dir),
            "command": create_command,
            "returncode": create_process.returncode,
            "stdout_tail": tail_text(create_process.stdout, 4000),
            "stderr_tail": tail_text(create_process.stderr, 4000),
        })

    try:
        analyze_process = run_command(analyze_command, project_dir, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"CodeQL database analyze timed out after {timeout_seconds}s for {project_dir}"
        ) from exc

    if analyze_process.returncode != 0:
        raise RuntimeError({
            "message": "CodeQL database analyze failed.",
            "project_path": str(project_dir),
            "command": analyze_command,
            "returncode": analyze_process.returncode,
            "stdout_tail": tail_text(analyze_process.stdout, 4000),
            "stderr_tail": tail_text(analyze_process.stderr, 4000),
        })

    summary = summarize_output(result_file, resolved_output_format)
    findings = summary["findings"]
    if max_results > 0:
        truncated = len(findings) > max_results
        returned_findings = findings[:max_results]
    else:
        truncated = False
        returned_findings = findings

    return {
        "tool": "codeql",
        "project_path": str(project_dir),
        "language": language,
        "queries": resolved_queries,
        "database_path": str(database_dir),
        "raw_report_path": str(result_file),
        "output_file": str(result_file),
        "output_format": resolved_output_format,
        "total_findings": summary["total_findings"],
        "returned_findings": len(returned_findings),
        "total_results": summary["total_findings"],
        "returned_results": len(returned_findings),
        "truncated": truncated,
        "severity_count": count_by_severity(returned_findings),
        "findings": returned_findings,
        "results": returned_findings,
        "create_returncode": create_process.returncode,
        "analyze_returncode": analyze_process.returncode,
        "create_stdout_tail": tail_text(create_process.stdout, 2000),
        "create_stderr_tail": tail_text(create_process.stderr, 2000),
        "analyze_stdout_tail": tail_text(analyze_process.stdout, 2000),
        "analyze_stderr_tail": tail_text(analyze_process.stderr, 2000),
    }


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=get_required_env("CODEQL_MCP_HOST"),
        port=get_env_int("CODEQL_MCP_PORT"),
        path=get_required_env("CODEQL_MCP_PATH"),
    )
