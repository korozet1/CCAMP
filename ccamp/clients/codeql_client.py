from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
from pathlib import Path
from typing import Any

from fastmcp import Client

from ccamp.shared.constants import LOCAL_NO_PROXY
from ccamp.shared.env import get_required_env, load_project_env
from ccamp.shared.mcp_client import unwrap_tool_result
from ccamp.shared.report_schema import normalize_scan_result


load_project_env()

MCP_URL = get_required_env("CODEQL_MCP_URL")
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


def _int_value(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _normalize_path(path: str | None) -> str | None:
    if not path:
        return None
    if path.startswith(("/", "\\")) and not Path(path).drive:
        return path.lstrip("/\\")
    return path


def _csv_has_header(row: list[str]) -> bool:
    normalized = {item.strip() for item in row}
    return {"Name", "Description", "Severity", "Message", "Path"}.issubset(normalized)


def _load_codeql_csv_findings(csv_path: Path) -> list[dict[str, Any]]:
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    with csv_path.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        rows = [row for row in csv.reader(handle) if any(cell.strip() for cell in row)]

    if not rows:
        return []

    if _csv_has_header(rows[0]):
        fieldnames = rows[0]
        data_rows = rows[1:]
    else:
        fieldnames = CODEQL_CSV_COLUMNS
        data_rows = rows

    findings: list[dict[str, Any]] = []
    for values in data_rows:
        padded = values + [""] * max(0, len(fieldnames) - len(values))
        row = dict(zip(fieldnames, padded))
        findings.append({
            "rule_id": row.get("Name"),
            "name": row.get("Name"),
            "description": row.get("Description"),
            "severity": (row.get("Severity") or "").upper() or None,
            "message": row.get("Message"),
            "file": _normalize_path(row.get("Path")),
            "start_line": _int_value(row.get("Start line")),
            "start_col": _int_value(row.get("Start column")),
            "end_line": _int_value(row.get("End line")),
            "end_col": _int_value(row.get("End column")),
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
        })
    return findings


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity") or "UNKNOWN"
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _normalize_codeql_payload(payload: dict[str, Any]) -> dict[str, Any]:
    output_file = payload.get("output_file") or payload.get("raw_report_path")
    if not output_file:
        return payload

    output_path = Path(output_file)
    if output_path.suffix.lower() != ".csv":
        return payload

    findings = _load_codeql_csv_findings(output_path)
    if not findings:
        return payload

    payload["raw_report_path"] = str(output_path)
    payload["output_file"] = str(output_path)
    payload["total_findings"] = len(findings)
    payload["returned_findings"] = len(findings)
    payload["total_results"] = len(findings)
    payload["returned_results"] = len(findings)
    payload["truncated"] = False
    payload["severity_count"] = _count_by_severity(findings)
    payload["findings"] = findings
    payload["results"] = findings
    return payload


async def run(
    project_path: str,
    mcp_url: str = MCP_URL,
    language: str = "python",
    queries: str | None = None,
    database_path: str | None = None,
    result_output: str | None = None,
    output_format: str | None = None,
    source_root: str = ".",
    build_mode: str = "none",
    timeout_seconds: int = 900,
    max_results: int = 0,
    output: str | None = None,
) -> None:
    os.environ.setdefault("NO_PROXY", LOCAL_NO_PROXY)
    os.environ.setdefault("no_proxy", LOCAL_NO_PROXY)

    project_dir = Path(project_path).resolve()

    async with Client(mcp_url) as client:
        tools = await client.list_tools()
        print("Available tools:")
        for tool in tools:
            print(f"- {tool.name}")

        arguments: dict[str, Any] = {
            "project_path": str(project_dir),
            "language": language,
            "source_root": source_root,
            "build_mode": build_mode,
            "timeout_seconds": timeout_seconds,
        }
        if queries:
            arguments["queries"] = queries
        if database_path:
            arguments["database_path"] = database_path
        if result_output:
            arguments["output_file"] = result_output
        if output_format:
            arguments["output_format"] = output_format
        if max_results > 0:
            arguments["max_results"] = max_results

        result = await client.call_tool("scan_project_with_codeql", arguments)

    payload = normalize_scan_result(_normalize_codeql_payload(unwrap_tool_result(result)))
    output_path = (
        Path(output).resolve()
        if output
        else project_dir / "reports" / "codeql-mcp-result.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8-sig",
    )

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"\nCodeQL MCP result written to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Test the CodeQL MCP server.")
    parser.add_argument("project_path", help="Project directory to scan.")
    parser.add_argument("--mcp-url", default=MCP_URL, help="Streamable HTTP MCP URL.")
    parser.add_argument("--language", default="python")
    parser.add_argument("--queries", default=None)
    parser.add_argument("--database-path", default=None)
    parser.add_argument("--result-output", default=None)
    parser.add_argument("--output-format", default=None)
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--build-mode", default="none")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument(
        "--max-results",
        type=int,
        default=0,
        help="Maximum results to return. Use 0 to return all parsed results.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Write the normalized MCP result JSON to this path. "
            "Defaults to <project>\\reports\\codeql-mcp-result.json."
        ),
    )
    args = parser.parse_args()

    asyncio.run(
        run(
            project_path=args.project_path,
            mcp_url=args.mcp_url,
            language=args.language,
            queries=args.queries,
            database_path=args.database_path,
            result_output=args.result_output,
            output_format=args.output_format,
            source_root=args.source_root,
            build_mode=args.build_mode,
            timeout_seconds=args.timeout_seconds,
            max_results=args.max_results,
            output=args.output,
        )
    )


if __name__ == "__main__":
    main()
