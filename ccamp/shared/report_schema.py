from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ccamp.scan_result.v1"


TOP_LEVEL_COMMON_KEYS = {
    "tool",
    "project_path",
    "raw_report_path",
    "total_findings",
    "returned_findings",
    "truncated",
    "severity_count",
    "findings",
    "results",
}

FINDING_COMMON_KEYS = {
    "rule_id",
    "name",
    "description",
    "severity",
    "message",
    "file",
    "path",
    "start_line",
    "start_col",
    "end_line",
    "end_col",
    "category",
    "technology",
    "cwe",
    "owasp",
    "confidence",
    "impact",
    "likelihood",
    "vulnerability_class",
    "references",
    "source",
    "lines",
    "fix",
    "duplicate_count",
    "duplicate_rule_ids",
    "duplicate_sources",
}


def list_value(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]


def string_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def int_value(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def tool_version(payload: dict[str, Any], tool_name: str) -> str | None:
    return (
        payload.get(f"{tool_name}_version")
        or payload.get("version")
        or payload.get("scanner_version")
    )


def returncode(payload: dict[str, Any], tool_name: str) -> int | None:
    direct = payload.get(f"{tool_name}_returncode")
    if direct is not None:
        return int_value(direct)
    if tool_name == "codeql":
        analyze = int_value(payload.get("analyze_returncode"))
        create = int_value(payload.get("create_returncode"))
        if analyze is not None and create is not None:
            return 0 if analyze == 0 and create == 0 else analyze or create
        return analyze if analyze is not None else create
    return None


def scan_status(payload: dict[str, Any], tool_name: str) -> str:
    code = returncode(payload, tool_name)
    if code is not None and code != 0:
        return "failed"
    if payload.get("truncated"):
        return "partial"
    return "success"


def output_file(payload: dict[str, Any]) -> str | None:
    return payload.get("output_file") or payload.get("raw_report_path")


def result_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = payload.get("findings")
    if isinstance(findings, list):
        return findings
    results = payload.get("results")
    if isinstance(results, list):
        return results
    issues = payload.get("issues")
    if isinstance(issues, list):
        return issues
    return []


def build_scan_id(
    tool_name: str,
    project_path: str | None,
    raw_report_path: str | None,
    total_findings: int,
) -> str:
    return sha256_text("|".join([
        tool_name,
        project_path or "",
        raw_report_path or "",
        str(total_findings),
    ]))[:32]


def build_finding_id(
    tool_name: str,
    project_path: str | None,
    finding: dict[str, Any],
) -> str:
    fields = [
        tool_name,
        project_path or "",
        string_value(finding.get("rule_id")) or "",
        string_value(finding.get("file") or finding.get("path")) or "",
        str(finding.get("start_line") or ""),
        str(finding.get("start_col") or ""),
        string_value(finding.get("message")) or "",
    ]
    return sha256_text("|".join(fields))[:32]


def build_embedding_text(finding: dict[str, Any], tool_name: str) -> str:
    parts = [
        f"tool: {tool_name}",
        f"rule: {finding.get('rule_id') or finding.get('name') or ''}",
        f"severity: {finding.get('severity') or ''}",
        f"category: {finding.get('category') or ''}",
        f"file: {finding.get('file') or finding.get('path') or ''}",
        f"message: {finding.get('message') or ''}",
        f"cwe: {', '.join(str(item) for item in list_value(finding.get('cwe')))}",
        f"owasp: {', '.join(str(item) for item in list_value(finding.get('owasp')))}",
        "technology: "
        + ", ".join(str(item) for item in list_value(finding.get("technology"))),
        "vulnerability_class: "
        + ", ".join(str(item) for item in list_value(finding.get("vulnerability_class"))),
        f"evidence: {finding.get('lines') or ''}",
    ]
    return "\n".join(part for part in parts if part.strip())


def finding_tool_specific(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in finding.items()
        if key not in FINDING_COMMON_KEYS
    }


def normalize_finding(
    finding: dict[str, Any],
    tool_name: str,
    project_path: str | None,
) -> dict[str, Any]:
    rule_id = string_value(finding.get("rule_id") or finding.get("key"))
    rule_name = string_value(finding.get("name") or rule_id)
    rule_description = string_value(finding.get("description"))
    file_path = string_value(finding.get("file") or finding.get("path"))
    normalized = {
        "finding_id": build_finding_id(tool_name, project_path, finding),
        "tool_name": tool_name,
        "project_path": project_path,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "rule_description": rule_description,
        "rule_source": string_value(finding.get("source")),
        "severity": string_value(finding.get("severity")),
        "category": string_value(finding.get("category")),
        "message": string_value(finding.get("message")),
        "file": file_path,
        "file_path": file_path,
        "start_line": int_value(finding.get("start_line")),
        "start_col": int_value(finding.get("start_col")),
        "end_line": int_value(finding.get("end_line")),
        "end_col": int_value(finding.get("end_col")),
        "technology": list_value(finding.get("technology")),
        "cwe": list_value(finding.get("cwe")),
        "owasp": list_value(finding.get("owasp")),
        "vulnerability_class": list_value(finding.get("vulnerability_class")),
        "confidence": string_value(finding.get("confidence")),
        "impact": string_value(finding.get("impact")),
        "likelihood": string_value(finding.get("likelihood")),
        "references": list_value(finding.get("references")),
        "evidence_lines": string_value(finding.get("lines")),
        "fix": finding.get("fix"),
        "duplicate_count": int_value(finding.get("duplicate_count")) or 1,
        "duplicate_rule_ids": list_value(finding.get("duplicate_rule_ids")),
        "duplicate_sources": list_value(finding.get("duplicate_sources")),
        "embedding_text": build_embedding_text(finding, tool_name),
        "tool_specific": finding_tool_specific(finding),
    }
    normalized["location"] = {
        "file": normalized["file"],
        "start_line": normalized["start_line"],
        "start_col": normalized["start_col"],
        "end_line": normalized["end_line"],
        "end_col": normalized["end_col"],
    }
    normalized["rule"] = {
        "id": normalized["rule_id"],
        "name": normalized["rule_name"],
        "description": normalized["rule_description"],
        "source": normalized["rule_source"],
    }
    normalized["taxonomy"] = {
        "technology": normalized["technology"],
        "cwe": normalized["cwe"],
        "owasp": normalized["owasp"],
        "vulnerability_class": normalized["vulnerability_class"],
    }
    normalized["risk"] = {
        "confidence": normalized["confidence"],
        "impact": normalized["impact"],
        "likelihood": normalized["likelihood"],
    }
    normalized["evidence"] = {
        "lines": normalized["evidence_lines"],
        "fix": normalized["fix"],
        "references": normalized["references"],
    }
    return normalized


def tool_specific_config(payload: dict[str, Any], tool_name: str) -> dict[str, Any]:
    if tool_name == "opengrep":
        return {
            "rule_paths": payload.get("rule_paths", []),
            "deduplicated": payload.get("deduplicated"),
        }
    if tool_name == "semgrep":
        return {
            "configs": payload.get("configs", []),
        }
    if tool_name == "codeql":
        return {
            "language": payload.get("language"),
            "queries": payload.get("queries"),
            "database_path": payload.get("database_path"),
            "output_file": payload.get("output_file"),
            "output_format": payload.get("output_format"),
        }
    return {}


def normalized_config(payload: dict[str, Any], tool_name: str) -> dict[str, Any]:
    rules = payload.get("rule_paths") or payload.get("configs") or []
    queries = payload.get("queries")
    if queries and not rules:
        rules = [queries] if isinstance(queries, str) else list_value(queries)
    return {
        "rules": list_value(rules),
        "excludes": list_value(payload.get("excludes")),
        "language": payload.get("language"),
        "database_path": payload.get("database_path"),
        "output_file": output_file(payload),
        "output_format": payload.get("output_format"),
        "tool_specific": tool_specific_config(payload, tool_name),
    }


def normalized_scan(payload: dict[str, Any], tool_name: str) -> dict[str, Any]:
    return {
        "status": scan_status(payload, tool_name),
        "returncode": returncode(payload, tool_name),
        "raw_report_path": payload.get("raw_report_path"),
        "scanned_paths": list_value(payload.get("scanned_paths")),
        "errors": list_value(payload.get("errors")),
        "stdout_tail": payload.get("stdout_tail") or payload.get("analyze_stdout_tail"),
        "stderr_tail": payload.get("stderr_tail") or payload.get("analyze_stderr_tail"),
        "tool_returncodes": {
            key: value
            for key, value in payload.items()
            if key.endswith("_returncode")
        },
    }


def normalized_summary(
    payload: dict[str, Any],
    finding_count: int,
) -> dict[str, Any]:
    raw_total = (
        payload.get("raw_total_findings")
        or payload.get("total_results")
        or payload.get("total_findings")
        or finding_count
    )
    return {
        "raw_total_findings": int_value(raw_total) or finding_count,
        "total_findings": int_value(payload.get("total_findings")) or finding_count,
        "returned_findings": int_value(payload.get("returned_findings")) or finding_count,
        "truncated": bool(payload.get("truncated")),
        "severity_count": payload.get("severity_count") or {},
        "deduplicated": payload.get("deduplicated"),
        "duplicate_groups": int_value(payload.get("duplicate_groups")) or 0,
        "duplicate_findings_removed": (
            int_value(payload.get("duplicate_findings_removed")) or 0
        ),
    }


def top_level_tool_specific(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key not in TOP_LEVEL_COMMON_KEYS
        and not key.endswith("_tail")
        and not key.endswith("_returncode")
    }


def normalize_scan_result(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") == SCHEMA_VERSION:
        return payload

    tool_name = string_value(payload.get("tool")) or "unknown"
    project_path = string_value(payload.get("project_path"))
    findings = [
        normalize_finding(finding, tool_name, project_path)
        for finding in result_findings(payload)
    ]
    summary = normalized_summary(payload, len(findings))
    raw_report_path = string_value(payload.get("raw_report_path"))
    generated_at = datetime.now(timezone.utc).isoformat()
    scan_id = build_scan_id(
        tool_name,
        project_path,
        raw_report_path,
        summary["total_findings"],
    )

    project_name = Path(project_path).name if project_path else None
    result = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "scan_id": scan_id,
        "tool_name": tool_name,
        "tool_version": tool_version(payload, tool_name),
        "project_path": project_path,
        "project_name": project_name,
        "status": scan_status(payload, tool_name),
        "raw_report_path": raw_report_path,
        "total_findings": summary["total_findings"],
        "returned_findings": summary["returned_findings"],
        "severity_count": summary["severity_count"],
        "truncated": summary["truncated"],
        "tool": {
            "name": tool_name,
            "version": tool_version(payload, tool_name),
        },
        "project": {
            "path": project_path,
            "name": project_name,
        },
        "scan": normalized_scan(payload, tool_name),
        "config": normalized_config(payload, tool_name),
        "summary": summary,
        "findings": findings,
        "tool_specific": top_level_tool_specific(payload),
    }
    return result
