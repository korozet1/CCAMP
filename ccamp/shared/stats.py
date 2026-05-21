"""统计工具。

对扫描结果按 severity、type 等维度做简单计数，
用于报告的摘要部分。
"""

from typing import Any


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    """按 severity 字段统计 finding/issue 数量。

    severity 为空时计为 "UNKNOWN"。
    """
    return count_by(findings, "severity")


def count_by(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    """按指定字段统计字典列表中的条目数量。

    Args:
        items: 扫描结果列表。
        field: 统计维度字段名，如 "severity"、"type"。

    Returns:
        {字段值: 计数} 字典。缺失值计为 "UNKNOWN"。
    """
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(field) or "UNKNOWN"
        counts[value] = counts.get(value, 0) + 1
    return counts
