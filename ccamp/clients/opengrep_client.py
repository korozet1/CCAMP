"""OpenGrep MCP 调试客户端。

独立验证 OpenGrep MCP 服务是否可用。
将扫描结果写入 <project>/reports/opengrep-mcp-result.json。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from fastmcp import Client

from ccamp.shared.constants import LOCAL_NO_PROXY
from ccamp.shared.env import get_required_env, load_project_env
from ccamp.shared.mcp_client import unwrap_tool_result


load_project_env()

MCP_URL = get_required_env("OPENGREP_MCP_URL")


async def run(
    project_path: str,
    mcp_url: str = MCP_URL,
    rule_paths: list[str] | None = None,
    max_findings: int = 0,
    output: str | None = None,
) -> None:
    """连接 OpenGrep MCP，列出工具，执行扫描，写结果到文件。"""
    os.environ.setdefault("NO_PROXY", LOCAL_NO_PROXY)
    os.environ.setdefault("no_proxy", LOCAL_NO_PROXY)

    project_dir = Path(project_path).resolve()

    async with Client(mcp_url) as client:
        tools = await client.list_tools()
        print("Available tools:")
        for tool in tools:
            print(f"- {tool.name}")

        arguments = {
            "project_path": str(project_dir),
            "rule_paths": rule_paths,
            "keep_raw_report": True,
        }
        if max_findings > 0:
            arguments["max_findings"] = max_findings

        result = await client.call_tool("scan_project_with_opengrep", arguments)

    payload = unwrap_tool_result(result)
    output_path = (
        Path(output).resolve()
        if output
        else project_dir / "reports" / "opengrep-mcp-result.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8-sig",
    )

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"\nNormalized MCP result written to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Test the OpenGrep MCP server.")
    parser.add_argument("project_path", help="Project directory to scan.")
    parser.add_argument("--mcp-url", default=MCP_URL, help="Streamable HTTP MCP URL.")
    parser.add_argument(
        "--rule-path", action="append", dest="rule_paths", default=None
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=0,
        help="Maximum findings to return. Use 0 to return all findings.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Write the normalized MCP result JSON to this path. "
            "Defaults to <project>\\reports\\opengrep-mcp-result.json."
        ),
    )
    args = parser.parse_args()
    asyncio.run(
        run(args.project_path, args.mcp_url, args.rule_paths, args.max_findings, args.output)
    )


if __name__ == "__main__":
    main()
