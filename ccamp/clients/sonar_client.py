"""SonarQube MCP 调试客户端。

独立验证 SonarQube MCP 服务是否可用。
支持两种模式：
  - 完整扫描（默认）：运行 sonar-scanner + 获取 API 结果
  - 仅摘要（--summary-only）：从已有项目读取数据，不重新扫描
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

MCP_URL = get_required_env("SONAR_MCP_URL")


async def run(
    project_path: str,
    project_key: str = "ccamp",
    project_name: str | None = None,
    mcp_url: str = MCP_URL,
    summary_only: bool = False,
    max_issues: int = 0,
    timeout_seconds: int = 900,
    ce_wait_seconds: int = 600,
    output: str | None = None,
) -> None:
    """连接 SonarQube MCP，列出工具，执行扫描/摘要，打印结果。"""
    os.environ.setdefault("NO_PROXY", LOCAL_NO_PROXY)
    os.environ.setdefault("no_proxy", LOCAL_NO_PROXY)

    project_dir = Path(project_path).resolve()

    async with Client(mcp_url) as client:
        tools = await client.list_tools()
        print("Available tools:")
        for tool in tools:
            print(f"- {tool.name}")

        if summary_only:
            arguments = {"project_key": project_key}
            if max_issues > 0:
                arguments["max_issues"] = max_issues

            result = await client.call_tool("get_sonarqube_project_summary", arguments)
        else:
            arguments = {
                "project_path": str(project_dir),
                "project_key": project_key,
                "project_name": project_name or project_key,
                "timeout_seconds": timeout_seconds,
                "ce_wait_seconds": ce_wait_seconds,
            }
            if max_issues > 0:
                arguments["max_issues"] = max_issues

            result = await client.call_tool("scan_project_with_sonarqube", arguments)

    payload = unwrap_tool_result(result)
    output_path = (
        Path(output).resolve()
        if output
        else project_dir / "reports" / "sonarqube-mcp-result.json"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8-sig",
    )

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"\nSonarQube MCP result written to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Test the SonarQube MCP server.")
    parser.add_argument("project_path", help="Project directory to scan.")
    parser.add_argument("--project-key", default="ccamp")
    parser.add_argument("--project-name", default=None)
    parser.add_argument("--mcp-url", default=MCP_URL, help="Streamable HTTP MCP URL.")
    parser.add_argument("--summary-only", action="store_true")
    parser.add_argument(
        "--max-issues",
        type=int,
        default=0,
        help="Maximum issues to return. Use 0 to return all issues.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--ce-wait-seconds", type=int, default=600)
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Write the normalized MCP result JSON to this path. "
            "Defaults to <project>\\reports\\sonarqube-mcp-result.json."
        ),
    )
    args = parser.parse_args()
    asyncio.run(
        run(
            args.project_path,
            args.project_key,
            args.project_name,
            args.mcp_url,
            args.summary_only,
            args.max_issues,
            args.timeout_seconds,
            args.ce_wait_seconds,
            args.output,
        )
    )


if __name__ == "__main__":
    main()
