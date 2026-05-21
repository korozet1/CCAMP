"""向后兼容入口 — 请使用 scripts/run_semgrep_server.py。"""

from ccamp.semgrep.server import mcp
from ccamp.shared.env import get_env_int, get_required_env, load_project_env

if __name__ == "__main__":
    load_project_env()
    mcp.run(
        transport="streamable-http",
        host=get_required_env("SEMGREP_MCP_HOST"),
        port=get_env_int("SEMGREP_MCP_PORT"),
        path=get_required_env("SEMGREP_MCP_PATH"),
    )
