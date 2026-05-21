from ccamp.codeql.server import mcp
from ccamp.shared.env import get_env_int, get_required_env, load_project_env


if __name__ == "__main__":
    load_project_env()
    mcp.run(
        transport="streamable-http",
        host=get_required_env("CODEQL_MCP_HOST"),
        port=get_env_int("CODEQL_MCP_PORT"),
        path=get_required_env("CODEQL_MCP_PATH"),
    )
