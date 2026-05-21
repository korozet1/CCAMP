"""FastMCP 客户端响应归一化工具。

FastMCP 不同版本的 tool 返回结构不完全一样：
有的放在 data，有的放在 structured_content，旧版本可能嵌套在 content 文本里。
to_jsonable 和 unwrap_tool_result 统一处理这些差异，
让业务代码不需要关心 FastMCP 版本兼容细节。
"""

from __future__ import annotations

import json
from typing import Any

from fastmcp import Client


def to_jsonable(value: Any) -> Any:
    """把 FastMCP / Pydantic 返回对象转成普通 Python 可序列化值。

    按优先级尝试：data → structured_content → model_dump → content。
    如果是列表或字典，递归转换每个元素。
    """
    # FastMCP 3.x 常用 data 字段
    if hasattr(value, "data") and value.data is not None:
        return value.data
    # FastMCP 4.x 常用 structured_content 字段
    if hasattr(value, "structured_content") and value.structured_content is not None:
        return value.structured_content
    # Pydantic 模型直接用 model_dump
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    # 旧版本可能嵌套在 content 里
    if hasattr(value, "content"):
        return to_jsonable(value.content)
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    return value


def unwrap_tool_result(result: Any) -> dict[str, Any]:
    """从 FastMCP tool 返回结果中提取真正的字典载荷。

    处理 FastMCP 不同版本和各种嵌套层级 —
    解包 data/structured_content/content 包装、
    解析 text 类型的内容块中的 JSON 字符串。
    最终始终返回一个 dict。
    """
    data = to_jsonable(result)

    # 解包外层包装
    if isinstance(data, dict) and data.get("data") is not None:
        data = data["data"]
    elif isinstance(data, dict) and data.get("structured_content") is not None:
        data = data["structured_content"]
    elif isinstance(data, dict) and "content" in data:
        data = data["content"]

    # 解包 text 类型的内容块（FastMCP 有时把结果放在 list[TextContent] 里）
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict) and first.get("type") == "text":
            text = first.get("text", "")
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                raise RuntimeError(
                    f"MCP tool returned non-JSON text in content block: {text[:200]}..."
                ) from None

    if not isinstance(data, dict):
        raise RuntimeError(
            f"Unexpected MCP result type {type(data).__name__}: {data!r}"
        )
    return data


async def call_mcp_tool(
    mcp_url: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """通过 streamable HTTP 调用一个 MCP tool，返回 JSON 字典载荷。

    封装了 FastMCP Client 的创建、调用和结果解包。
    编排器使用此函数并发调用多个扫描器。
    """
    async with Client(mcp_url) as client:
        result = await client.call_tool(tool_name, arguments)
    return unwrap_tool_result(result)
