"""文本处理工具。

主要是 tail_text，用于裁剪 subprocess 的 stdout/stderr，
避免超长错误信息塞满 MCP 返回值和模型上下文。
"""


def tail_text(value: str | None, limit: int) -> str:
    """只保留字符串尾部 limit 个字符。

    进程失败时 stdout/stderr 可能非常长（几万行编译日志）。
    完整返回会浪费 token，也容易超出 MCP 消息大小限制。
    通常只需要尾部信息就能判断错误原因。
    """
    if not value:
        return ""
    return value[-limit:]
