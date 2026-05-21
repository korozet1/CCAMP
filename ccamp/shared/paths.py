"""路径解析与校验。

所有 MCP 服务都需要验证调用方传入的项目目录是否存在、
是否为目录，并统一 expanduser + resolve。
"""

from pathlib import Path


def resolve_project_path(project_path: str) -> Path:
    """解析并校验调用方传入的项目目录。

    - expanduser: 展开 ~ 为用户目录
    - resolve:    转为绝对路径

    Raises:
        ValueError: 路径不存在或不是目录。
    """
    path = Path(project_path).expanduser().resolve()

    if not path.exists():
        raise ValueError(f"Project path does not exist: {path}")

    if not path.is_dir():
        raise ValueError(f"Project path is not a directory: {path}")

    return path
