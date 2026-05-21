"""从 .env 文件加载环境变量。

项目配置通过 .env 文件管理（API key、URL、token 等）。
这个模块只做最基本的 KV 解析，不覆盖已有环境变量 —
这样 CI 或父进程可以通过真实环境变量覆盖 .env 中的值。
"""

from pathlib import Path
import os


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_env_file(env_path: Path) -> None:
    """读取 .env 文件中的 KEY=VALUE 配置，不覆盖已有环境变量。

    Args:
        env_path: .env 文件的路径（通常是项目根目录）。
    """
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        # 跳过空行、注释行、格式错误行
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        # 去掉值两端的引号（支持单引号和双引号）
        value = value.strip().strip('"').strip("'")

        if key and key not in os.environ:
            os.environ[key] = value


def load_project_env() -> None:
    load_env_file(project_root() / ".env")


def get_required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def get_env_int(name: str) -> int:
    value = get_required_env(name)
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"Environment variable {name} must be an integer.") from exc
