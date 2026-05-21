"""扫描器和编排器共用的常量。

原本分散在各个文件中硬编码，现在集中管理，方便调整。
"""

# ---------------------------------------------------------------------------
# 通用排除目录 — Semgrep、OpenGrep、SonarQube 共用
# ---------------------------------------------------------------------------
# 这些目录包含第三方依赖、构建产物、IDE 配置或之前扫描生成的报告。
# 不排除它们会导致：扫描时间暴增、误报激增、甚至递归扫描自己的输出。
DEFAULT_EXCLUDES = [
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".git",
    ".idea",
    ".scannerwork",
    "reports",
    "__pycache__",
    "data/static/codefixes",
]

# ---------------------------------------------------------------------------
# SonarQube 排除项使用 glob 通配符 (**) 而非纯目录名
# ---------------------------------------------------------------------------
SONAR_EXCLUDES = [
    "node_modules/**",
    ".venv/**",
    "venv/**",
    "dist/**",
    "build/**",
    "target/**",
    ".git/**",
    ".scannerwork/**",
    "reports/**",
    "__pycache__/**",
    "data/static/codefixes/**",
]

# ---------------------------------------------------------------------------
# SonarQube JS/TS/CSS 降级排除模式
# ---------------------------------------------------------------------------
# 某些大型 JS/TS 项目（如 Juice Shop）会触发 SonarQube JavaScript bridge
# 的 WebSocket 异常。在首次扫描失败后，自动用这些模式重试。
JS_TS_CSS_EXCLUSIONS = [
    "**/*.js",
    "**/*.jsx",
    "**/*.mjs",
    "**/*.cjs",
    "**/*.ts",
    "**/*.tsx",
    "**/*.css",
    "**/*.scss",
    "**/*.sass",
    "**/*.less",
]

# ---------------------------------------------------------------------------
# 本地 MCP 通信不走代理
# ---------------------------------------------------------------------------
LOCAL_NO_PROXY = "127.0.0.1,localhost"

# ---------------------------------------------------------------------------
# Semgrep 默认规则集
# ---------------------------------------------------------------------------
# "auto" 让 Semgrep 根据项目语言自动选择规则；
# "p/security-audit" 和 "p/secrets" 补充安全和密钥检测。
SEMGREP_DEFAULT_CONFIGS = [
    "auto",
    "p/security-audit",
    "p/secrets",
]

# ---------------------------------------------------------------------------
# SonarQube 默认关注的指标
# ---------------------------------------------------------------------------
SONAR_DEFAULT_METRICS = [
    "bugs",
    "vulnerabilities",
    "code_smells",
    "security_hotspots",
    "coverage",
    "duplicated_lines_density",
    "ncloc",
    "complexity",
    "cognitive_complexity",
]

# ---------------------------------------------------------------------------
# OpenGrep 默认规则目录（来自 semgrep-rules 仓库的分类）
# ---------------------------------------------------------------------------
OPENGREP_DEFAULT_RULESET_DIRS = [
    "ai",
    "apex",
    "bash",
    "c",
    "clojure",
    "csharp",
    "dockerfile",
    "elixir",
    "generic",
    "go",
    "html",
    "java",
    "javascript",
    "json",
    "kotlin",
    "libsonnet",
    "ocaml",
    "package_managers",
    "php",
    "problem-based-packs",
    "python",
    "ruby",
    "rust",
    "scala",
    "solidity",
    "swift",
    "terraform",
    "trusted_python",
    "typescript",
    "yaml",
]
