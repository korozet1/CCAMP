# CCAMP MCP Scanners

本项目把本地静态扫描工具封装成 MCP 服务，并提供对应的测试客户端。

当前只保留 4 个独立 MCP：

| MCP | 服务端 | 客户端 | 默认端口 |
|---|---|---|---|
| Semgrep | `python -m ccamp.semgrep.server` | `python -m test_semgrep <项目路径>` | `8004` |
| SonarQube | `python -m ccamp.sonarqube.server` | `python -m test_sonar <项目路径>` | `8005` |
| OpenGrep | `python -m ccamp.opengrep.server` | `python -m test_opengrep <项目路径>` | `8006` |
| CodeQL | `python -m ccamp.codeql.server` | `python -m test_codeql <项目路径>` | `8007` |

本项目已经删除聚合扫描和 AI 报告相关逻辑，不再包含 `run_audit.py`。

## 1. 先理解运行方式

每个扫描器都分成两层：

| 层 | 作用 | 是否长时间运行 |
|---|---|---|
| MCP 服务端 | 暴露工具给客户端调用 | 是 |
| 测试客户端 | 调用 MCP 工具，并把结果写到 `reports` | 否 |

例如 OpenGrep：

```text
OpenGrep MCP 服务端
  ↓
scan_project_with_opengrep 工具
  ↓
opengrep.exe
  ↓
<项目>\reports\opengrep.json
<项目>\reports\opengrep-mcp-result.json
```

所以使用时通常是：

1. 启动对应 MCP 服务。
2. 另开一个 CMD。
3. 进入 `scripts` 目录。
4. 运行对应测试客户端。

不需要 4 个 MCP 全部启动。你要扫哪个工具，就启动哪个 MCP。

## 2. 项目结构

```text
CCAMP/
  .env
  pyproject.toml
  README.md
  ccamp/
    clients/
      codeql_client.py
      opengrep_client.py
      semgrep_client.py
      sonar_client.py
    codeql/
      server.py
    opengrep/
      server.py
    semgrep/
      server.py
    sonarqube/
      server.py
    shared/
      env.py
      mcp_client.py
      paths.py
      stats.py
      text.py
  mcp_servers/
    codeql_server.py
    opengrep_server.py
    semgrep_server.py
    sonar_server.py
  scripts/
    test_codeql.py
    test_opengrep.py
    test_semgrep.py
    test_sonar.py
```

推荐启动入口是 `python -m ccamp.xxx.server`。

`mcp_servers/` 目录只保留兼容入口，正常使用可以不用管。

## 3. 基础环境

### 3.1 Python 环境

建议 Python 3.11+。

```cmd
conda create -n CCAM python=3.11 -y
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP
pip install -e .
```

验证：

```cmd
python --version
pip show fastmcp
```

### 3.2 Git

OpenGrep 的规则库建议直接 clone。

```cmd
git --version
```

如果没有 Git，从这里下载：

```text
https://git-scm.com/download/win
```

## 4. 外部工具准备

### 4.1 Semgrep

安装：

```cmd
conda activate CCAM
pip install semgrep
```

验证：

```cmd
semgrep --version
```

### 4.2 OpenGrep

下载地址：

```text
https://github.com/opengrep/opengrep/releases
```

Windows 选择：

```text
opengrep_windows_x86.exe
```

建议改名为：

```text
D:\BaiduNetdiskDownload\opengrep.exe
```

验证：

```cmd
D:\BaiduNetdiskDownload\opengrep.exe --version
```

OpenGrep 自己不带规则库。建议下载 Semgrep 官方规则库：

```cmd
cd /d D:\BaiduNetdiskDownload
git clone https://github.com/semgrep/semgrep-rules.git
```

得到：

```text
D:\BaiduNetdiskDownload\semgrep-rules
```

### 4.3 SonarQube Server

SonarQube 分两部分：

| 工具 | 作用 |
|---|---|
| SonarQube Server | 本地 Web 服务和结果数据库 |
| SonarScanner CLI | 把项目扫描结果上传到 SonarQube Server |

SonarQube Server 下载：

```text
https://www.sonarsource.com/products/sonarqube/downloads/
```

示例目录：

```text
D:\BaiduNetdiskDownload\sonarqube-26.5.0.122743
```

启动：

```cmd
cd /d D:\BaiduNetdiskDownload\sonarqube-26.5.0.122743\bin\windows-x86-64
StartSonar.bat
```

打开：

```text
http://127.0.0.1:9000
```

停止：

```cmd
cd /d D:\BaiduNetdiskDownload\sonarqube-26.5.0.122743\bin\windows-x86-64
StopSonar.bat
```

### 4.4 SonarScanner CLI

下载文档：

```text
https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/scanners/sonarscanner/
```

示例目录：

```text
D:\BaiduNetdiskDownload\sonar-scanner-8.0.1.6346-windows-x64
```

验证：

```cmd
D:\BaiduNetdiskDownload\sonar-scanner-8.0.1.6346-windows-x64\bin\sonar-scanner.bat --version
```

### 4.5 CodeQL

下载 CodeQL Bundle：

```text
https://github.com/github/codeql-action/releases
```

建议解压到：

```text
D:\BaiduNetdiskDownload\codeql
```

应该存在：

```text
D:\BaiduNetdiskDownload\codeql\codeql.exe
```

验证：

```cmd
D:\BaiduNetdiskDownload\codeql\codeql.exe version
```

扫描 Python 项目时，Windows 上还需要 `py.exe`：

```cmd
py --version
where py
```

如果没有 `py.exe`，安装 Python 官方 Windows 版，并勾选：

```text
Install launcher for all users
Add python.exe to PATH
```

## 5. `.env` 配置

配置文件：

```text
D:\BaiduNetdiskDownload\CCAM\CCAMP\.env
```

示例：

```env
SEMGREP_MCP_URL=http://127.0.0.1:8004/mcp
SEMGREP_MCP_HOST=127.0.0.1
SEMGREP_MCP_PORT=8004
SEMGREP_MCP_PATH=/mcp

SONAR_MCP_URL=http://127.0.0.1:8005/mcp
SONAR_MCP_HOST=127.0.0.1
SONAR_MCP_PORT=8005
SONAR_MCP_PATH=/mcp

OPENGREP_MCP_URL=http://127.0.0.1:8006/mcp
OPENGREP_MCP_HOST=127.0.0.1
OPENGREP_MCP_PORT=8006
OPENGREP_MCP_PATH=/mcp

CODEQL_MCP_URL=http://127.0.0.1:8007/mcp
CODEQL_MCP_HOST=127.0.0.1
CODEQL_MCP_PORT=8007
CODEQL_MCP_PATH=/mcp

SONAR_HOST_URL=http://127.0.0.1:9000
SONAR_TOKEN=你的SonarQubeToken
SONAR_SCANNER_BIN=D:\BaiduNetdiskDownload\sonar-scanner-8.0.1.6346-windows-x64\bin\sonar-scanner.bat

OPENGREP_BIN=D:\BaiduNetdiskDownload\opengrep.exe
OPENGREP_RULES_DIR=D:\BaiduNetdiskDownload\semgrep-rules

CODEQL_BIN=D:\BaiduNetdiskDownload\codeql\codeql.exe
CODEQL_DEFAULT_DATABASE=codeql_db
CODEQL_DEFAULT_FORMAT=csv
```

说明：

| 变量 | 给谁用 | 作用 |
|---|---|---|
| `*_MCP_URL` | 客户端 | 连接 MCP 服务 |
| `*_MCP_HOST` | 服务端 | 监听地址 |
| `*_MCP_PORT` | 服务端 | 监听端口 |
| `*_MCP_PATH` | 服务端 | MCP HTTP 路径 |
| `SONAR_HOST_URL` | SonarQube MCP | SonarQube Web 地址 |
| `SONAR_TOKEN` | SonarQube MCP | SonarQube API Token |
| `SONAR_SCANNER_BIN` | SonarQube MCP | SonarScanner CLI 路径 |
| `OPENGREP_BIN` | OpenGrep MCP | OpenGrep exe 路径 |
| `OPENGREP_RULES_DIR` | OpenGrep MCP | semgrep-rules 规则库路径 |
| `CODEQL_BIN` | CodeQL MCP | CodeQL exe 路径 |
| `CODEQL_DEFAULT_DATABASE` | CodeQL MCP | 默认 database 目录名 |
| `CODEQL_DEFAULT_FORMAT` | CodeQL MCP | 默认输出格式 |

修改 `.env` 后，要重启对应 MCP 服务。

## 6. 启动 MCP 服务

进入项目根目录：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP
```

启动哪个 MCP，就新开一个 CMD 执行对应命令：

| MCP | 启动命令 | 地址 |
|---|---|---|
| Semgrep | `python -m ccamp.semgrep.server` | `http://127.0.0.1:8004/mcp` |
| SonarQube | `python -m ccamp.sonarqube.server` | `http://127.0.0.1:8005/mcp` |
| OpenGrep | `python -m ccamp.opengrep.server` | `http://127.0.0.1:8006/mcp` |
| CodeQL | `python -m ccamp.codeql.server` | `http://127.0.0.1:8007/mcp` |

SonarQube MCP 比较特殊，启动 MCP 之前要先启动 SonarQube Server：

```cmd
cd /d D:\BaiduNetdiskDownload\sonarqube-26.5.0.122743\bin\windows-x86-64
StartSonar.bat
```

检查 SonarQube 状态：

```cmd
powershell -Command "Invoke-RestMethod http://127.0.0.1:9000/api/system/status"
```

看到 `UP` 后，再启动：

```cmd
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP
python -m ccamp.sonarqube.server
```

## 7. 调用客户端

客户端都在：

```text
D:\BaiduNetdiskDownload\CCAM\CCAMP\scripts
```

先进入：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP\scripts
```

常用命令：

| 工具 | 命令 | 输出 |
|---|---|---|
| Semgrep | `python -m test_semgrep D:\BaiduNetdiskDownload\CCAM\test` | `reports\semgrep.json`、`reports\semgrep-mcp-result.json` |
| OpenGrep | `python -m test_opengrep D:\BaiduNetdiskDownload\CCAM\test` | `reports\opengrep.json`、`reports\opengrep-mcp-result.json` |
| SonarQube | `python -m test_sonar D:\BaiduNetdiskDownload\CCAM\test` | `reports\sonarqube-mcp-result.json` |
| CodeQL | `python -m test_codeql D:\BaiduNetdiskDownload\CCAM\test` | `reports\codeql-result.csv`、`reports\codeql-mcp-result.json` |

### 7.1 Semgrep 常用参数

限制返回条数：

```cmd
python -m test_semgrep D:\BaiduNetdiskDownload\CCAM\test --max-findings 50
```

### 7.2 OpenGrep 常用参数

默认会使用 `.env` 里的 `OPENGREP_RULES_DIR`。

指定某个规则目录：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\CCAM\test --rule-path D:\BaiduNetdiskDownload\semgrep-rules\python
```

限制返回条数：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\CCAM\test --max-findings 50
```

不传 `--max-findings` 时，默认不截断。

### 7.3 SonarQube 常用参数

只读取已有 SonarQube 结果，不重新扫描：

```cmd
python -m test_sonar D:\BaiduNetdiskDownload\CCAM\test --summary-only
```

后台任务慢时延长等待：

```cmd
python -m test_sonar D:\BaiduNetdiskDownload\CCAM\test --ce-wait-seconds 1200
```

指定项目 key：

```cmd
python -m test_sonar D:\BaiduNetdiskDownload\CCAM\test --project-key ccamp-test
```

限制返回条数：

```cmd
python -m test_sonar D:\BaiduNetdiskDownload\CCAM\test --max-issues 100
```

不传 `--max-issues` 时，默认不截断。

### 7.4 CodeQL 常用参数

默认行为：

```text
language=python
queries=codeql/python-queries
database=<项目>\codeql_db
raw result=<项目>\reports\codeql-result.csv
mcp result=<项目>\reports\codeql-mcp-result.json
```

指定语言：

```cmd
python -m test_codeql D:\BaiduNetdiskDownload\CCAM\test --language python
```

指定查询包：

```cmd
python -m test_codeql D:\BaiduNetdiskDownload\CCAM\test --queries codeql/python-queries
```

输出 SARIF：

```cmd
python -m test_codeql D:\BaiduNetdiskDownload\CCAM\test --output-format sarif-latest --result-output D:\BaiduNetdiskDownload\CCAM\test\reports\codeql-result.sarif
```

限制返回条数：

```cmd
python -m test_codeql D:\BaiduNetdiskDownload\CCAM\test --max-results 50
```

不传 `--max-results` 时，默认不截断。

## 8. MCP 工具清单

每个 MCP 里一般有两类工具：

| 工具类型 | 作用 |
|---|---|
| `get_*_command_preview` | 只预览实际命令，不执行扫描 |
| `scan_project_with_*` | 执行扫描并返回结构化结果 |

具体工具：

| MCP | 工具 |
|---|---|
| Semgrep | `get_semgrep_command_preview`、`scan_project_with_semgrep` |
| OpenGrep | `get_opengrep_command_preview`、`scan_project_with_opengrep` |
| SonarQube | `get_sonar_scanner_command_preview`、`scan_project_with_sonarqube`、`get_sonarqube_project_summary` |
| CodeQL | `get_codeql_command_preview`、`scan_project_with_codeql` |

测试客户端通常只调用一个主扫描工具。例如：

| 客户端 | 默认调用的 MCP 工具 |
|---|---|
| `test_semgrep.py` | `scan_project_with_semgrep` |
| `test_opengrep.py` | `scan_project_with_opengrep` |
| `test_sonar.py` | `scan_project_with_sonarqube` |
| `test_codeql.py` | `scan_project_with_codeql` |

预览工具不是必须调用，它只用于排查命令是否正确。

## 9. 输出文件

假设项目路径是：

```text
D:\BaiduNetdiskDownload\CCAM\test
```

输出目录是：

```text
D:\BaiduNetdiskDownload\CCAM\test\reports
```

常见文件：

| 文件 | 来源 | 说明 |
|---|---|---|
| `semgrep.json` | Semgrep | Semgrep 原始 JSON |
| `semgrep-mcp-result.json` | Semgrep MCP | MCP 整理后的结果 |
| `opengrep.json` | OpenGrep | OpenGrep 原始 JSON |
| `opengrep-mcp-result.json` | OpenGrep MCP | MCP 整理后的结果 |
| `sonarqube-mcp-result.json` | SonarQube MCP | 从 SonarQube API 拉取并整理的结果 |
| `codeql-result.csv` | CodeQL | CodeQL 原始 CSV |
| `codeql-result.sarif` | CodeQL | CodeQL SARIF，只有指定 SARIF 输出时才有 |
| `codeql-mcp-result.json` | CodeQL MCP | MCP 整理后的结果 |

注意：

- Semgrep 和 OpenGrep 会同时保留原始 JSON 和 MCP 整理 JSON。
- SonarQube 的原始数据在 SonarQube Server 中，客户端输出的是 API 整理结果。
- CodeQL 默认原始结果是 CSV。如果 CSV 为空，通常表示扫描成功但没有命中规则。

## 10. CodeQL 手动命令

这一节是不走 MCP 的手动流程，用于单独验证 CodeQL 是否可用。

测试项目：

```text
D:\BaiduNetdiskDownload\CCAM\test
```

CodeQL 路径：

```text
D:\BaiduNetdiskDownload\codeql\codeql.exe
```

进入项目：

```cmd
cd /d D:\BaiduNetdiskDownload\CCAM\test
```

删除旧 database：

```cmd
rmdir /s /q codeql_db
```

如果提示“系统找不到指定的文件”，可以忽略。

确保当前 CMD 使用正确 Python：

```cmd
set PATH=D:\anaconda3\envs\CCAM;D:\anaconda3\envs\CCAM\Scripts;%PATH%
python --version
where python
py --version
where py
```

创建 CodeQL database：

```cmd
D:\BaiduNetdiskDownload\codeql\codeql.exe database create codeql_db --language=python --source-root . --build-mode=none --no-run-unnecessary-builds --overwrite
```

运行官方 Python 查询：

```cmd
D:\BaiduNetdiskDownload\codeql\codeql.exe database analyze codeql_db codeql/python-queries --format=csv --output=codeql-result.csv
```

查看结果：

```cmd
notepad codeql-result.csv
```

CodeQL 的基本流程是：

```text
源代码
  ↓
创建 CodeQL database
  ↓
运行 CodeQL 查询规则
  ↓
输出 CSV / SARIF
```

这里的 database 不是 MySQL、PostgreSQL 这种数据库，而是 CodeQL 对源码解析后生成的本地分析目录。

## 11. 常见问题

### 11.1 `.env` 修改后不生效

重启对应 MCP 服务。

### 11.2 端口冲突

查看端口：

```cmd
powershell -Command "Get-NetTCPConnection -LocalPort 8004,8005,8006,8007,9000 -ErrorAction SilentlyContinue | Select LocalAddress,LocalPort,State,OwningProcess"
```

如果端口被占用，改 `.env` 里的 `*_MCP_PORT` 和 `*_MCP_URL`，然后重启服务。

### 11.3 `No module named 'ccamp'`

通常是没有在项目根目录安装，或者从错误目录运行。

执行：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP
pip install -e .
```

然后客户端从 `scripts` 目录运行：

```cmd
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP\scripts
python -m test_opengrep D:\BaiduNetdiskDownload\CCAM\test
```

### 11.4 OpenGrep 找不到规则

检查规则目录：

```cmd
dir D:\BaiduNetdiskDownload\semgrep-rules
```

检查 `.env`：

```env
OPENGREP_RULES_DIR=D:\BaiduNetdiskDownload\semgrep-rules
```

如果只想扫描 Python，可以传：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\CCAM\test --rule-path D:\BaiduNetdiskDownload\semgrep-rules\python
```

如果想扫多语言，直接使用整个规则库：

```env
OPENGREP_RULES_DIR=D:\BaiduNetdiskDownload\semgrep-rules
```

### 11.5 结果只有 50 条

旧版本客户端可能默认只返回 50 条。

当前用法：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\vulpy
python -m test_semgrep D:\BaiduNetdiskDownload\vulpy
python -m test_sonar D:\BaiduNetdiskDownload\vulpy
python -m test_codeql D:\BaiduNetdiskDownload\vulpy
```

不传 `--max-findings`、`--max-issues`、`--max-results` 时默认不截断。

如果仍然只有 50 条，说明旧 MCP 服务还在运行。关闭旧 CMD，重新启动对应 MCP。

### 11.6 SonarQube 一直 PENDING

通常是 SonarQube Compute Engine 没起来。

检查系统状态：

```cmd
powershell -Command "Invoke-RestMethod http://127.0.0.1:9000/api/system/status"
```

检查健康状态：

```cmd
powershell -Command "$token='你的SonarQubeToken'; $basic=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($token + ':')); Invoke-RestMethod 'http://127.0.0.1:9000/api/system/health' -Headers @{Authorization='Basic '+$basic}"
```

如果是 `RED`，重启 SonarQube，并看日志：

```text
D:\BaiduNetdiskDownload\sonarqube-26.5.0.122743\logs\sonar.log
D:\BaiduNetdiskDownload\sonarqube-26.5.0.122743\logs\ce.log
```

### 11.7 SonarQube API 报 `ps=0`

说明正在运行的是旧版 SonarQube MCP 服务。

处理：

1. 关闭旧的 `python -m ccamp.sonarqube.server` CMD。
2. 重新启动 SonarQube MCP。
3. 再运行 `python -m test_sonar ...`。

### 11.8 CodeQL 报缺少 `py.exe`

安装 Python 官方 Windows 版，并勾选：

```text
Install launcher for all users
Add python.exe to PATH
```

验证：

```cmd
py --version
where py
```

### 11.9 CodeQL CSV 为空

这通常不是错误。

含义是：

```text
CodeQL 扫描成功，但没有命中当前查询规则。
```

如果想验证 CodeQL 是否能报漏洞，可以写一个包含外部输入和危险函数的测试文件，例如 Flask 的 `request.args.get()` 流向 `os.system()`、`subprocess.call(..., shell=True)`、`cursor.execute()` 或 `eval()`。

## 12. 最常用流程

### 12.1 OpenGrep

CMD 1：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP
python -m ccamp.opengrep.server
```

CMD 2：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP\scripts
python -m test_opengrep D:\BaiduNetdiskDownload\CCAM\test
```

### 12.2 Semgrep

CMD 1：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP
python -m ccamp.semgrep.server
```

CMD 2：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP\scripts
python -m test_semgrep D:\BaiduNetdiskDownload\CCAM\test
```

### 12.3 SonarQube

CMD 1：

```cmd
cd /d D:\BaiduNetdiskDownload\sonarqube-26.5.0.122743\bin\windows-x86-64
StartSonar.bat
```

CMD 2：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP
python -m ccamp.sonarqube.server
```

CMD 3：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP\scripts
python -m test_sonar D:\BaiduNetdiskDownload\CCAM\test
```

### 12.4 CodeQL

CMD 1：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP
python -m ccamp.codeql.server
```

CMD 2：

```cmd
conda activate CCAM
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP\scripts
python -m test_codeql D:\BaiduNetdiskDownload\CCAM\test
```
