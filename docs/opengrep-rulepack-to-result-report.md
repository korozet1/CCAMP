# OpenGrep 规则库到扫描结果报告

本文档整理当前 CCAMP 项目中 OpenGrep MCP 的规则库配置、规则加载流程、扫描结果文件、结果归一化、去重逻辑，以及本次 Java 项目扫描的结果对比。

测试项目：

```text
D:\BaiduNetdiskDownload\fortify\java-sec-code-master
```

相关结果文件：

```text
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\opengrep-mcp-result-old.json
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\opengrep-mcp-result.json
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\opengrep.json
```

## 1. 当前 OpenGrep 配置

OpenGrep MCP 的配置来自项目根目录的 `.env`：

```env
OPENGREP_MCP_URL=http://127.0.0.1:8006/mcp
OPENGREP_MCP_HOST=127.0.0.1
OPENGREP_MCP_PORT=8006
OPENGREP_MCP_PATH=/mcp

OPENGREP_BIN=D:\BaiduNetdiskDownload\opengrep.exe

OPENGREP_RULE_PATHS=D:\BaiduNetdiskDownload\opengrep_tool\semgrep-rules;D:\BaiduNetdiskDownload\opengrep_tool\opengrep-rules\opengrep-rules-main;D:\BaiduNetdiskDownload\opengrep_tool\aikido-opengrep-rules\rules;D:\BaiduNetdiskDownload\opengrep_tool\gitlab-sast-rules
```

其中：

| 配置项 | 作用 |
|---|---|
| `OPENGREP_BIN` | OpenGrep 可执行文件路径 |
| `OPENGREP_RULE_PATHS` | 多个规则库路径，使用英文分号 `;` 分隔 |
| `OPENGREP_MCP_URL` | 客户端连接 OpenGrep MCP 服务的地址 |
| `OPENGREP_MCP_HOST` / `PORT` / `PATH` | MCP 服务启动监听参数 |

## 2. 当前启用的规则库

当前不是只跑一个规则库，而是同时启用了 4 个规则源：

| 规则库 | 本地路径 | 作用 |
|---|---|---|
| `semgrep-rules` | `D:\BaiduNetdiskDownload\opengrep_tool\semgrep-rules` | Semgrep 社区规则，覆盖多语言安全、正确性、配置风险 |
| `opengrep-rules-main` | `D:\BaiduNetdiskDownload\opengrep_tool\opengrep-rules\opengrep-rules-main` | OpenGrep 规则库，和 Semgrep 规则有大量重叠，但也可能包含新增或调整后的规则 |
| `aikido-opengrep-rules` | `D:\BaiduNetdiskDownload\opengrep_tool\aikido-opengrep-rules\rules` | AikidoSec 提供的 OpenGrep 规则补充 |
| `gitlab-sast-rules` | `D:\BaiduNetdiskDownload\opengrep_tool\gitlab-sast-rules` | GitLab SAST 规则，能补充部分 GitLab 安全检测能力 |

本次新扫描中，MCP 展开后的规则路径数量为 72：

| 规则源 | 展开后的规则路径数量 |
|---|---:|
| `semgrep-rules` | 28 |
| `opengrep-rules-main` | 27 |
| `gitlab-sast-rules` | 16 |
| `aikido-opengrep-rules` | 1 |
| 合计 | 72 |

这里的 72 不是规则条数，而是传给 OpenGrep 的规则目录或规则文件路径数量。实际规则条数由 OpenGrep 加载后统计。

## 3. 规则路径展开逻辑

OpenGrep 不能直接无脑扫描某些规则仓库根目录，因为规则仓库里经常混有非规则 YAML 文件。

例如 GitLab SAST 规则库根目录中存在：

```text
D:\BaiduNetdiskDownload\opengrep_tool\gitlab-sast-rules\.gitlab-ci.yml
```

这个文件是 GitLab CI 配置，不是 OpenGrep/Semgrep 规则。如果直接把整个 `gitlab-sast-rules` 根目录传给 OpenGrep，会报：

```text
InvalidRuleSchemaError
One of these properties is missing: 'rules'
invalid configuration file found
```

因此当前 MCP 做了规则路径安全展开：

1. 对 `semgrep-rules`、`opengrep-rules-main` 这类标准规则库，按语言目录展开。
2. 对 `gitlab-sast-rules` 这类混合仓库，只选择真正包含顶层 `rules:` 的规则目录或规则文件。
3. 自动跳过 `.git`、`.github`、`.gitlab`、`scripts`、`spec`、`qa`、`test`、`tests` 等非规则目录。
4. 去除重复路径，避免同一个规则目录重复传入 OpenGrep。

这样既能加载多个规则库，又不会因为 `.gitlab-ci.yml`、mapping YAML、schema YAML 等非规则文件导致扫描失败。

## 4. OpenGrep 扫描命令形态

客户端命令：

```cmd
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP\scripts
python -m test_opengrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master
```

MCP 内部会构造类似下面的 OpenGrep 命令：

```cmd
D:\BaiduNetdiskDownload\opengrep.exe scan ^
  --config <规则路径1> ^
  --config <规则路径2> ^
  --config <规则路径N> ^
  --exclude node_modules ^
  --exclude .venv ^
  --exclude venv ^
  --exclude dist ^
  --exclude build ^
  --exclude target ^
  --exclude .git ^
  --exclude .idea ^
  --exclude .scannerwork ^
  --exclude codeql_db ^
  --exclude reports ^
  --exclude __pycache__ ^
  --exclude data/static/codefixes ^
  . ^
  --json ^
  --json-output <临时目录>\opengrep.json
```

默认排除目录包括：

```text
node_modules
.venv
venv
dist
build
target
.git
.idea
.scannerwork
codeql_db
reports
__pycache__
data/static/codefixes
```

其中 `codeql_db` 和 `reports` 必须排除，否则会把 CodeQL 数据库和之前生成的扫描结果也扫进去，导致结果膨胀。

## 5. 输出文件说明

一次 OpenGrep MCP 扫描会产生两类结果。

### 5.1 OpenGrep 原始报告

路径：

```text
<项目目录>\reports\opengrep.json
```

这是 OpenGrep CLI 原始 JSON 输出，保留最完整的信息：

```json
{
  "version": "1.22.0",
  "results": [],
  "errors": [],
  "paths": {
    "scanned": []
  }
}
```

这个文件适合：

| 用途 | 说明 |
|---|---|
| 追查 OpenGrep 原始输出 | 保留 CLI 原始字段 |
| 和命令行手动扫描对比 | 最接近 OpenGrep 自身行为 |
| 后续做更复杂二次处理 | 可重新解析 `results` |

### 5.2 MCP 归一化报告

路径：

```text
<项目目录>\reports\opengrep-mcp-result.json
```

这是 MCP 处理后的报告，结构更稳定，适合后续统一展示、汇总和 AI 分析。

主要字段：

| 字段 | 含义 |
|---|---|
| `tool` | 工具名称，固定为 `opengrep` |
| `opengrep_version` | OpenGrep 版本 |
| `project_path` | 被扫描项目路径 |
| `raw_report_path` | 原始 OpenGrep 报告路径 |
| `rule_paths` | 实际传给 OpenGrep 的规则路径 |
| `excludes` | 扫描排除目录 |
| `scanned_paths` | OpenGrep 实际扫描的文件 |
| `errors` | OpenGrep 扫描警告或错误 |
| `raw_total_findings` | 原始归一化发现数量，未去重 |
| `deduplicated` | MCP 是否启用了去重 |
| `duplicate_groups` | 重复发现组数量 |
| `duplicate_findings_removed` | 去重移除的重复发现数量 |
| `total_findings` | 当前报告中的发现总数 |
| `returned_findings` | 实际返回到 JSON 的发现数量 |
| `truncated` | 是否因为 `max_findings` 被截断 |
| `severity_count` | 按严重级别统计 |
| `findings` | 归一化后的发现列表 |

## 6. 结果归一化字段

每条 finding 会被 MCP 转换成统一结构：

| 字段 | 含义 |
|---|---|
| `rule_id` | 规则 ID |
| `severity` | 严重级别，如 `ERROR`、`WARNING`、`INFO` |
| `file` | 命中文件 |
| `start_line` / `start_col` | 起始位置 |
| `end_line` / `end_col` | 结束位置 |
| `message` | 告警描述 |
| `category` | 规则分类，例如 `security`、`correctness` |
| `technology` | 相关技术栈，例如 `java`、`spring`、`xml` |
| `cwe` | CWE 编号 |
| `owasp` | OWASP 分类 |
| `confidence` | 规则置信度 |
| `impact` | 影响程度 |
| `likelihood` | 发生可能性 |
| `references` | 参考链接 |
| `lines` | 命中的源码行内容 |
| `fix` | 规则提供的修复建议 |

启用去重后，每条 finding 还可能包含：

| 字段 | 含义 |
|---|---|
| `duplicate_count` | 此问题由多少条原始发现合并而来 |
| `duplicate_sources` | 命中该问题的规则库来源 |
| `duplicate_rule_ids` | 被合并的原始规则 ID 列表 |

## 7. 去重策略

启用多个规则库后，重复发现会显著增加。

典型重复来源：

1. `semgrep-rules` 和 `opengrep-rules-main` 有大量同名或同语义规则。
2. `gitlab-sast-rules` 会对同一漏洞类型再次命中。
3. 同一个漏洞位置可能被多个规则库用不同 rule id 表达。

MCP 当前默认启用去重。

去重依据：

```text
文件路径 + 起始行 + 结束行 + 归一化后的告警描述
```

这个策略不会简单按“同一行”合并，因为同一行可能存在多个不同安全问题。

例如同一行 Cookie 代码可能同时命中：

```text
cookie missing HttpOnly
cookie missing Secure flag
```

这两个属于不同问题，不能合并。

代表性 finding 的选择规则：

1. 优先保留严重级别更高的结果：`ERROR` > `WARNING` > `INFO`
2. 严重级别相同，优先保留置信度更高的结果：`HIGH` > `MEDIUM` > `LOW`
3. 再看影响程度：`HIGH` > `MEDIUM` > `LOW`
4. 最后按规则源优先级选择：

```text
opengrep-rules-main > semgrep-rules > gitlab-sast-rules > aikido-opengrep-rules
```

## 8. 本次 old 与 new 结果对比

### 8.1 总体对比

| 指标 | old 报告 | new 报告 |
|---|---:|---:|
| OpenGrep 版本 | 1.22.0 | 1.22.0 |
| 扫描返回码 | 0 | 0 |
| 规则路径数量 | 28 | 72 |
| 实际扫描文件数 | 100 | 100 |
| 原始发现数 | 105 | 304 |
| MCP 去重后发现数 | 未启用 | 156 |
| 重复发现组 | 未统计 | 104 |
| 去重移除数量 | 未统计 | 148 |
| 返回 finding 数 | 105 | 156 |
| 是否截断 | 否 | 否 |

### 8.2 严重级别对比

| 严重级别 | old | new 去重后 |
|---|---:|---:|
| `ERROR` | 18 | 41 |
| `WARNING` | 83 | 111 |
| `INFO` | 4 | 4 |
| 合计 | 105 | 156 |

### 8.3 分类对比

new 去重后结果：

| 分类 | 数量 |
|---|---:|
| `security` | 155 |
| `correctness` | 1 |

说明本次 OpenGrep 扫描主要是安全类发现。

### 8.4 技术栈分布

new 去重后高频技术标签：

| 技术标签 | 数量 |
|---|---:|
| `java` | 81 |
| `spring` | 48 |
| `xml` | 14 |
| `unknown` | 11 |
| `cookie` | 5 |
| `docker-compose` | 4 |
| `django` | 4 |
| `gitleaks` | 3 |
| `jackson` | 2 |
| `snakeyaml` | 2 |
| `groovy` | 2 |
| `html` | 2 |

### 8.5 命中最多的文件

new 去重后 Top 文件：

| 数量 | 文件 |
|---:|---|
| 12 | `src\main\java\org\joychou\controller\XXE.java` |
| 11 | `src\main\java\org\joychou\controller\URLRedirect.java` |
| 10 | `src\main\java\org\joychou\controller\CRLFInjection.java` |
| 10 | `src\main\java\org\joychou\util\CookieUtils.java` |
| 9 | `src\main\java\org\joychou\controller\Rce.java` |
| 9 | `src\main\java\org\joychou\controller\SQLI.java` |
| 9 | `src\main\java\org\joychou\controller\XSS.java` |
| 7 | `src\main\java\org\joychou\controller\Cors.java` |
| 7 | `src\main\java\org\joychou\controller\SpEL.java` |
| 6 | `src\main\java\org\joychou\controller\Deserialize.java` |

## 9. 为什么 new 比 old 多

new 结果数量增加不是因为项目代码变多，而是因为规则覆盖面扩大。

old 主要使用：

```text
D:\BaiduNetdiskDownload\opengrep-rules
```

new 同时使用：

```text
semgrep-rules
opengrep-rules-main
aikido-opengrep-rules
gitlab-sast-rules
```

因此变化是合理的：

| 变化 | 原因 |
|---|---|
| 原始发现从 105 增加到 304 | 规则库数量增加，规则总覆盖面扩大 |
| new 检出更多类型 | GitLab SAST 和 OpenGrep 规则补充了旧规则未覆盖的场景 |
| 重复发现明显增加 | 多个规则库对同一代码位置、同一漏洞类型重复命中 |
| 去重后仍高于 old | new 确实发现了 old 没覆盖的一部分问题 |

本次 new 的有效结论不是“304 条都要人工看”，而是：

```text
OpenGrep 原始命中 304 条
MCP 合并重复后剩余 156 条
其中 ERROR 41 条，WARNING 111 条，INFO 4 条
```

## 10. 新增覆盖的风险类型

new 扫描相比 old 覆盖更广，新增或更明显的方向包括：

| 风险类型 | 说明 |
|---|---|
| CSRF | Spring `RequestMapping` 未限定 HTTP method 等 |
| CORS 配置风险 | 过宽的跨域配置 |
| 硬编码凭证 | 代码或配置中出现疑似密钥、密码、token |
| SSRF | 外部输入控制 URL 请求 |
| 路径遍历 | 用户输入控制文件路径 |
| XXE | XML 解析器未禁用外部实体或 DOCTYPE |
| SQL 注入 | 拼接 SQL 或用户输入进入 SQL 查询 |
| 命令注入 | 用户输入进入 `exec`、`ProcessBuilder` 等命令执行点 |
| Cookie 安全属性缺失 | `HttpOnly`、`Secure` 等属性缺失 |
| Docker Compose 安全配置 | 容器未开启 `no-new-privileges`、根文件系统可写等 |

## 11. 扫描 warning/error 如何理解

本次 old 和 new 都存在 `PartialParsing` warning，位置是：

```text
src\main\resources\templates\login.html:39
```

原因是 HTML 模板中存在类似 Thymeleaf 的语法：

```text
@{/}
```

OpenGrep 在某些 HTML/JavaScript 规则中尝试按 JavaScript 片段解析该模板语法，导致局部解析警告。

这类 warning 的含义：

| 项目 | 说明 |
|---|---|
| 是否导致扫描失败 | 否 |
| 是否影响全部扫描 | 否 |
| 是否需要立刻修复 | 一般不需要 |
| 影响范围 | 只影响相关 HTML/JS 规则在该模板片段上的解析 |

如果报告中 `opengrep_returncode=0`，这类 warning 可以作为扫描噪声记录，不代表 OpenGrep 执行失败。

## 12. 推荐使用方式

### 12.1 默认扫描

默认启用去重，适合正常查看：

```cmd
cd /d D:\BaiduNetdiskDownload\CCAM\CCAMP\scripts
python -m test_opengrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master
```

输出：

```text
D:\BaiduNetdiskDownload\fortify\java-sec-code-master\reports\opengrep-mcp-result.json
```

### 12.2 查看未去重 MCP 结果

如果需要完整归一化结果，可以加：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master --no-dedupe
```

这会返回所有归一化 finding，不做重复合并。

### 12.3 限制返回数量

如果项目很大，可以限制 MCP JSON 中返回的 finding 数：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master --max-findings 100
```

注意：`max_findings` 只限制 MCP 返回结果，不代表 OpenGrep 没有扫描其他问题。

### 12.4 额外排除目录

如果某个项目还有生成目录或第三方目录，可以额外排除：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master --exclude logs --exclude tmp
```

## 13. 如何进一步减少噪声

如果后续希望报告更短，可以从三个层面优化。

### 13.1 规则库层面

最强覆盖：

```text
semgrep-rules + opengrep-rules-main + gitlab-sast-rules + aikido-opengrep-rules
```

优点是覆盖广，缺点是重复和误报更多。

更适合正式审计的组合：

```text
opengrep-rules-main + gitlab-sast-rules
```

或者：

```text
semgrep-rules + gitlab-sast-rules
```

不建议长期同时启用 `semgrep-rules` 和 `opengrep-rules-main` 后又完全不去重，因为这两个规则库有大量重叠。

### 13.2 结果层面

当前已经启用 MCP 去重，建议默认查看：

```text
opengrep-mcp-result.json
```

需要追查完整来源时再查看：

```text
opengrep.json
```

### 13.3 审查优先级层面

人工审查建议按顺序看：

1. `severity = ERROR`
2. `confidence = HIGH` 或 `MEDIUM`
3. `impact = HIGH`
4. `duplicate_count > 1`
5. 同一文件中高密度命中的问题

`duplicate_count > 1` 不一定是坏事。它说明多个规则库都认为同一位置有问题，反而可以作为优先审查信号。

## 14. 当前结论

本次 OpenGrep 从规则库到结果的流程已经形成：

```text
.env 配置多个规则库
  ↓
MCP 安全展开规则路径
  ↓
过滤非规则 YAML
  ↓
OpenGrep 执行扫描
  ↓
生成原始 reports\opengrep.json
  ↓
MCP 归一化 finding
  ↓
MCP 默认去重
  ↓
生成 reports\opengrep-mcp-result.json
```

当前 Java 项目扫描结论：

```text
扫描成功，returncode = 0
扫描文件数 = 100
规则路径数 = 72
原始发现数 = 304
去重后发现数 = 156
重复发现组 = 104
去重移除 = 148
ERROR = 41
WARNING = 111
INFO = 4
```

因此，new 报告比 old 多是正常的：规则库扩展带来了更广覆盖；MCP 去重后，报告已经从 304 条压缩到 156 条，同时保留了重复来源信息，适合后续漏洞审查和 AI 分析。
