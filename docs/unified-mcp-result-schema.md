# MCP 扫描结果统一 Schema

当前 Semgrep、OpenGrep、CodeQL 三个 MCP 客户端统一输出同一套 JSON 结构：

```text
schema_version = ccamp.scan_result.v1
```

适用结果文件：

```text
reports\semgrep-mcp-result.json
reports\opengrep-mcp-result.json
reports\codeql-mcp-result.json
```

## 1. 顶层结构

```json
{
  "schema_version": "ccamp.scan_result.v1",
  "generated_at": "2026-05-22T...",
  "scan_id": "...",
  "tool_name": "opengrep",
  "tool_version": "1.22.0",
  "project_path": "D:\\...",
  "project_name": "java-sec-code-master",
  "status": "success",
  "raw_report_path": "D:\\...\\reports\\opengrep.json",
  "total_findings": 156,
  "returned_findings": 156,
  "severity_count": {
    "ERROR": 41,
    "WARNING": 111,
    "INFO": 4
  },
  "truncated": false,
  "tool": {},
  "project": {},
  "scan": {},
  "config": {},
  "summary": {},
  "findings": [],
  "tool_specific": {}
}
```

## 2. 顶层字段说明

| 字段 | 类型 | 说明 | 数据库存储建议 |
|---|---|---|---|
| `schema_version` | string | 统一 schema 版本 | 普通列 |
| `generated_at` | string | 结果文件生成时间，UTC ISO 格式 | datetime/timestamp |
| `scan_id` | string | 扫描结果 ID，按工具、项目、原始报告、数量生成 | 主键或唯一索引 |
| `tool_name` | string | 工具名：`semgrep`、`opengrep`、`codeql` | 普通列，建议索引 |
| `tool_version` | string/null | 工具版本，CodeQL 当前可能为空 | 普通列 |
| `project_path` | string | 项目路径 | 普通列 |
| `project_name` | string | 项目目录名 | 普通列，建议索引 |
| `status` | string | `success`、`partial`、`failed` | 普通列 |
| `raw_report_path` | string/null | 工具原始报告路径 | 普通列 |
| `total_findings` | integer | 当前统一结果 finding 总数 | 普通列 |
| `returned_findings` | integer | 当前 JSON 返回 finding 数 | 普通列 |
| `severity_count` | object | 严重级别统计 | JSON 列 |
| `truncated` | boolean | 是否被截断 | 普通列 |
| `tool` | object | 工具基础信息 | JSON 列 |
| `project` | object | 项目信息 | JSON 列 |
| `scan` | object | 扫描执行信息 | JSON 列 |
| `config` | object | 扫描配置 | JSON 列 |
| `summary` | object | 汇总统计 | JSON 列 |
| `findings` | array | 统一 finding 列表 | 单独拆 finding 表 |
| `tool_specific` | object | 工具特有字段 | JSON 列 |

## 3. scan 字段

```json
{
  "status": "success",
  "returncode": 0,
  "raw_report_path": "...",
  "scanned_paths": [],
  "errors": [],
  "stdout_tail": "...",
  "stderr_tail": "...",
  "tool_returncodes": {}
}
```

用途：

| 字段 | 说明 |
|---|---|
| `status` | 扫描状态 |
| `returncode` | 统一返回码 |
| `raw_report_path` | 原始报告路径 |
| `scanned_paths` | 实际扫描文件 |
| `errors` | 工具报告的错误或 warning |
| `stdout_tail` / `stderr_tail` | 命令输出尾部，排错用 |
| `tool_returncodes` | 工具多阶段返回码，例如 CodeQL 的 create/analyze |

## 4. config 字段

```json
{
  "rules": [],
  "excludes": [],
  "language": "java",
  "database_path": "...",
  "output_file": "...",
  "output_format": "csv",
  "tool_specific": {}
}
```

不同工具会填不同字段：

| 工具 | 主要配置 |
|---|---|
| Semgrep | `rules` 来自 `configs` |
| OpenGrep | `rules` 来自 `rule_paths`，`excludes` 来自排除目录 |
| CodeQL | `language`、`queries`、`database_path`、`output_format` |

## 5. summary 字段

```json
{
  "raw_total_findings": 304,
  "total_findings": 156,
  "returned_findings": 156,
  "truncated": false,
  "severity_count": {},
  "deduplicated": true,
  "duplicate_groups": 104,
  "duplicate_findings_removed": 148
}
```

说明：

| 字段 | 说明 |
|---|---|
| `raw_total_findings` | 原始 finding 数，OpenGrep 去重前会大于 `total_findings` |
| `total_findings` | 当前统一结果 finding 数 |
| `returned_findings` | 当前 JSON 返回数 |
| `truncated` | 是否被 `max_findings` 或 `max_results` 截断 |
| `severity_count` | 严重级别统计 |
| `deduplicated` | 是否做过去重 |
| `duplicate_groups` | 重复组数量 |
| `duplicate_findings_removed` | 被去重移除的数量 |

## 6. finding 结构

每条 finding 都有相同字段：

```json
{
  "finding_id": "...",
  "tool_name": "opengrep",
  "project_path": "D:\\...",
  "rule_id": "...",
  "rule_name": "...",
  "rule_description": "...",
  "rule_source": "...",
  "severity": "ERROR",
  "category": "security",
  "message": "...",
  "file": "src/main/java/...",
  "file_path": "src/main/java/...",
  "start_line": 1,
  "start_col": 1,
  "end_line": 1,
  "end_col": 10,
  "technology": [],
  "cwe": [],
  "owasp": [],
  "vulnerability_class": [],
  "confidence": "HIGH",
  "impact": "HIGH",
  "likelihood": "LOW",
  "references": [],
  "evidence_lines": "...",
  "fix": null,
  "duplicate_count": 1,
  "duplicate_rule_ids": [],
  "duplicate_sources": [],
  "embedding_text": "...",
  "tool_specific": {},
  "location": {},
  "rule": {},
  "taxonomy": {},
  "risk": {},
  "evidence": {}
}
```

## 7. finding 字段入库建议

建议拆成一张 `scan_findings` 表：

| 字段 | MySQL 类型建议 | 说明 |
|---|---|---|
| `finding_id` | varchar(64) | 主键或唯一索引 |
| `scan_id` | varchar(64) | 外键，关联 scan 表 |
| `tool_name` | varchar(32) | 工具名 |
| `project_path` | text | 项目路径 |
| `rule_id` | varchar(512) | 规则 ID |
| `rule_name` | varchar(512) | 规则名 |
| `severity` | varchar(32) | 严重级别 |
| `category` | varchar(64) | 分类 |
| `message` | text | 告警描述 |
| `file_path` | text | 文件路径 |
| `start_line` | int | 起始行 |
| `start_col` | int | 起始列 |
| `end_line` | int | 结束行 |
| `end_col` | int | 结束列 |
| `confidence` | varchar(32) | 置信度 |
| `impact` | varchar(32) | 影响 |
| `likelihood` | varchar(32) | 可能性 |
| `technology` | json | 技术标签 |
| `cwe` | json | CWE |
| `owasp` | json | OWASP |
| `references` | json | 参考链接 |
| `duplicate_count` | int | 重复数量 |
| `embedding_text` | text | 向量化文本 |
| `tool_specific` | json | 工具扩展字段 |

建议索引：

```sql
CREATE INDEX idx_findings_tool ON scan_findings(tool_name);
CREATE INDEX idx_findings_project ON scan_findings(project_path(255));
CREATE INDEX idx_findings_file ON scan_findings(file_path(255));
CREATE INDEX idx_findings_severity ON scan_findings(severity);
CREATE INDEX idx_findings_rule ON scan_findings(rule_id(255));
CREATE INDEX idx_findings_location ON scan_findings(start_line, end_line);
```

## 8. 向量库建议

向量库推荐按 finding 粒度入库。

向量文本字段：

```text
embedding_text
```

推荐 metadata：

```json
{
  "finding_id": "...",
  "scan_id": "...",
  "tool_name": "opengrep",
  "project_name": "java-sec-code-master",
  "severity": "ERROR",
  "category": "security",
  "file_path": "src/main/java/...",
  "start_line": 10,
  "rule_id": "...",
  "cwe": [],
  "owasp": [],
  "technology": []
}
```

这样可以支持：

- 按项目查相似漏洞
- 按 CWE/OWASP 检索
- 按工具对比同一类发现
- 基于代码位置聚合
- 找出类似修复建议

## 9. 扩展规则

后续新增 SonarQube、Fortify、Checkmarx 等工具时，不要改业务消费方，只需要：

1. 把工具原始结果转换成统一 finding 字段。
2. 工具特有字段放入 `tool_specific`。
3. 顶层仍输出 `schema_version = ccamp.scan_result.v1`。
4. 如果 schema 有破坏性变化，再升级为 `ccamp.scan_result.v2`。

核心原则：

```text
公共字段稳定
工具差异隔离
原始能力不丢
数据库和向量库都能直接消费
```
