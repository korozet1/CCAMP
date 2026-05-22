# CodeQL、Semgrep、OpenGrep 对比文档

本文用于说明三个扫描器为什么结果不一样、各自擅长什么、什么时候该用哪个，以及在本项目 MCP 中应该怎么组合使用。

## 1. 总体结论

CodeQL、Semgrep、OpenGrep 都是静态分析工具，但它们不是同一种分析模型。

| 工具 | 核心模型 | 主要侧重点 | 结果特点 |
|---|---|---|---|
| CodeQL | 语义分析 + 数据流分析 | 找可利用漏洞链 | 数量较少，但漏洞链更完整 |
| Semgrep | 规则模式匹配 + 轻量语义 | 找危险写法、配置问题、常见漏洞模式 | 快，结果较直观 |
| OpenGrep | 本地规则库匹配，兼容 Semgrep 规则生态 | 用大规则库做多语言广覆盖 | 覆盖广，结果通常更多 |

一句话：

```text
CodeQL 负责深挖漏洞链。
Semgrep 负责快速发现典型危险写法。
OpenGrep 负责用本地规则库做更广的覆盖。
```

## 2. 为什么结果不一样

三个工具结果不同不是异常，而是正常现象。

主要原因有 5 类：

| 原因 | 说明 |
|---|---|
| 分析模型不同 | CodeQL 会建 database 并分析数据流；Semgrep/OpenGrep 更偏规则匹配 |
| 规则集不同 | CodeQL 的 `java-queries`、`java-security-and-quality.qls` 结果会明显不同 |
| 环境依赖不同 | CodeQL Java 依赖 JDK/Maven/classpath，环境不完整会漏结果 |
| 输出格式不同 | CodeQL CSV、SARIF、MCP JSON 包含的信息层级不同 |
| 过滤策略不同 | 有的结果只保留安全漏洞，有的包含质量、诊断、遥测结果 |

例如 Java 项目里：

```text
--queries codeql/java-queries
```

和：

```text
--queries ...\java-security-and-quality.qls
```

不是同一个扫描范围。后者会包含更多质量类和扩展安全规则，例如 `Log Injection`、`Missing Override annotation`、资源泄露等。

## 3. CodeQL

### 3.1 工作方式

CodeQL 的流程是：

```text
源代码
  ↓
创建 CodeQL database
  ↓
运行 CodeQL 查询规则
  ↓
输出 CSV / SARIF / JSON
```

CodeQL 会把源码解析成数据库，再用查询语言分析代码结构、调用关系和数据流。

它关注的是：

```text
外部输入从哪里来
经过了哪些函数
最后流向了哪个危险点
中间有没有过滤或校验
```

### 3.2 擅长发现的问题

CodeQL 适合找漏洞链，例如：

| 类型 | 示例 |
|---|---|
| 注入漏洞 | SQL 注入、命令注入、LDAP 注入、表达式注入 |
| Web 漏洞 | XSS、SSRF、重定向、响应拆分 |
| 文件问题 | 路径穿越、Zip Slip、任意文件访问 |
| XML 问题 | XXE |
| 序列化问题 | 不安全反序列化 |
| 敏感信息 | 错误信息泄露、敏感信息写日志 |
| 认证授权 | JWT、CSRF、Cookie 安全 |

### 3.3 优点

| 优点 | 说明 |
|---|---|
| 数据流强 | 能发现从 source 到 sink 的完整漏洞链 |
| 语义理解强 | 不只是看字符串，还理解调用关系和类型 |
| 漏洞解释清楚 | SARIF 中通常有路径、source、sink、规则信息 |
| 适合深度审计 | 对 Java、Python、JavaScript 等语言效果较好 |

### 3.4 缺点

| 缺点 | 说明 |
|---|---|
| 慢 | 需要创建 database，Java 项目尤其慢 |
| 依赖环境 | Java 需要 JDK、Maven/Gradle、classpath |
| 配置敏感 | 查询套件不同，结果差异很大 |
| 跨语言成本高 | 通常一个语言一次建库分析 |

### 3.5 本项目推荐命令

Java 默认安全查询：

```cmd
python -m test_codeql D:\BaiduNetdiskDownload\fortify\java-sec-code-master --language java --queries codeql/java-queries --timeout-seconds 3600
```

Java 安全 + 质量查询：

```cmd
python -m test_codeql D:\BaiduNetdiskDownload\fortify\java-sec-code-master --language java --queries D:\BaiduNetdiskDownload\codeql\qlpacks\codeql\java-queries\1.11.2\codeql-suites\java-security-and-quality.qls --timeout-seconds 3600
```

只想安全扩展，不想质量类：

```cmd
python -m test_codeql D:\BaiduNetdiskDownload\fortify\java-sec-code-master --language java --queries D:\BaiduNetdiskDownload\codeql\qlpacks\codeql\java-queries\1.11.2\codeql-suites\java-security-extended.qls --timeout-seconds 3600
```

Python：

```cmd
python -m test_codeql D:\BaiduNetdiskDownload\CCAM\test --language python --queries codeql/python-queries --timeout-seconds 3600
```

## 4. Semgrep

### 4.1 工作方式

Semgrep 更像规则匹配引擎。

它会根据规则描述匹配代码结构，例如：

```text
这里是否调用了危险函数
这里是否用了不安全参数
这里是否硬编码了密钥
这里是否出现了常见漏洞写法
```

Semgrep 不需要像 CodeQL 那样先建 database。

### 4.2 擅长发现的问题

| 类型 | 示例 |
|---|---|
| 危险 API | `eval`、`exec`、`Runtime.exec`、`shell=True` |
| 不安全配置 | CORS 过宽、Cookie 缺少安全属性、debug 开启 |
| 硬编码秘密 | Token、密钥、密码、Access Key |
| 框架常见问题 | Flask/Django/Spring/Express 常见危险写法 |
| 简单注入模式 | 简单 SQL 拼接、模板注入、命令拼接 |
| 供应链或配置 | Dockerfile、YAML、Terraform、CI 配置问题 |

### 4.3 优点

| 优点 | 说明 |
|---|---|
| 快 | 不需要建库 |
| 简单 | 执行命令直接出 JSON |
| 跨语言方便 | 规则覆盖多语言 |
| 容易自定义 | YAML 规则易写易改 |
| 适合 CI | 可以快速作为第一轮扫描 |

### 4.4 缺点

| 缺点 | 说明 |
|---|---|
| 深层数据流弱 | 对复杂跨函数漏洞链不如 CodeQL |
| 误报可能较多 | 规则过宽时容易报危险模式但不一定可利用 |
| 依赖规则质量 | 规则写得好坏直接决定效果 |
| 对项目语义理解有限 | 类型、依赖、框架上下文理解有限 |

### 4.5 本项目推荐命令

```cmd
python -m test_semgrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master
```

限制返回条数：

```cmd
python -m test_semgrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master --max-findings 100
```

默认会排除：

```text
codeql_db
reports
node_modules
venv
.git
target
build
```

## 5. OpenGrep

### 5.1 工作方式

OpenGrep 和 Semgrep 的审查方向接近，都是规则驱动。

当前项目中 OpenGrep 使用的是本地：

```text
D:\BaiduNetdiskDownload\semgrep-rules
```

也就是说，OpenGrep 的覆盖范围很大程度取决于你下载的 `semgrep-rules` 规则库。

### 5.2 擅长发现的问题

OpenGrep 擅长做广覆盖扫描：

| 类型 | 示例 |
|---|---|
| 多语言危险写法 | Java、Python、JavaScript、Go、PHP、Ruby 等 |
| 框架规则 | Spring、Django、Flask、FastAPI、Express 等 |
| 配置文件风险 | Dockerfile、YAML、Terraform、JSON |
| 密钥泄露 | API Key、Token、私钥、密码 |
| 安全审计规则 | 注入、弱加密、不安全随机数、不安全反序列化 |

### 5.3 优点

| 优点 | 说明 |
|---|---|
| 本地规则库 | 不强依赖在线 registry |
| 覆盖广 | 使用完整 semgrep-rules 时结果更多 |
| 多语言方便 | 适合扫混合语言项目 |
| 快于 CodeQL | 不需要建 database |

### 5.4 缺点

| 缺点 | 说明 |
|---|---|
| 结果可能很多 | 大规则库会带来大量 INFO/WARNING |
| 和 Semgrep 有重叠 | 因为使用相似规则生态 |
| 误报需要人工筛 | 广覆盖规则通常需要去重和筛选 |
| 深层数据流有限 | 复杂漏洞链仍然不如 CodeQL |

### 5.5 本项目推荐命令

使用默认完整规则库：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master
```

只扫 Java 规则：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master --rule-path D:\BaiduNetdiskDownload\semgrep-rules\java
```

额外排除目录：

```cmd
python -m test_opengrep D:\BaiduNetdiskDownload\fortify\java-sec-code-master --exclude codeql_db --exclude reports
```

当前默认已经排除：

```text
codeql_db
reports
node_modules
venv
.git
target
build
```

## 6. 三者审查方向对比

| 维度 | CodeQL | Semgrep | OpenGrep |
|---|---|---|---|
| 分析深度 | 深 | 中 | 中 |
| 规则覆盖 | 取决于 query suite | 取决于 config/registry | 取决于本地规则库 |
| 数据流能力 | 强 | 中等 | 中等 |
| 速度 | 慢 | 快 | 快到中等 |
| Java 环境依赖 | 强依赖 Maven/JDK | 弱依赖 | 弱依赖 |
| 多语言项目 | 通常按语言分别跑 | 方便 | 方便 |
| 密钥检测 | 不是主要强项 | 强 | 强 |
| 配置文件检测 | 有限 | 强 | 强 |
| 漏洞链解释 | 强 | 中 | 中 |
| 误报情况 | 相对少 | 中等 | 中等偏多 |
| 适合阶段 | 深度审计 | 快速扫描/CI | 广覆盖扫描 |

## 7. 结果数量差异如何理解

不要简单用“条数多”判断工具强弱。

正确理解方式：

| 情况 | 说明 |
|---|---|
| CodeQL 条数少 | 可能是只报可达漏洞链，或者 query suite 较窄 |
| Semgrep 条数多 | 可能包含危险模式、配置、密钥、最佳实践 |
| OpenGrep 条数更多 | 可能因为本地规则库加载范围更大 |
| SARIF 比 CSV 多 | SARIF 可能包含诊断、质量、遥测或更多规则结果 |
| Java 结果突然变少 | 通常是 Maven/JDK/classpath 没配好 |

以本地 Java 项目为例：

```text
codeql/java-queries                 -> 106 条
java-security-and-quality.qls        -> 186 条
别人给的 SARIF                      -> 177 条
```

差异主要来自查询套件不同，不是扫描失败。

## 8. 推荐组合策略

### 8.1 快速初筛

先跑：

```text
Semgrep
OpenGrep
```

目的：

```text
快速发现危险 API、配置问题、硬编码秘密、明显漏洞模式
```

### 8.2 深度验证

再跑：

```text
CodeQL
```

目的：

```text
确认 source 到 sink 的漏洞链
降低误报
找复杂数据流问题
```

### 8.3 Java 项目推荐顺序

```text
1. 配好 JDK 和 Maven
2. OpenGrep 快速广覆盖
3. Semgrep 做补充对照
4. CodeQL 跑 java-security-and-quality.qls
5. 按规则和文件去重
6. 优先审 CodeQL 高危 + OpenGrep/Semgrep 高危交集
```

## 9. 结果优先级建议

建议按这个顺序看：

| 优先级 | 结果类型 |
|---|---|
| P0 | CodeQL 的命令注入、SQL 注入、SSRF、XSS、路径穿越、反序列化 |
| P1 | OpenGrep/Semgrep 的 ERROR 且命中安全类别 |
| P2 | 多个工具同时命中的同一文件/同一函数 |
| P3 | 硬编码密钥、配置错误、Cookie/CORS/Debug 问题 |
| P4 | 代码质量类、最佳实践类、Recommendation |

需要重点人工确认的结果：

```text
Log Injection
Information exposure through an error message
Potential resource leak
Deprecated method
Missing Override annotation
```

这些不一定都是可利用漏洞，但适合做安全整改和质量整改。

## 10. 实战建议

### 10.1 不要只看数量

例如：

```text
OpenGrep 300 条
CodeQL 100 条
```

不代表 OpenGrep 更准。OpenGrep 可能覆盖更多规则和语言，而 CodeQL 报的是更深的数据流漏洞。

### 10.2 不要把 Semgrep 和 OpenGrep 简单相加

因为 OpenGrep 当前使用的是 `semgrep-rules`，和 Semgrep 有大量规则来源重叠。

建议：

```text
Semgrep/OpenGrep 之间做去重
CodeQL 单独作为深度漏洞链结果
```

### 10.3 Java 项目必须关注 Maven

CodeQL Java 如果 Maven 没配好，会出现：

```text
mvn.cmd 找不到
classpath 不完整
scanned files 变少
dependency graph failed
```

这会导致结果明显少。

检查：

```cmd
mvn -version
java -version
```

本项目已配置：

```env
MAVEN_HOME=D:\apache-maven-3.9.16-bin\apache-maven-3.9.16
```

Maven 依赖下载目录：

```text
D:\maven-repository
```

### 10.4 查询套件要固定

做结果对比时，必须固定这些条件：

```text
CodeQL 版本
查询套件
JDK 版本
Maven 配置
build-mode
输出格式
过滤规则
```

否则不同人的结果数量不一致是正常的。

## 11. 推荐默认策略

如果目标是安全审计，推荐：

```text
OpenGrep: 全规则库广覆盖
Semgrep: auto + security-audit + secrets
CodeQL Java: java-security-and-quality.qls
CodeQL Python: codeql/python-queries
```

如果目标是只看可利用安全漏洞，推荐：

```text
OpenGrep: 只看 ERROR / security 类
Semgrep: 只看 ERROR / security 类
CodeQL Java: java-security-extended.qls 或 codeql/java-queries
```

如果目标是和别人 CodeQL SARIF 对齐，优先确认对方是不是用了：

```text
java-security-and-quality.qls
```

而不是：

```text
codeql/java-queries
```

