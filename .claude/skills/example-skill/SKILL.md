---
name: example-skill
description: 一个示例模板，演示 skill 的基本写法。当用户提到"生成提交信息"或"commit message"时触发。
---

# 示例 Skill 模板

你现在就是 Claude Code，按下面的规则执行。

## 触发条件

当用户说"帮我写 commit message"、"生成提交信息"时使用此 skill。

## 规则

1. 先运行 `git diff --staged` 和 `git log --oneline -5` 获取变更内容和最近的提交风格
2. 用中文生成一条简洁的 commit message，格式为 `<type>: <简短描述>`
3. 常见的 type：feat、fix、refactor、docs、chore
4. 不要超过 50 个字符

## 示例输出

```
feat: 添加用户登录验证模块
```
