# 安全策略

Agent Permission Gateway 是一个安全敏感组件：它决定 AI Agent 可以做什么。请认真对待
以下安全说明。

## 报告漏洞

**请不要公开披露漏洞。** 请通过以下渠道私下报告：

- 通过 GitHub 的 [Security Advisories](https://github.com/OWNER/AbertJob/security/advisories/new)（推荐）
- 或给维护者发送邮件（见仓库主页）

我们承诺：

- 48 小时内确认收到报告；
- 尽快修复并发布补丁版本；
- 在修复发布前不公开细节。

## 安全设计承诺

本项目把以下不变量视为安全边界，任何代码变更都不得破坏：

| 不变量 | 说明 |
|---|---|
| **Fail-closed** | 无批准通道时 ASK 退化为 DENY；无规则命中时受 `deny_risk_above` 熔断保护 |
| **解析器宁错勿宽** | YAML/glob 解析失败必须抛错（带行号），绝不静默放宽匹配（一个 `*` 的错误可能开错一扇门） |
| **风险只是证据** | 风险引擎只产生评分与旗标，从不单独裁决；裁定权在策略与操作者手里 |
| **Deny 优先** | 默认 `deny > approval > allow`；`deny: ["*"]` 是显式的 allowlist 模式，语义与"特定禁止"区分 |
| **授权有界** | 任何"Always allow"授权都必须满足 Action + Resource + Scope + Time，且有过期时间 |
| **审计 log-only** | `permission/gateway-decision` 事件永不出现在模型上下文 |

## 支持的版本

只维护最新主版本的安全补丁。发现旧版本存在漏洞时，请升级到最新版本。

## 致谢

感谢所有通过负责任的披露帮助我们改进安全性的研究者与用户。
