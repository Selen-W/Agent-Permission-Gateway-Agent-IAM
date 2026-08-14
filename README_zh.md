<div align="center">

<img src="assets/logo.svg" alt="Agent Permission Gateway" width="120" />

# Agent Permission Gateway / Agent IAM

**要回答的根本问题：*Agent 被允许做什么？***

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/Selen-W/AbertJob/ci.yml?branch=main&label=CI)](.github/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen)](#开发与测试)
[![Node](https://img.shields.io/badge/node-%3E%3D18-339933)](#开发与测试)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/Selen-W/AbertJob?style=social)](https://github.com/Selen-W/AbertJob)

*[English](README.md) | 简体中文*

*IAM + 策略防火墙 + 人工审批 + 审计日志，面向 AI Agent*

</div>

当 Agent 能够调用 shell、文件系统、GitHub、数据库、云服务、浏览器乃至支付 API 时，权限控制
便不再是"增加一个确认弹窗"所能解决的，它成为 Agent 基础设施的组成部分。

本项目并非"弹窗确认插件"，而是一层 **Agent Permission Gateway**，置于 Agent 每一次工具调用
之前：

```text
                    User
                     │
                     ▼
                AI Agent
                     │
             Tool / Action
                     │
                     ▼
        ┌──────────────────────┐
        │ Agent Permission     │
        │ Gateway              │
        ├──────────────────────┤
        │ Identity  (WHO)      │
        │ Policy    (WHAT)     │
        │ Risk      (WHY/WHEN) │
        │ Approval  (scoped)   │
        │ Audit               │
        └──────────┬───────────┘
                   │
                   ▼
         ALLOW / DENY / ASK
```

第一原则：**Agent 不持有权限**。Agent 提出权限请求，由网关裁定是否放行。

**主要特性**

- 🚦 三种决策：**ALLOW / DENY / ASK**（ASK 进入宿主批准通道）
- 🧠 五维风险引擎：**WHO / WHAT / WHERE / WHEN / WHY**，输出 0–100 可解释评分
- 📜 声明式 YAML 策略：预先界定能力边界，而非逐次点击批准
- ⏱️ 有界授权：**一次性批准 ≠ 长期放行**（Action + Resource + Scope + Time）
- 🧾 全程审计：会话日志事件、进程级审计环与会话投影
- 🔌 零运行时依赖，标准 Cordis 插件，可直接挂载

## 快速开始

```sh
pnpm install
pnpm exec tsx examples/demo.ts     # 端到端演示：逐条查看判决与风险分解
pnpm run check                     # 类型检查 + 103 项测试
```

挂载到 dsh（`cordis.patch.yml`）：

```yaml
plugins:
  permission-gateway:
    $apply: ./agent_job_permission_dev/src/index.ts
    policy: |
      agent: coding-agent
      default_decision: ask
      permissions:
        shell:
          allow: ["git status", "git diff", "npm test"]
          deny:  ["sudo", "rm -rf /"]
```

不配置任何策略亦可使用：默认 fail-closed（`ask` 姿态，风险 ≥ 80 的调用直接拒绝）。

## 核心概念

### 1. 三种决策

| 决策 | 含义 | 示例 |
|---|---|---|
| **ALLOW** | 立即放行 | `read_file("readme.md")` — 命中 allow 条目 |
| **ASK** | 进入批准流程 | `git push origin main` — 命中 approval 条目或生产策略 |
| **DENY** | 拒绝并说明原因 | `rm -rf /` — 命中 deny 条目或风险熔断 |

### 2. 风险模型不限于命令本身

`git = allowed / rm = denied` 的粗粒度判断并不成立：推送至 `feature/*` 与推送至生产分支的
风险截然不同。因此风险引擎同时考察五个维度：

| 维度 | 信号 | 对风险的影响 |
|---|---|---|
| **WHO** | 发起方为哪个 Agent / 操作者 / 会话 | 未识别主体 +5；操作者本人 −5 |
| **WHAT** | read / write / execute / delete / network / deploy | 基础分 0 → 30 |
| **WHERE** | workspace / repository / database / **production** | 敏感度 0 → 45 |
| **WHEN** | 是否处于生产窗口内 | 窗口外 +20 |
| **WHY** | 任务关键词与动作的重合程度 | 不匹配 +15（如任务为修复测试，动作却是删除生产桶） |

风险只是**证据**，并非判决 —— 最终裁定由策略引擎给出。

### 3. 声明式策略

```yaml
agent: coding-agent
default_decision: ask
operator: alice
permissions:
  filesystem:
    read:   ["./workspace/**"]
    write:  ["./workspace/**"]
    delete: ["./workspace/tmp/**"]
  shell:
    allow:    ["git status", "git diff", "mvn test", "npm test"]
    approval: ["git commit", "git push"]
    deny:     ["sudo", "rm -rf /"]
  network:
    allow: ["github.com", "registry.npmjs.org"]
    deny:  ["*"]          # 默认拒绝：未列出的主机一律拒绝
  production:
    require_approval: true
    protected_branches: ["main", "master", "prod/*"]
    window: ["09:00-18:00 Mon-Fri"]
```

规则语义：

- 命令按 **token 前缀**匹配（`git push` 匹配 `git push origin main`，不匹配 `git pushy`）
- 默认优先级为 **deny > approval > allow**；`deny: ["*"]` 切换为 allowlist 模式（allow 优先，
  其余调用落入拒绝兜底）
- **能力特异性**：repository / database / deploy / network 的规则先于通用 shell 求值，
  `git push --force`（deny）可覆盖 `git push`（approval）
- 无规则命中且风险 ≥ `deny_risk_above`（默认 80）时触发熔断 DENY；显式规则命中可覆盖熔断

### 4. 批准与有界授权

判决为 ASK 时，宿主批准通道展示请求：

```text
⚠️ Approval Required
──────────────────────────────
Agent: coding-agent
User:  Alice
Action: git push origin main
Risk:   HIGH
Reason: Modifies protected branch
[Approve once]  [Always allow]  [Reject]
```

关键设计：**一次性批准 ≠ 长期放行**。"Always allow" 是一项有边界的授权：

```text
git push                                  （Action）
+ repository = github.com/company/project-a（Resource）
+ branch     = feature/*                  （Scope）
+ duration   = 1 hour                     （Time）
```

授权仅在 Action + Resource + Scope + Time 全部满足时生效，到期自动失效；命中有效授权的调用
直接放行，不再打扰操作者（`approval/request` 短路）。

### 5. 审计

每一次到达网关的调用都会写入：

- 会话日志事件 `permission/gateway-decision`（log-only，**永不出现在模型上下文**）
- 进程级审计环（默认 500 条，`service.recentAudit()`）
- 会话投影 `permissionGateway`（最近 50 条，供浏览器面板与重放共用）

## 文档

| 文档 | 内容 |
|---|---|
| [**使用手册**](docs/使用手册.md) | 完整参考：安装挂载、全部配置字段、策略语法、风险引擎、批准授权、审计、编程接口、常见场景、FAQ |
| [**示例策略**](examples/policy.example.yaml) | 一份带注释的完整能力边界示例 |
| [**端到端演示**](examples/demo.ts) | 可运行 demo：逐条展示判决、风险分解与授权短路 |
| [**变更日志**](CHANGELOG.md) | 版本历史与计划 |
| [**贡献指南**](CONTRIBUTING.md) | 行为准则、开发环境、PR 流程 |
| [**安全策略**](SECURITY.md) | 漏洞报告与安全设计承诺 |
| [**English README**](README.md) | English version |

## 项目结构

```text
src/
  types.ts      # 公共词汇表（与 dsh permission-gateway/types 兼容）
  glob.ts       # glob / 命令 token / 主机匹配
  yaml.ts       # 策略专用 YAML 子集解析器（宁可报错，绝不静默误解析）
  context.ts    # 工具调用 → WHO/WHAT/WHERE/WHEN/WHY 信号提取
  risk.ts       # 风险引擎（0–100 评分、档位、可解释贡献）
  policy.ts     # 声明式策略 → 有序规则
  grants.ts     # 有界授权（Action + Resource + Scope + Time）
  audit.ts      # 有界审计环
  engine.ts     # 决策引擎：风险 + 规则 + 授权 → 判决
  host.ts       # 宿主结构契约（tools / approval / session / …）
  service.ts    # 网关服务（judge / summary / audit / grants）
  index.ts      # Cordis 插件入口（apply）
examples/       # 示例策略与 demo
docs/           # 使用手册
tests/          # 103 项单测（含基于模拟宿主的端到端测试）
```

## 开发与测试

```sh
pnpm install
pnpm run typecheck      # tsc --noEmit
pnpm run test           # vitest
pnpm run test:coverage  # 覆盖率报告
pnpm run check          # 类型检查 + 测试
pnpm run demo           # 端到端演示
```

`tests/plugin.spec.ts` 基于模拟的 Cordis 上下文对插件进行端到端验证：`tools/pre-execute`
拦截、批准通道授权短路、审计事件落日志、策略热更新。

## 设计取舍

- **风险引擎为启发式**：仅产出证据，最终裁定始终由策略与操作者作出
- **解析器宁可报错**：YAML 属于安全边界，误读一个 `*` 可能打开错误的通路，故对不支持的
  结构抛出带行号的错误，而非静默误解析
- **`deny: ["*"]` 具有专门语义**："默认拒绝"（allow 优先）与"特定禁止"（覆盖 allow）含义不同
- **默认 fail-closed**：缺少批准通道时 ASK 退化为 DENY；无规则命中时受 `deny_risk_above`
  熔断保护

---

*更完整的内容——全部配置字段、风险评分表、批准授权 API、常见场景与 FAQ——见
[**使用手册**](docs/使用手册.md)。*

## 许可证

[MIT](LICENSE) © [AbertJob](https://github.com/Selen-W)
