# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与
[语义化版本](https://semver.org/lang/zh-CN/)。所有显著变更都会记录在本文件。

## [Unreleased]

### 计划中

- 浏览器端审计面板（消费 `permissionGateway` 会话投影）
- 授权持久化（跨进程重启保留 grant）
- 更多内置信号提取器（GitHub API、Kubernetes、云厂商参数解析）

## [0.1.0] - 2025-08-14

首个公开版本：Agent Permission Gateway / Agent IAM 核心能力。

### 新增

- **三种决策**：`ALLOW` / `DENY` / `ASK`，挂在 `tools/pre-execute` 瀑布上，与 dsh 宿主工具注册表兼容。
- **五维风险引擎**：WHO / WHAT / WHERE / WHEN / WHY → 0-100 可解释评分 + 档位 + 风险旗标
  （`src/risk.ts` + `src/context.ts`）。
- **声明式策略**：YAML 或对象形式的 `PolicyDocument`，编译为有序规则
  （`src/policy.ts` + `src/yaml.ts` + `src/glob.ts`）。
  - 命令按 token 前缀匹配，路径/主机/分支按 glob 匹配；
  - `deny > approval > allow`，`deny: ["*"]` 触发 allowlist 模式；
  - 能力特异性排序（repository/database/deploy/network 先于通用 shell）；
  - 风险熔断 `deny_risk_above`，显式规则可覆盖熔断。
- **有界授权（Always allow）**：Action + Resource + Scope + Time 四元组，过期自动失效
  （`src/grants.ts`），`approval/request` 授权短路。
- **审计**：会话日志 `permission/gateway-decision` 事件（log-only）+ 进程级审计环
  （`src/audit.ts`）+ `permissionGateway` 会话投影。
- **宿主集成**：`permissionGateway` 服务注册、system-prompt 姿态段、settings 命名空间
  overlay、invariant 伴生插件（`src/index.ts` + `src/service.ts` + `src/host.ts`）。
- **文档**：README（产品定位与核心概念）、使用手册（完整配置/API/场景参考）、示例策略、
  可运行端到端演示。

### 测试

- 103 个单测（glob / yaml / risk / context / policy / grants / engine / plugin 端到端），
  行覆盖率 86.55%。
