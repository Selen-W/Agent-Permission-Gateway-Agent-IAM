# 贡献指南

感谢你愿意为 Agent Permission Gateway 贡献代码！这是一个安全敏感的组件——**策略解析
错误可能直接导致权限边界被错误地打开**——所以请仔细阅读以下约定。

## 行为准则

- 友善、专业、尊重。
- 涉及安全的行为（放行/拒绝语义、规则匹配、授权判定）变更必须附带测试。
- 不引入运行时依赖：核心必须保持零依赖，可独立编译、测试、审计。

## 开发环境

```sh
pnpm install
pnpm run check        # typecheck + 全部测试
pnpm run test:coverage
```

要求：Node.js ≥ 18，pnpm ≥ 9。

## 代码结构速览

| 目录/文件 | 职责 |
|---|---|
| `src/types.ts` | 公共词汇表（与 `@deepseek-ai/dsh-permission-gateway/types` 兼容） |
| `src/context.ts` | 工具调用 → WHO/WHAT/WHERE/WHEN/WHY 信号提取 |
| `src/risk.ts` | 风险引擎（纯函数） |
| `src/policy.ts` | 声明式策略 → 有序规则 |
| `src/grants.ts` | 有界授权 |
| `src/engine.ts` | 决策引擎（纯函数） |
| `src/host.ts` | 宿主结构契约（不 import 任何宿主包） |
| `src/service.ts` | 网关服务 |
| `src/index.ts` | Cordis 插件入口 |
| `tests/` | vitest 测试（每个模块一个 spec） |

## 如何贡献

1. **开 issue 先讨论**：行为语义（优先级、熔断、授权匹配）的变更影响所有使用者，
   请先说明动机与对既有策略的兼容性影响。
2. Fork 并创建 feature 分支：`feat/xxx` 或 `fix/xxx`。
3. 提交信息遵循 [Conventional Commits](https://www.conventionalcommits.org/)：
   `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`…
4. 任何逻辑变更都必须：
   - 新增/更新对应 `tests/*.spec.ts`；
   - `pnpm run check` 全绿；
   - 若改变了公共类型或行为语义，更新 `CHANGELOG.md` 与相关文档。
5. 开 PR，描述变更与测试结果。

## 安全相关变更

本项目的核心承诺：

- **fail-closed**：任何不确定路径都应当拒绝而不是放行。
- **解析器宁可报错**：YAML/glob 解析失败必须抛错（带行号），绝不静默放宽匹配。
- **风险只是证据**：风险引擎永远不单独裁决；裁定由策略与操作者作出。

触碰以上任何一条的 PR 需要额外的 review 关注。

## 发布

维护者按语义化版本发布：

1. 更新 `CHANGELOG.md` 与 `package.json` 版本号；
2. 打 tag（如 `v0.1.0`）并推送；
3. CI 通过后发布。
