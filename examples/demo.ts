/**
 * 演示：在模拟的 Cordis 上下文上挂载权限网关，跑几个典型调用。
 *
 * 运行：pnpm exec tsx examples/demo.ts
 */

import { readFileSync } from 'node:fs'
import { apply, PermissionGatewayService } from '../src/index.ts'
import type { CordisCtxLike, ToolExecutionLike } from '../src/host.ts'

/** 极简的内存会话。 */
function makeSession(id: string) {
  const events: Array<{ type: string; data: unknown }> = []
  return {
    id,
    events,
    append(type: string, data: unknown) {
      events.push({ type, data })
    },
  }
}

/** 极简的 Cordis 上下文（只实现插件用到的部分）。 */
function makeContext(policy: string): CordisCtxLike & {
  listeners: Map<string, Array<(...args: any[]) => any>>
  provided: Map<string, unknown>
} {
  const listeners = new Map<string, Array<(...args: any[]) => any>>()
  const provided = new Map<string, unknown>()
  return {
    config: { policy },
    listeners,
    provided,
    on(event, listener) {
      const list = listeners.get(event) ?? []
      list.push(listener)
      listeners.set(event, list)
      return () => {}
    },
    get<T>(name: string): T | undefined {
      return provided.get(name) as T | undefined
    },
    reflect: {
      provide(name, value) {
        provided.set(name, value)
      },
    },
  }
}

async function main(): Promise<void> {
  const policy = readFileSync(new URL('./policy.example.yaml', import.meta.url), 'utf8')
  const ctx = makeContext(policy)
  apply(ctx)
  const service = ctx.provided.get('permissionGateway') as PermissionGatewayService

  const session = makeSession('demo-session')
  session.append('user/message', { content: [{ type: 'text', text: 'fix the failing unit tests' }] })
  // 与策略 `agent: coding-agent` 对应，身份被识别
  const agent = { id: 'demo-session', session, options: { name: 'coding-agent' } }

  const call = (callId: string, name: string, args: unknown): ToolExecutionLike => ({ callId, name, arguments: args, agent })

  const preExecute = ctx.listeners.get('tools/pre-execute')![0]!
  const judge = async (exec: ToolExecutionLike) => {
    const result = await preExecute(exec, () => Promise.resolve({ kind: 'allow' }))
    return result as { kind: string; reason?: string }
  }

  console.log('═'.repeat(64))
  console.log('网关姿态：', JSON.stringify(service.summary()))
  console.log('═'.repeat(64))

  const cases: Array<[string, ToolExecutionLike]> = [
    ['git status（shell.allow）', call('c1', 'bash', { command: 'git status' })],
    ['git push origin main（shell.approval）', call('c2', 'bash', { command: 'git push origin main' })],
    ['sudo apt update（shell.deny）', call('c3', 'bash', { command: 'sudo apt update' })],
    ['fs.write ./workspace/src/a.ts（白名单）', call('c4', 'fs.write', { path: './workspace/src/a.ts' })],
    ['fs.delete ./workspace/src/a.ts（不在 tmp）', call('c5', 'fs.delete', { path: './workspace/src/a.ts' })],
    ['curl evil.example.com（network deny *）', call('c6', 'http.fetch', { url: 'https://evil.example.com' })],
    ['psql DROP TABLE（database.deny）', call('c7', 'bash', { command: 'psql -c "DROP TABLE users"' })],
    ['kubectl apply --namespace=prod（生产批准）', call('c8', 'bash', { command: 'kubectl apply -f x.yaml --namespace=prod' })],
    ['aws s3 rm s3://prod-bucket（任务不匹配，风险拉高）', call('c9', 'bash', { command: 'aws s3 rm s3://prod-bucket --recursive' })],
  ]

  for (const [label, exec] of cases) {
    const verdict = await judge(exec)
    const entry = service.recentAudit(1)[0]!
    const risk = entry.risk
    console.log(`\n▶ ${label}`)
    console.log(`  判决: ${verdict.kind.toUpperCase()}${verdict.reason !== undefined ? `  (${verdict.reason})` : ''}`)
    console.log(`  风险: ${risk.score}/100 ${risk.level}  flags=[${risk.flags.join(', ')}]`)
  }

  console.log('\n═'.repeat(64))
  console.log('演示“Always allow”授权：批准 git push 到 feature/*（1 小时内）')
  service.mintGrant({
    action: 'git push*',
    scope: { branch: 'feature/*', agent: 'coding-agent' },
    durationMs: 3_600_000,
    grantedBy: 'alice',
    reason: 'feature 分支推送获批',
  })
  const push = await judge(call('c10', 'bash', { command: 'git push origin feature/login' }))
  console.log(`  判决: ${push.kind.toUpperCase()}  ← 命中有界授权，不再打扰用户`)
  console.log('═'.repeat(64))
}

void main()
