import { describe, expect, it } from 'vitest'
import {
  branchOf,
  classifyCommand,
  classifyTool,
  extractCall,
  inProductionWindow,
  isProductionCommand,
  lastUserTask,
  taskRelevance,
} from '../src/context.ts'
import { RISK_FLAGS } from '../src/risk.ts'

describe('classifyTool', () => {
  it('classifies filesystem tools', () => {
    expect(classifyTool('fs.read')).toBe('read')
    expect(classifyTool('fs.write')).toBe('write')
    expect(classifyTool('fs.delete')).toBe('delete')
    expect(classifyTool('filesystem.readFile')).toBe('read')
  })

  it('classifies shell tools', () => {
    expect(classifyTool('bash')).toBe('execute')
    expect(classifyTool('terminal')).toBe('execute')
    expect(classifyTool('run_code')).toBe('execute')
  })

  it('classifies network and deploy tools', () => {
    expect(classifyTool('http.fetch')).toBe('network')
    expect(classifyTool('github.create-repo')).toBe('write')
    expect(classifyTool('kubectl')).toBe('deploy')
    expect(classifyTool('aws')).toBe('deploy')
  })

  it('defaults unknown tools', () => {
    expect(classifyTool('weird.tool')).toBe('unknown')
  })
})

describe('classifyCommand', () => {
  it('classifies by program', () => {
    expect(classifyCommand('rm -rf ./build')).toBe('delete')
    expect(classifyCommand('git push origin main')).toBe('write')
    expect(classifyCommand('curl https://api.example.com')).toBe('network')
    expect(classifyCommand('kubectl apply -f deploy.yaml')).toBe('deploy')
    expect(classifyCommand('psql -c "DELETE FROM t"')).toBe('delete')
  })
})

describe('commandFlags', () => {
  it('detects destructive remove', () => {
    const flags = extractCall({ name: 'bash', arguments: { command: 'rm -rf ./build' } }).signals.what.flags
    expect(flags).toContain(RISK_FLAGS.destructiveRemove)
  })

  it('detects privilege escalation', () => {
    const flags = extractCall({ name: 'bash', arguments: { command: 'sudo systemctl restart nginx' } }).signals.what.flags
    expect(flags).toContain(RISK_FLAGS.privilegeEscalation)
  })

  it('detects credential material', () => {
    const flags = extractCall({ name: 'bash', arguments: { command: 'curl -H "Authorization: Bearer AKIAIOSFODNN7EXAMPLE" https://x' } }).signals.what.flags
    expect(flags).toContain(RISK_FLAGS.credentialAccess)
  })

  it('detects database writes without WHERE', () => {
    const flags = extractCall({ name: 'bash', arguments: { command: 'psql -c "UPDATE users SET admin = true"' } }).signals.what.flags
    expect(flags).toContain(RISK_FLAGS.databaseWrite)
  })
})

describe('production markers', () => {
  it('detects production namespaces and buckets', () => {
    expect(isProductionCommand('kubectl apply -f deploy.yaml --namespace=prod')).toBe(true)
    expect(isProductionCommand('aws s3 rm s3://production-bucket --recursive')).toBe(true)
    expect(isProductionCommand('git push origin main')).toBe(false)
    expect(isProductionCommand('npm test')).toBe(false)
  })
})

describe('branchOf', () => {
  it('extracts the pushed branch', () => {
    expect(branchOf('git push origin main')).toBe('main')
    expect(branchOf('git push origin feature/login')).toBe('feature/login')
    expect(branchOf('git push --set-upstream origin feature/x')).toBe('feature/x')
  })

  it('returns undefined for non-git commands', () => {
    expect(branchOf('npm test')).toBeUndefined()
  })
})

describe('extractCall', () => {
  it('builds the canonical action for shell calls', () => {
    const extracted = extractCall({ name: 'bash', arguments: { command: 'git push origin main' } })
    expect(extracted.signals.what.action).toBe('bash:git push origin main')
    expect(extracted.signals.what.program).toBe('git')
    expect(extracted.signals.where.kind).toBe('repository')
    expect(extracted.signals.where.branch).toBe('main')
  })

  it('classifies filesystem paths into workspace vs system', () => {
    const workspace = extractCall({ name: 'fs.write', arguments: { path: './workspace/src/main.ts' } })
    expect(workspace.signals.where.kind).toBe('workspace')
    expect(workspace.signals.where.resource).toBe('./workspace/src/main.ts')

    const system = extractCall({ name: 'fs.write', arguments: { path: '/etc/hosts' } })
    expect(system.signals.where.kind).toBe('system')
  })

  it('extracts host resources from network calls', () => {
    const extracted = extractCall({ name: 'http.fetch', arguments: { url: 'https://api.github.com/repos/x' } })
    expect(extracted.signals.where.kind).toBe('network')
    expect(extracted.signals.where.resource).toContain('api.github.com')
  })

  it('flags production from args', () => {
    const extracted = extractCall({ name: 'bash', arguments: { command: 'aws s3 rm s3://prod-bucket --recursive' } })
    expect(extracted.signals.where.production).toBe(true)
    expect(extracted.signals.where.kind).toBe('production')
  })

  it('computes task relevance from the WHY dimension', () => {
    const extracted = extractCall(
      { name: 'bash', arguments: { command: 'aws s3 rm s3://production-bucket' } },
      { task: 'fix the unit tests' },
    )
    expect(extracted.signals.why.task).toBe('fix the unit tests')
    expect(extracted.signals.why.mismatched).toBe(true)
  })

  it('reports unknown identity when not recognized', () => {
    const extracted = extractCall(
      { name: 'bash', arguments: { command: 'git status' } },
      { agentName: 'coding-agent', operatorName: 'alice', knownAgents: ['coding-agent'] },
    )
    expect(extracted.signals.who.known).toBe(true)
    expect(extracted.signals.who.agentName).toBe('coding-agent')
  })
})

describe('lastUserTask', () => {
  it('finds the last user/message text', () => {
    const events = [
      { type: 'turn/start', data: {} },
      { type: 'user/message', data: { content: [{ type: 'text', text: 'fix the login bug' }] } },
      { type: 'assistant/message', data: {} },
      { type: 'user/message', data: { content: [{ type: 'text', text: 'now run the tests' }] } },
    ]
    expect(lastUserTask(events as never)).toBe('now run the tests')
  })

  it('returns undefined without a user message', () => {
    expect(lastUserTask([{ type: 'turn/start', data: {} }] as never)).toBeUndefined()
  })
})

describe('taskRelevance', () => {
  it('measures keyword overlap', () => {
    expect(taskRelevance('deploy the app', 'deploy --app demo')).toBe(1)
    expect(taskRelevance('fix the unit tests', 'aws s3 rm production-bucket')).toBe(0)
    expect(taskRelevance('', 'anything')).toBe(1)
  })
})

describe('inProductionWindow', () => {
  it('respects day ranges', () => {
    // 2024-01-08 is a Monday.
    const monday = new Date(2024, 0, 8, 10, 0).getTime()
    expect(inProductionWindow(monday, ['09:00-18:00 Mon-Fri'])).toBe(true)
    const mondayNight = new Date(2024, 0, 8, 22, 0).getTime()
    expect(inProductionWindow(mondayNight, ['09:00-18:00 Mon-Fri'])).toBe(false)
    // 2024-01-06 is a Saturday.
    const saturday = new Date(2024, 0, 6, 10, 0).getTime()
    expect(inProductionWindow(saturday, ['09:00-18:00 Mon-Fri'])).toBe(false)
  })
})
