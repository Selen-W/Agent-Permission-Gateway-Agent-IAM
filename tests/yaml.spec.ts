import { describe, expect, it } from 'vitest'
import { parseYaml, parseYamlObject } from '../src/yaml.ts'

describe('parseYaml', () => {
  it('parses the example policy document shape', () => {
    const source = `
# Agent capability boundary
agent: coding-agent
default_decision: ask
deny_risk_above: 80
operator: alice

permissions:
  filesystem:
    read:
      - ./workspace/**
    write:
      - ./workspace/**
    delete:
      - ./workspace/tmp/**
  shell:
    allow:
      - git status
      - git diff
      - mvn test
    approval:
      - git commit
      - git push
    deny:
      - sudo
      - rm -rf /
  network:
    allow:
      - github.com
      - registry.npmjs.org
    deny:
      - "*"
  production:
    require_approval: true
    window:
      - 09:00-18:00 Mon-Fri
`
    const value = parseYamlObject(source)
    expect(value.agent).toBe('coding-agent')
    expect(value.default_decision).toBe('ask')
    expect(value.operator).toBe('alice')

    const permissions = value.permissions as Record<string, any>
    expect(permissions.filesystem.read).toEqual(['./workspace/**'])
    expect(permissions.filesystem.delete).toEqual(['./workspace/tmp/**'])
    expect(permissions.shell.allow).toEqual(['git status', 'git diff', 'mvn test'])
    expect(permissions.shell.approval).toEqual(['git commit', 'git push'])
    expect(permissions.shell.deny).toEqual(['sudo', 'rm -rf /'])
    expect(permissions.network.deny).toEqual(['*'])
    expect(permissions.production.require_approval).toBe(true)
    expect(permissions.production.window).toEqual(['09:00-18:00 Mon-Fri'])
  })

  it('parses flow arrays and objects', () => {
    const value = parseYamlObject(`
a: [1, 2, three]
b: {x: 1, y: "two"}
c: true
d: null
`)
    expect(value.a).toEqual([1, 2, 'three'])
    expect(value.b).toEqual({ x: 1, y: 'two' })
    expect(value.c).toBe(true)
    expect(value.d).toBeNull()
  })

  it('parses quoted strings with escapes', () => {
    const value = parseYamlObject(`
a: "line1\\nline2"
b: 'it''s'
c: "say \\"hi\\""
`)
    expect(value.a).toBe('line1\nline2')
    expect(value.b).toBe("it's")
    expect(value.c).toBe('say "hi"')
  })

  it('ignores comments and blank lines', () => {
    const value = parseYamlObject(`
# top comment
a: 1  # trailing comment
b: two
`)
    expect(value).toEqual({ a: 1, b: 'two' })
  })

  it('throws on duplicate keys', () => {
    expect(() => parseYamlObject('a: 1\na: 2')).toThrow(/duplicate key/)
  })

  it('throws on non-mapping roots', () => {
    expect(() => parseYamlObject('- a\n- b')).toThrow(/root must be a mapping/)
  })

  it('throws with a line number on malformed input', () => {
    expect(() => parseYamlObject('a:\n  - x\n  b: 2')).toThrow(/yaml:\d+/)
  })

  it('parses numeric scalars', () => {
    const value = parseYamlObject('n: 42\nf: 3.5\nneg: -7')
    expect(value).toEqual({ n: 42, f: 3.5, neg: -7 })
  })

  it('handles an empty document', () => {
    expect(parseYaml('')).toBeNull()
    expect(parseYaml('# nothing here')).toBeNull()
  })
})
