/**
 * Signal extraction: turn one raw tool call into the five WHO / WHAT /
 * WHERE / WHEN / WHY dimensions the risk engine and the policy matcher
 * consume.
 *
 * This is deliberately heuristic and conservative — it parses tool names,
 * shell commands, and argument shapes with a compact rule table, and flags
 * what it cannot classify instead of guessing. Nothing here decides
 * anything; it only produces evidence.
 *
 * @module agent-permission-gateway/context
 */

import { matchHost, tokenize } from './glob.ts'
import { RISK_FLAGS } from './risk.ts'
import type {
  OperationKind,
  ResourceKind,
  RiskSignals,
  WhenSignal,
  WhereSignal,
  WhoSignal,
  WhySignal,
} from './types.ts'

/** A minimal tool call shape the extractor accepts. */
export interface ToolCallLike {
  readonly name: string
  readonly arguments: unknown
}

/** Extra context the extractor can use. */
export interface ExtractOptions {
  /** Wall-clock now (epoch ms); defaults to `Date.now()`. */
  readonly now?: number
  /** The agent's current task text, when known. */
  readonly task?: string
  /** The agent id. */
  readonly agentId?: string
  /** The agent display name. */
  readonly agentName?: string
  /** The operator (trusted principal) name. */
  readonly operatorName?: string
  /** Session id. */
  readonly sessionId?: string
  /** Production window strings (`"09:00-18:00 Mon-Fri"`). */
  readonly productionWindow?: readonly string[]
  /** Agent names the policy recognizes. */
  readonly knownAgents?: readonly string[]
}

/** The full extracted signal set plus raw call facts. */
export interface ExtractedCall {
  readonly signals: RiskSignals
  /** The tool name. */
  readonly tool: string
  /** Lossless JSON stringification of the arguments. */
  readonly argsText: string
}

/** Classify a tool name into a coarse operation. */
export function classifyTool(name: string): OperationKind {
  if (/^(fs|file|filesystem)[._-]/.test(name) || /(^|\.)(read|write|append|create|delete|remove|rename|copy|mkdir|stat|list|watch)/.test(name)) {
    // fs.* tools; read vs write decided from the verb below.
    if (/delete|remove|rm\b/.test(name)) return 'delete'
    if (/write|append|create|mkdir|rename|copy|move/.test(name)) return 'write'
    if (/read|stat|list|watch|open/.test(name)) return 'read'
    return 'write'
  }
  if (/^(bash|shell|terminal|exec|subprocess|run)[._-]?/.test(name) || name === 'bash' || name === 'pwsh' || name === 'sh') {
    return 'execute'
  }
  if (/^(git|github|repo|vcs)[._-]/.test(name) || /^git$/.test(name)) return 'write'
  if (/^(http|fetch|curl|network|npm|registry|mcp)[._-]/.test(name) || /http|fetch|curl/.test(name)) return 'network'
  if (/^(db|sql|database|postgres|mysql|redis|mongo)[._-]/.test(name) || /sql|query/.test(name)) {
    // Database tools: the verb in the tool name decides the operation.
    if (/delete|drop|truncate|remove/.test(name)) return 'delete'
    if (/read|query|select|get|list|find|count/.test(name)) return 'read'
    return 'write'
  }
  if (/^(deploy|k8s|kubernetes|aws|gcp|azure|terraform|helm|docker|kubectl|heroku|vercel|netlify)[._-]?/.test(name)) {
    return 'deploy'
  }
  return 'unknown'
}

/** Shell-like tools whose `command` argument is parsed as a command line. */
const SHELL_TOOLS = /^(bash|shell|terminal|exec|subprocess|run|sh|pwsh)[._-]?/

/** Operation implied by a shell program name. */
const PROGRAM_OPERATION: Record<string, OperationKind> = {
  rm: 'delete',
  rmdir: 'delete',
  unlink: 'delete',
  mv: 'write',
  cp: 'write',
  mkdir: 'write',
  touch: 'write',
  chmod: 'write',
  chown: 'write',
  git: 'write',
  curl: 'network',
  wget: 'network',
  nc: 'network',
  ssh: 'network',
  scp: 'network',
  npm: 'network',
  pnpm: 'network',
  yarn: 'network',
  pip: 'network',
  kubectl: 'deploy',
  helm: 'deploy',
  terraform: 'deploy',
  aws: 'deploy',
  gcloud: 'deploy',
  az: 'deploy',
  docker: 'deploy',
  heroku: 'deploy',
  psql: 'delete',
  mysql: 'delete',
  sqlite3: 'delete',
  mongosh: 'delete',
  rediscli: 'delete',
  sudo: 'execute',
  su: 'execute',
  systemctl: 'execute',
}

/** The first token of a command line, or undefined. */
function programOf(command: string): string | undefined {
  return tokenize(command)[0]
}

/** Database client programs whose SQL verb decides the operation. */
const DATABASE_PROGRAMS = new Set(['psql', 'mysql', 'sqlite3', 'mongosh', 'rediscli', 'mssql', 'pg_dump', 'pg_restore'])

/** Git subcommands that read repository state. */
const GIT_READ_SUBCOMMANDS = new Set([
  'status', 'diff', 'log', 'show', 'fetch', 'pull', 'clone', 'branch', 'remote',
  'ls-files', 'grep', 'blame', 'tag', 'describe', 'rev-parse', 'stash', 'list',
])

/** Classify a shell command into an operation. */
export function classifyCommand(command: string): OperationKind {
  const program = programOf(command)
  if (program === 'git') {
    const subcommand = tokenize(command)[1]
    if (subcommand !== undefined && GIT_READ_SUBCOMMANDS.has(subcommand)) return 'read'
    return 'write'
  }
  if (program !== undefined && DATABASE_PROGRAMS.has(program)) {
    // The SQL verb is more informative than the client program: SELECT is a
    // read, INSERT/UPDATE a write, DELETE/DROP/TRUNCATE a delete.
    if (/\b(DELETE\s+FROM|DROP\s+(TABLE|DATABASE|INDEX|VIEW)|TRUNCATE)\b/i.test(command)) return 'delete'
    if (/\b(INSERT|UPDATE|REPLACE|ALTER|CREATE|GRANT|REVOKE)\b/i.test(command)) return 'write'
    return 'read'
  }
  if (program !== undefined && program in PROGRAM_OPERATION) {
    return PROGRAM_OPERATION[program]!
  }
  // Fall back to the raw tool classification for `run_*` wrappers.
  return 'execute'
}

/** Canonical action string for one call. */
export function canonicalAction(tool: string, command?: string): string {
  return command !== undefined ? `${tool}:${command}` : tool
}

/**
 * Extract risk flags from a shell command.
 */
export function commandFlags(command: string): string[] {
  const flags: string[] = []
  if (/\brm\b/.test(command) && /-[a-z]*r/.test(command)) flags.push(RISK_FLAGS.destructiveRemove)
  if (/\brm\b/.test(command) && /(^|\s)\/[^\s]*(\s|$)/.test(command)) flags.push(RISK_FLAGS.broadWildcard)
  if (/\brm\b/.test(command) && /\*/.test(command)) flags.push(RISK_FLAGS.broadWildcard)
  if (/\bsudo\b/.test(command) || /\bsu\s+-/.test(command)) flags.push(RISK_FLAGS.privilegeEscalation)
  if (/chmod\s+[0-7]?[0-7]?[0-7]/.test(command) && /chmod\s+[0-7]*7/.test(command)) flags.push(RISK_FLAGS.privilegeEscalation)
  if (/\b(docker|kubectl)\s+exec\b/.test(command)) flags.push(RISK_FLAGS.privilegeEscalation)
  if (/\b(curl|wget|nc|ssh|scp|telnet)\b/.test(command)) flags.push(RISK_FLAGS.networkEgress)
  if (/\b(DELETE\s+FROM|DROP\s+(TABLE|DATABASE)|TRUNCATE)\b/i.test(command)) flags.push(RISK_FLAGS.databaseWrite)
  // `UPDATE … SET …` without WHERE is a SQL write; require the SET so
  // non-SQL uses of the word "update" (`apt update`) do not false-positive.
  if (/\bUPDATE\b/i.test(command) && /\bSET\b/i.test(command) && !/\bWHERE\b/i.test(command)) {
    flags.push(RISK_FLAGS.databaseWrite)
  }
  if (/AKIA[0-9A-Z]{16}|aws_access_key|password\s*=|token\s*=|\.env\b|id_rsa|secret/i.test(command)) {
    flags.push(RISK_FLAGS.credentialAccess)
  }
  return flags
}

/** Production markers that make a call production-touching. */
const PRODUCTION_MARKERS = [
  /(^|\s)--namespace=(prod|production)/i,
  /(^|\s)-n\s+(prod|production)\b/i,
  /(^|\s)--env(ironment)?=(prod|production)\b/i,
  /(^|\s)-e\s+(prod|production)\b/i,
  /s3:\/\/(prod|production)[.-]/i,
  /\bheroku\s+\w+\s+--app=?\s*[a-z-]*prod/i,
  /(^|\s)apply\b.*\b--auto-approve/i,
]

/** Detect whether a command touches production. */
export function isProductionCommand(command: string): boolean {
  return PRODUCTION_MARKERS.some(regex => regex.test(command))
}

/** Detect a git branch from a command. */
export function branchOf(command: string): string | undefined {
  const tokens = tokenize(command)
  if (tokens[0] !== 'git') return undefined
  const pushIndex = tokens.indexOf('push')
  if (pushIndex !== -1) {
    // `git push origin main` or `git push --set-upstream origin feature/x`
    for (let i = pushIndex + 1; i < tokens.length; i += 1) {
      const token = tokens[i]!
      if (token === '--set-upstream' || token === '-u') continue
      if (token === 'origin' || token === 'upstream') continue
      if (token.startsWith('-')) continue
      return token
    }
  }
  const checkoutIndex = tokens.indexOf('checkout')
  if (checkoutIndex !== -1) {
    for (let i = checkoutIndex + 1; i < tokens.length; i += 1) {
      const token = tokens[i]!
      if (token.startsWith('-')) continue
      if (token === '--') continue
      return token
    }
  }
  return undefined
}

/** Extract a host from a URL or bare host. */
function hostOf(value: string): string | undefined {
  const match = value.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/:\s]+)/i)
  if (!match) return undefined
  const host = match[1]!
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return host
  return host
}

/** Common argument keys that carry a path. */
const PATH_KEYS = ['path', 'filePath', 'file', 'target', 'source', 'destination', 'dir', 'directory', 'cwd', 'workspace', 'root']

/** Common argument keys that carry a host/url. */
const HOST_KEYS = ['url', 'host', 'domain', 'endpoint', 'baseUrl', 'base_url', 'repository', 'repo', 'remote', 'uri']

/** Flatten an arguments object into string values for inspection. */
function flattenArgs(args: unknown, depth = 0): string[] {
  if (depth > 3) return []
  if (typeof args === 'string') return [args]
  if (typeof args === 'number' || typeof args === 'boolean') return [String(args)]
  if (Array.isArray(args)) return args.flatMap(item => flattenArgs(item, depth + 1))
  if (typeof args === 'object' && args !== null) {
    return Object.entries(args as Record<string, unknown>).flatMap(([, value]) => flattenArgs(value, depth + 1))
  }
  return []
}

/** Extract a string argument by key. */
function stringArg(args: unknown, keys: readonly string[]): string | undefined {
  if (typeof args !== 'object' || args === null || Array.isArray(args)) return undefined
  const record = args as Record<string, unknown>
  for (const key of keys) {
    const value = record[key]
    if (typeof value === 'string' && value !== '') return value
  }
  return undefined
}

/** The agent's task from the last user message (a `user/message` event). */
export interface SessionEventLike {
  readonly type: string
  readonly data?: {
    readonly content?: unknown
    readonly text?: string
  }
}

/** Best-effort text extraction from a session event. */
function eventText(event: SessionEventLike): string | undefined {
  const data = event.data
  if (data === undefined) return undefined
  if (typeof data.text === 'string') return data.text
  if (typeof data.content === 'string') return data.content
  if (Array.isArray(data.content)) {
    const text = data.content
      .filter((block: { type?: string; text?: string }) => block.type === 'text' && typeof block.text === 'string')
      .map((block: { text?: string }) => block.text)
      .join(' ')
    return text === '' ? undefined : text
  }
  return undefined
}

/** Find the last human instruction from a session event list. */
export function lastUserTask(events: readonly SessionEventLike[]): string | undefined {
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const event = events[i]!
    if (event.type === 'user/message') {
      const text = eventText(event)
      if (text !== undefined && text.trim() !== '') return text.trim().slice(0, 512)
    }
  }
  return undefined
}

/** Stopwords dropped when computing task relevance. */
const STOPWORDS = new Set([
  'the', 'a', 'an', 'to', 'of', 'in', 'on', 'for', 'and', 'or', 'with', 'please',
  'can', 'you', 'your', 'me', 'my', 'i', 'we', 'us', 'it', 'this', 'that', 'these',
  'those', 'is', 'are', 'was', 'were', 'be', 'been', 'do', 'does', 'did', 'have',
  'has', 'had', 'will', 'would', 'should', 'could', 'can', 'not', 'no', 'at', 'by',
  'from', 'as', 'if', 'then', 'than', 'so', 'such', 'also', 'just', 'about', 'up',
  'out', 'into', 'over', 'after', 'before', 'between', 'under', 'again', 'once',
  '请', '把', '我', '你', '的', '了', '在', '是', '和', '与', '或', '为', '对', '用', '帮', '下',
])

/** Tokenize text into normalized keywords. */
function keywords(text: string): Set<string> {
  const words = text.toLowerCase().match(/[a-z0-9][a-z0-9_-]{1,}/g) ?? []
  const result = new Set<string>()
  for (const word of words) {
    if (!STOPWORDS.has(word)) result.add(word)
  }
  return result
}

/**
 * Compute task relevance: the fraction of task keywords that appear in the
 * action text. 1.0 means the action directly mentions the task's words.
 */
export function taskRelevance(task: string, actionText: string): number {
  const taskWords = keywords(task)
  if (taskWords.size === 0) return 1
  const actionLower = actionText.toLowerCase()
  let hits = 0
  for (const word of taskWords) {
    if (actionLower.includes(word)) hits += 1
  }
  return hits / taskWords.size
}

/**
 * Extract the full signal set from one tool call.
 */
export function extractCall(call: ToolCallLike, options: ExtractOptions = {}): ExtractedCall {
  const tool = call.name
  const args = call.arguments
  const argsText = safeJson(args)
  const now = options.now ?? Date.now()

  const command = extractCommand(tool, args)
  const program = command !== undefined ? programOf(command) : undefined
  const operation = command !== undefined
    ? classifyCommand(command)
    : classifyTool(tool)

  const whatFlags = command !== undefined ? commandFlags(command) : toolFlags(tool, argsText)

  // WHERE
  const where = extractWhere(tool, args, argsText, command)

  // WHEN
  const when: WhenSignal = {
    now,
    ...(where.production && options.productionWindow !== undefined && options.productionWindow.length > 0
      ? { inProductionWindow: inProductionWindow(now, options.productionWindow) }
      : {}),
  }

  // WHY
  const task = options.task
  let why: WhySignal
  if (task !== undefined && task.trim() !== '') {
    const relevance = taskRelevance(task, `${command ?? ''} ${tool} ${where.resource ?? ''} ${argsText}`)
    why = { task, relevance, mismatched: relevance < 0.25 }
  } else {
    why = { relevance: 1, mismatched: false }
  }

  // WHO
  const known = options.knownAgents !== undefined
    ? (options.agentName !== undefined && options.knownAgents.includes(options.agentName))
      || (options.agentId !== undefined && options.knownAgents.includes(options.agentId))
    : options.agentName === options.operatorName
  const who: WhoSignal = {
    ...options.agentId !== undefined ? { agentId: options.agentId } : {},
    ...options.agentName !== undefined ? { agentName: options.agentName } : {},
    ...options.operatorName !== undefined ? { operatorName: options.operatorName } : {},
    ...options.sessionId !== undefined ? { sessionId: options.sessionId } : {},
    known,
  }

  const signals: RiskSignals = { who, what: { operation, action: canonicalAction(tool, command), ...(command !== undefined ? { command } : {}), ...(program !== undefined ? { program } : {}), flags: whatFlags }, where, when, why }
  return { signals, tool, argsText }
}

/** Extract the command string from a shell-like call. */
function extractCommand(tool: string, args: unknown): string | undefined {
  if (!SHELL_TOOLS.test(tool)) return undefined
  if (typeof args === 'string') return args
  if (typeof args !== 'object' || args === null) return undefined
  const record = args as Record<string, unknown>
  for (const key of ['command', 'cmd', 'script', 'line', 'argv', 'input']) {
    const value = record[key]
    if (typeof value === 'string' && value !== '') return value
    if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'string') {
      return value.join(' ')
    }
  }
  return undefined
}

/** Classify WHERE from the tool, args, and command. */
function extractWhere(tool: string, args: unknown, argsText: string, command?: string): WhereSignal {
  const production = (command !== undefined && isProductionCommand(command)) || /prod(uction)?[._-]?(bucket|env|ns|cluster)/i.test(argsText)
  const branch = command !== undefined ? branchOf(command) : undefined

  // Database tools.
  if (/^(db|sql|database|postgres|mysql|redis|mongo|psql|mysql|sqlite|mongosh)[._-]?/.test(tool)) {
    return { kind: 'database', resource: stringArg(args, ['database', 'db', 'connection', 'connectionString', 'uri']), production, ...(branch !== undefined ? { branch } : {}) }
  }
  // Network tools.
  if (classifyTool(tool) === 'network') {
    const host = stringArg(args, HOST_KEYS)
    const fromUrl = host === undefined ? hostOf(flattenArgs(args).find(value => /^https?:\/\//.test(value)) ?? '') : host
    return { kind: 'network', resource: fromUrl, production, ...(branch !== undefined ? { branch } : {}) }
  }
  // Deploy tools.
  if (classifyTool(tool) === 'deploy') {
    return { kind: production ? 'production' : 'system', resource: stringArg(args, ['cluster', 'environment', 'env', 'stack', 'service']), production, ...(branch !== undefined ? { branch } : {}) }
  }
  // Git / repository tools.
  if (classifyTool(tool) === 'write' && (/^(git|github|repo|vcs)/.test(tool) || command?.startsWith('git '))) {
    const resource = stringArg(args, ['repository', 'repo', 'remote', 'url'])
    return { kind: 'repository', resource, production, ...(branch !== undefined ? { branch } : {}) }
  }
  // Filesystem tools.
  if (/^(fs|file|filesystem)/.test(tool)) {
    const path = stringArg(args, PATH_KEYS) ?? stringArg(args, ['path'])
    const kind: ResourceKind = path !== undefined && (path.startsWith('/') && !path.startsWith('/Users/') && !path.startsWith('/home/') && !path.startsWith('/workspace') && !path.startsWith('./') && !path.startsWith('../') && !path.startsWith('~/'))
      ? 'system'
      : 'workspace'
    return { kind, resource: path, production, ...(branch !== undefined ? { branch } : {}) }
  }
  // Shell commands.
  if (command !== undefined) {
    if (production) return { kind: 'production', resource: undefined, production, ...(branch !== undefined ? { branch } : {}) }
    const program = programOf(command)
    if (program === 'kubectl' || program === 'helm' || program === 'terraform' || program === 'aws' || program === 'gcloud' || program === 'az' || program === 'docker' || program === 'heroku') {
      return { kind: 'system', resource: undefined, production, ...(branch !== undefined ? { branch } : {}) }
    }
    if (program === 'psql' || program === 'mysql' || program === 'sqlite3' || program === 'mongosh') {
      return { kind: 'database', resource: undefined, production, ...(branch !== undefined ? { branch } : {}) }
    }
    if (program === 'git') {
      return { kind: 'repository', resource: undefined, production, ...(branch !== undefined ? { branch } : {}) }
    }
    if (program === 'curl' || program === 'wget' || program === 'nc' || program === 'ssh' || program === 'npm' || program === 'pnpm') {
      const host = hostOf(flattenArgs(args).find(value => /^https?:\/\//.test(value)) ?? '') ?? (program === 'ssh' ? undefined : undefined)
      return { kind: 'network', resource: host, production, ...(branch !== undefined ? { branch } : {}) }
    }
    return { kind: 'workspace', resource: undefined, production, ...(branch !== undefined ? { branch } : {}) }
  }
  return { kind: 'unknown', production, ...(branch !== undefined ? { branch } : {}) }
}

/** Tool-name / argument derived flags for non-shell calls. */
function toolFlags(tool: string, argsText: string): string[] {
  const flags: string[] = []
  if (/delete|remove|drop|truncate/i.test(tool) || /"(delete|remove|drop|truncate)"/i.test(argsText)) {
    flags.push(RISK_FLAGS.destructiveRemove)
  }
  if (/(^|\.)(delete|remove|drop|truncate)/i.test(tool)) flags.push(RISK_FLAGS.destructiveRemove)
  if (/AKIA[0-9A-Z]{16}|password\s*[:=]|token\s*[:=]|\.env|secret/i.test(argsText)) {
    flags.push(RISK_FLAGS.credentialAccess)
  }
  if (/^(github|git|repo)/.test(tool)) flags.push(RISK_FLAGS.protectedBranch)
  return flags
}

/** Whether `now` (epoch ms) falls inside any production window string. */
export function inProductionWindow(now: number, windows: readonly string[]): boolean {
  const date = new Date(now)
  const minutes = date.getHours() * 60 + date.getMinutes()
  const day = date.getDay() // 0 = Sunday
  for (const window of windows) {
    const parsed = parseWindow(window)
    if (parsed === undefined) continue
    const { start, end, days } = parsed
    if (!days.has(day)) continue
    if (minutes >= start && minutes < end) return true
  }
  return false
}

interface ParsedWindow {
  start: number
  end: number
  days: Set<number>
}

const DAY_INDEX: Record<string, number> = {
  sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6,
}

/** Parse `"HH:MM-HH:MM DDD[,DDD]"` where each DDD is a day or a `Mon-Fri` range (defaults to Mon-Fri). */
function parseWindow(window: string): ParsedWindow | undefined {
  const match = window.match(/^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})(?:\s+([A-Za-z,-]+))?$/)
  if (!match) return undefined
  const start = Number(match[1]) * 60 + Number(match[2])
  const end = Number(match[3]) * 60 + Number(match[4])
  if (start >= end) return undefined
  let days = new Set([1, 2, 3, 4, 5]) // Mon-Fri default
  const daySpec = match[5]
  if (daySpec !== undefined) {
    days = parseDaySpec(daySpec)
    if (days.size === 0) return undefined
  }
  return { start, end, days }
}

/** Parse a day spec like `Mon-Fri` or `Sat,Sun` into a set of day indexes. */
function parseDaySpec(spec: string): Set<number> {
  const days = new Set<number>()
  for (const part of spec.split(',')) {
    const trimmed = part.trim().toLowerCase()
    if (trimmed === '') continue
    const range = trimmed.match(/^([a-z]{3})-([a-z]{3})$/)
    if (range) {
      const from = DAY_INDEX[range[1]!]
      const to = DAY_INDEX[range[2]!]
      if (from === undefined || to === undefined) continue
      // Expand the range in week order (Mon..Sun), wrapping through Sunday.
      for (let day = from; ; day = (day + 1) % 7) {
        days.add(day)
        if (day === to) break
      }
      continue
    }
    const index = DAY_INDEX[trimmed]
    if (index !== undefined) days.add(index)
  }
  return days
}

/** Lossless JSON stringification that never throws. */
export function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? 'undefined'
  } catch {
    return String(value)
  }
}

/** Convenience re-export so callers can match hosts without importing glob. */
export { matchHost }
