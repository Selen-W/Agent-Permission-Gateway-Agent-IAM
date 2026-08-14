/**
 * Glob matching used by policy rules, tool patterns, and grant scopes.
 *
 * Supported syntax:
 * - `*`  — any run of characters except `/` (also `:` in command patterns).
 * - `**` — any run of characters including `/`.
 * - `?`  — exactly one character (except `/`).
 * - `{a,b}` — alternation (no nesting).
 *
 * The matcher is compiled once per pattern; a failed compile (malformed
 * braces) falls back to exact equality so a typo cannot silently allow
 * everything.
 *
 * @module agent-permission-gateway/glob
 */

/**
 * Compile a glob pattern to a predicate.
 * @param pattern - the glob pattern.
 * @returns a predicate over candidate strings.
 */
export function compileGlob(pattern: string): (value: string) => boolean {
  try {
    const regex = globToRegExp(pattern)
    return (value: string) => regex.test(value)
  } catch {
    // A malformed pattern must fail closed: match only the literal string.
    return (value: string) => value === pattern
  }
}

/**
 * Convert a glob pattern to a RegExp.
 * @param pattern - the glob pattern.
 * @returns the anchored regular expression.
 */
export function globToRegExp(pattern: string): RegExp {
  let body = '^'
  let index = 0
  while (index < pattern.length) {
    const char = pattern[index]!
    if (char === '*') {
      // `**` crosses separators; a single `*` does not.
      if (pattern[index + 1] === '*') {
        body += '.*'
        index += 2
      } else {
        body += '[^/:]*'
        index += 1
      }
      continue
    }
    if (char === '?') {
      body += '[^/:]'
      index += 1
      continue
    }
    if (char === '{') {
      const end = pattern.indexOf('}', index)
      if (end === -1) throw new Error(`unclosed brace in glob: ${pattern}`)
      const inner = pattern.slice(index + 1, end)
      const parts = inner.split(',').map(escapeRegExp)
      body += `(?:${parts.join('|')})`
      index = end + 1
      continue
    }
    body += escapeRegExp(char)
    index += 1
  }
  body += '$'
  return new RegExp(body)
}/** Escape one regex metacharacter. */
function escapeRegExp(char: string): string {
  return /[.*+?^${}()|[\]\\]/.test(char) ? `\\${char}` : char
}

/**
 * Whether a plain string contains a glob metacharacter.
 */
export function hasGlobMeta(value: string): boolean {
  return /[*?{}]/.test(value)
}

/**
 * Match a command string against a command pattern with token semantics:
 * every token of the pattern must equal the corresponding token of the
 * command (prefix match on tokens, not on characters). `git push` matches
 * `git push origin main` but not `git pushy`. Globs are honored per token
 * when present; within a token `*`/`**` match any characters (including
 * `/` — a command token is not a path segment).
 * @param pattern - the command pattern (`git push`, `rm -rf *`).
 * @param command - the full command text.
 * @returns whether the command starts with the pattern's tokens.
 */
export function matchCommand(pattern: string, command: string): boolean {
  const patternTokens = tokenize(pattern)
  const commandTokens = tokenize(command)
  if (patternTokens.length === 0) return false
  if (commandTokens.length < patternTokens.length) return false
  for (let i = 0; i < patternTokens.length; i += 1) {
    const patternToken = patternTokens[i]!
    const commandToken = commandTokens[i]!
    if (hasGlobMeta(patternToken)) {
      if (!compileTokenGlob(patternToken)(commandToken)) return false
    } else if (patternToken !== commandToken) {
      return false
    }
  }
  return true
}

/**
 * Compile a glob for a single command token: `*`/`**` match everything
 * (tokens may contain `/`), `?` matches one character, `{a,b}` alternates.
 */
function compileTokenGlob(pattern: string): (value: string) => boolean {
  let body = '^'
  for (let i = 0; i < pattern.length; i += 1) {
    const char = pattern[i]!
    if (char === '*') {
      if (pattern[i + 1] === '*') i += 1
      body += '.*'
      continue
    }
    if (char === '?') {
      body += '.'
      continue
    }
    if (char === '{') {
      const end = pattern.indexOf('}', i)
      if (end === -1) return value => value === pattern
      const parts = pattern.slice(i + 1, end).split(',').map(escapeRegExp)
      body += `(?:${parts.join('|')})`
      i = end
      continue
    }
    body += escapeRegExp(char)
  }
  body += '$'
  try {
    const regex = new RegExp(body)
    return value => regex.test(value)
  } catch {
    return value => value === pattern
  }
}

/** Tokenize a shell command line, stripping quotes. */
export function tokenize(command: string): string[] {
  const tokens: string[] = []
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g
  let match: RegExpExecArray | null
  while ((match = re.exec(command)) !== null) {
    tokens.push(match[1] ?? match[2] ?? match[3]!)
  }
  return tokens
}

/**
 * Whether a host string matches a host glob. A pattern without glob meta is
 * matched as an exact host or a suffix of a dotted host (`github.com`
 * matches `api.github.com` only when prefixed by a dot-boundary wildcard).
 */
export function matchHost(pattern: string, host: string): boolean {
  const matcher = compileGlob(pattern)
  if (matcher(host)) return true
  // Bare domains also match their subdomains: github.com → api.github.com.
  if (!hasGlobMeta(pattern)) {
    return host === pattern || host.endsWith(`.${pattern}`)
  }
  return false
}
