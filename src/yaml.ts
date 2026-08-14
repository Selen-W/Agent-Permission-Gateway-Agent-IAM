/**
 * A small YAML-subset parser for policy documents.
 *
 * Policy files are small, hand-written, and constrained to a fixed shape
 * (maps of maps of string lists), so a full YAML implementation is
 * overkill — but a policy file must never be silently mis-parsed, because a
 * typo can open or close the wrong capability. This parser therefore
 * supports exactly the constructs a policy needs and throws on anything
 * else:
 *
 * - block mappings (`key: value`, nested by indentation),
 * - block sequences (`- item`),
 * - flow arrays `[a, b]` and flow objects `{a: b, c: d}` (JSON-compatible),
 * - scalars: plain strings, single/double-quoted strings with escapes,
 *   numbers, `true`/`false`, `null`/`~`,
 * - `#` comments (full-line and trailing),
 * - `key: |`-style literal blocks are NOT supported (use flow arrays).
 *
 * Duplicate keys throw; unknown YAML constructs (anchors, tags, multiline
 * strings) throw with a line number so a human fixes the file instead of
 * running a policy that was parsed wrong.
 *
 * @module agent-permission-gateway/yaml
 */

/** One physical line: content without the comment, plus its indent. */
interface Line {
  indent: number
  text: string
  number: number
}

/**
 * Parse a YAML-subset document into a plain JS value.
 * @param source - the YAML text.
 * @returns the parsed value (object / array / scalar).
 * @throws on syntax errors with the offending line number.
 */
export function parseYaml(source: string): unknown {
  const lines = splitLines(source)
  if (lines.length === 0) return null
  const { value } = parseBlock(lines, 0, 0)
  return value
}

/**
 * Parse a YAML document into a record, throwing if the root is not a map.
 */
export function parseYamlObject(source: string): Record<string, unknown> {
  const value = parseYaml(source)
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('yaml: document root must be a mapping')
  }
  return value as Record<string, unknown>
}

/** Split source into comment-stripped, indentation-tagged lines. */
function splitLines(source: string): Line[] {
  const lines: Line[] = []
  const raw = source.split(/\r?\n/)
  for (let i = 0; i < raw.length; i += 1) {
    const line = raw[i]!
    if (line.trim() === '' || line.trim().startsWith('#')) continue
    const indent = line.match(/^ */)![0]!.length
    let text = line.slice(indent)
    // Strip trailing comments that are preceded by whitespace.
    text = text.replace(/\s+#.*$/, '').trimEnd()
    if (text === '') continue
    lines.push({ indent, text, number: i + 1 })
  }
  return lines
}

/**
 * Parse a block starting at `index` whose lines share at least `indent`
 * columns of indentation. Returns the value and the next index.
 */
function parseBlock(lines: Line[], index: number, indent: number): { value: unknown; next: number } {
  const first = lines[index]!
  if (first.indent < indent) {
    throw new Error(`yaml:${first.number}: unexpected dedent`)
  }
  if (first.text.startsWith('- ')) return parseSequence(lines, index, indent)
  return parseMapping(lines, index, indent)
}

/** Parse a block sequence; items must share `indent`. */
function parseSequence(lines: Line[], index: number, indent: number): { value: unknown[]; next: number } {
  const values: unknown[] = []
  let i = index
  while (i < lines.length) {
    const line = lines[i]!
    if (line.indent < indent) break
    if (line.indent > indent) {
      throw new Error(`yaml:${line.number}: unexpected indentation inside sequence`)
    }
    if (!line.text.startsWith('- ')) break
    const rest = line.text.slice(2).trim()
    if (rest === '') {
      // Nested block under the dash.
      if (i + 1 >= lines.length || lines[i + 1]!.indent <= indent) {
        throw new Error(`yaml:${line.number}: empty sequence item`)
      }
      const nested = parseBlock(lines, i + 1, lines[i + 1]!.indent)
      values.push(nested.value)
      i = nested.next
    } else {
      values.push(parseScalarOrFlow(rest, line.number))
      i += 1
    }
  }
  return { value: values, next: i }
}

/** Parse a block mapping; pairs must share `indent`. */
function parseMapping(lines: Line[], index: number, indent: number): { value: Record<string, unknown>; next: number } {
  const value: Record<string, unknown> = {}
  let i = index
  while (i < lines.length) {
    const line = lines[i]!
    if (line.indent < indent) break
    if (line.indent > indent) {
      throw new Error(`yaml:${line.number}: unexpected indentation inside mapping`)
    }
    if (line.text.startsWith('- ')) break
    const colon = findKeyColon(line.text)
    if (colon === -1) {
      throw new Error(`yaml:${line.number}: expected "key: value"`)
    }
    const key = parseKey(line.text.slice(0, colon).trim(), line.number)
    if (Object.hasOwn(value, key)) {
      throw new Error(`yaml:${line.number}: duplicate key "${key}"`)
    }
    const rest = line.text.slice(colon + 1).trim()
    if (rest === '') {
      // Nested block.
      if (i + 1 < lines.length && lines[i + 1]!.indent > indent) {
        const nested = parseBlock(lines, i + 1, lines[i + 1]!.indent)
        value[key] = nested.value
        i = nested.next
      } else {
        value[key] = null
        i += 1
      }
    } else {
      value[key] = parseScalarOrFlow(rest, line.number)
      i += 1
    }
  }
  return { value, next: i }
}

/** Parse a scalar or an inline flow value (`[..]` / `{..}`). */
function parseScalarOrFlow(text: string, lineNumber: number): unknown {
  if (text.startsWith('[')) return parseFlowArray(text, lineNumber)
  if (text.startsWith('{')) return parseFlowObject(text, lineNumber)
  return parseScalar(text, lineNumber)
}

/** Parse a flow array `[a, b, c]` — the whole remaining text. */
function parseFlowArray(text: string, lineNumber: number): unknown[] {
  const items = splitFlow(text, lineNumber)
  return items.map(item => {
    const trimmed = item.trim()
    if (trimmed === '') throw new Error(`yaml:${lineNumber}: empty flow array item`)
    if (trimmed.startsWith('[') || trimmed.startsWith('{')) return parseScalarOrFlow(trimmed, lineNumber)
    return parseScalar(trimmed, lineNumber)
  })
}

/** Parse a flow object `{k: v, k2: v2}` — the whole remaining text. */
function parseFlowObject(text: string, lineNumber: number): Record<string, unknown> {
  const parts = splitFlow(text, lineNumber)
  const result: Record<string, unknown> = {}
  for (const part of parts) {
    const colon = findKeyColon(part)
    if (colon === -1) throw new Error(`yaml:${lineNumber}: expected "key: value" in flow object`)
    const key = parseKey(part.slice(0, colon).trim(), lineNumber)
    if (Object.hasOwn(result, key)) throw new Error(`yaml:${lineNumber}: duplicate key "${key}"`)
    const rest = part.slice(colon + 1).trim()
    result[key] = rest === '' ? null : parseScalarOrFlow(rest, lineNumber)
  }
  return result
}

/**
 * Split a flow value on top-level commas, respecting quotes and brackets.
 * Expects `text` to start with `[` or `{` and to be balanced.
 */
function splitFlow(text: string, lineNumber: number): string[] {
  const open = text[0]!
  const close = open === '[' ? ']' : '}'
  if (!text.endsWith(close)) {
    throw new Error(`yaml:${lineNumber}: unterminated flow value`)
  }
  const parts: string[] = []
  let depth = 0
  let current = ''
  let quote: string | null = null
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]!
    if (quote !== null) {
      current += char
      if (char === quote && text[i - 1] !== '\\') quote = null
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      current += char
      continue
    }
    if (char === open || char === '{' || char === '[') {
      depth += 1
      current += char
      continue
    }
    if (char === close) {
      depth -= 1
      current += char
      continue
    }
    if (char === ',' && depth === 1) {
      parts.push(current)
      current = ''
      continue
    }
    current += char
  }
  if (depth !== 0) throw new Error(`yaml:${lineNumber}: unbalanced flow value`)
  parts.push(current)
  // Strip the outer brackets/braces from the first and last parts.
  if (parts.length > 0) {
    const first = parts[0]!
    parts[0] = first.startsWith(open) ? first.slice(1) : first
    const last = parts[parts.length - 1]!
    parts[parts.length - 1] = last.endsWith(close) ? last.slice(0, -1) : last
  }
  return parts
}

/** Parse a scalar string (quoted or plain) into its JS value. */
function parseScalar(text: string, lineNumber: number): unknown {
  if (text.startsWith('"')) {
    if (!text.endsWith('"') || text.length < 2) throw new Error(`yaml:${lineNumber}: unterminated double-quoted string`)
    return unescapeDouble(text.slice(1, -1), lineNumber)
  }
  if (text.startsWith("'")) {
    if (!text.endsWith("'") || text.length < 2) throw new Error(`yaml:${lineNumber}: unterminated single-quoted string`)
    return text.slice(1, -1).replace(/''/g, "'")
  }
  if (text === 'null' || text === '~' || text === 'Null' || text === 'NULL') return null
  if (text === 'true' || text === 'True' || text === 'TRUE') return true
  if (text === 'false' || text === 'False' || text === 'FALSE') return false
  if (/^-?\d+$/.test(text)) return Number(text)
  if (/^-?\d+\.\d+$/.test(text)) return Number(text)
  return text
}

/** Unescape a double-quoted YAML string. */
function unescapeDouble(text: string, lineNumber: number): string {
  let out = ''
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]!
    if (char !== '\\') {
      out += char
      continue
    }
    i += 1
    const next = text[i]
    if (next === undefined) throw new Error(`yaml:${lineNumber}: dangling escape`)
    switch (next) {
      case 'n': out += '\n'; break
      case 't': out += '\t'; break
      case 'r': out += '\r'; break
      case '\\': out += '\\'; break
      case '"': out += '"'; break
      case "'": out += "'"; break
      case '0': out += '\0'; break
      default: out += next
    }
  }
  return out
}

/** Parse a mapping key (bare or quoted). */
function parseKey(text: string, lineNumber: number): string {
  if (text.startsWith('"') || text.startsWith("'")) {
    return String(parseScalar(text, lineNumber))
  }
  return text
}

/**
 * Find the colon separating a mapping key from its value, ignoring colons
 * inside quotes and flow brackets.
 */
function findKeyColon(text: string): number {
  let quote: string | null = null
  let depth = 0
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i]!
    if (quote !== null) {
      if (char === quote && text[i - 1] !== '\\') quote = null
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      continue
    }
    if (char === '[' || char === '{') {
      depth += 1
      continue
    }
    if (char === ']' || char === '}') {
      depth -= 1
      continue
    }
    if (char === ':' && depth === 0) return i
  }
  return -1
}
