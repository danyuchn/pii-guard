// The pii-guard front end as a Mod.
//
// Every decision stays in the resident hookd service: this module only moves
// values between the engine's events and the service's endpoints. It talks to
// the service over loopback HTTP, reading the port and token from the state
// file the service writes.
//
// It FAILS CLOSED. A hook that cannot reach the service refuses the write or
// withholds the result itself; it never falls through to `next` unguarded,
// because a hook that throws is skipped and what is beneath it runs instead.

import type { Register } from 'claude-code'

const DEFAULT_HOME = '.local/share/pii-guard/hookd'

// Tools whose input is restored, or refused, on the way down.
const RESTORED = new Set(['Write', 'Edit', 'MultiEdit', 'Bash'])
const EGRESS = new Set(['WebFetch', 'WebSearch', 'Agent', 'Task', 'Workflow'])
// Tools whose result is de-identified on the way up.
const REDACTED = new Set(['Read', 'Bash', 'Grep'])
// The engine owns these and refuses a rewrite of any, so a rewritten input
// never carries them back.
const RESERVED = ['tool', 'tool_use_id', 'agentId', 'consent']

const OFFLINE = '[pii-guard] hookd unreachable; content withheld. Start it with: uv run pii-guard-hookd serve'
const DENY_OFFLINE = 'pii-guard: guard unreachable, so this call was refused rather than run unguarded'
const DROP_OFFLINE = 'pii-guard offline: the prompt was not checked for personal data, so it was not sent'
const SKIP_OFFLINE = 'pii-guard offline: the transcript was not swept, so it was not compacted'
const OFFLINE_CONTEXT =
  'pii-guard hookd is not running, so this result could not be de-identified and was withheld. ' +
  'Do not retry the same read through another tool. Tell the user to start the guard with ' +
  "'uv run pii-guard-hookd serve', then try again."
const OFFLINE_BRIEFING =
  'The pii-guard guard service is offline. Until the user starts it with ' +
  "'uv run pii-guard-hookd serve', do not read files that may contain personal data, " +
  'and tell the user the guard is off.'

type Connection = { port: string; token: string }

let cached: Connection | null = null
let briefing: string | null = null
let briefed = false

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

// Every call on `$` is a dispatch to the host, so all of them are async,
// `$.env.get` included: reading one without awaiting yields a Promise that
// stringifies into the path and turns every lookup into ENOENT.
async function homeDir($: any, options: Record<string, unknown>): Promise<string> {
  const configured = options['hookdHome']
  if (typeof configured === 'string' && configured.trim()) return configured.trim()
  const fromEnv = await $.env.get('PII_GUARD_HOOKD_HOME')
  if (typeof fromEnv === 'string' && fromEnv.trim()) return fromEnv.trim()
  const home = await $.env.get('HOME')
  return `${typeof home === 'string' ? home : ''}/${DEFAULT_HOME}`
}

// The state file is owner-only and holds the port and bearer token of the
// running service. A stale cache is dropped by the caller on any failure.
async function connect($: any, options: Record<string, unknown>): Promise<Connection> {
  if (cached) return cached
  const text = await $.fs.read(`${await homeDir($, options)}/state.env`)
  const port = /PII_HOOKD_PORT=(\d+)/.exec(text)?.[1]
  const token = /PII_HOOKD_TOKEN=(\S+)/.exec(text)?.[1]
  if (!port || !token) throw new Error('no hookd state')
  cached = { port, token }
  return cached
}

async function ask(
  $: any,
  options: Record<string, unknown>,
  event: string,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  let connection: Connection
  try {
    connection = await connect($, options)
  } catch (error) {
    cached = null
    throw error
  }
  const { port, token } = connection
  let response
  try {
    response = await $.http.fetch(`http://127.0.0.1:${port}/v1/hooks/${event}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Host: `127.0.0.1:${port}`,
      },
      body: JSON.stringify({ ...payload, session_id: await $.session.id() }),
    })
  } catch (error) {
    // The service may have restarted on a new port since the cache was filled.
    cached = null
    throw error
  }
  if (!response.ok) {
    cached = null
    throw new Error(`hookd answered ${response.status}`)
  }
  const reply = JSON.parse(response.text)
  if (!isRecord(reply)) throw new Error('unexpected reply')
  return reply
}

// Replace every string in a result whose shape is not pinned down, keeping the
// structure exactly: a reply that does not match the tool's own output shape is
// ignored, which would let the real values through.
function withholdLeaves(value: unknown, depth = 0): unknown {
  if (depth > 12) return value
  if (typeof value === 'string') return OFFLINE
  if (Array.isArray(value)) return value.map((item) => withholdLeaves(item, depth + 1))
  if (isRecord(value)) {
    const output: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value)) output[key] = withholdLeaves(item, depth + 1)
    return output
  }
  return value
}

function withheld(tool: string, result: unknown): unknown {
  if (tool === 'Read') {
    const file = isRecord(result) && isRecord(result['file']) ? result['file'] : {}
    return {
      type: 'text',
      file: {
        filePath: file['filePath'] ?? '',
        content: OFFLINE,
        numLines: 1,
        startLine: file['startLine'] ?? 1,
        totalLines: 1,
      },
    }
  }
  if (tool === 'Bash') {
    return { stdout: OFFLINE, stderr: '', interrupted: false, isImage: false }
  }
  return withholdLeaves(result)
}

function guarded(tool: string): boolean {
  return RESTORED.has(tool) || EGRESS.has(tool) || tool.startsWith('mcp__')
}

function inspected(tool: string): boolean {
  return REDACTED.has(tool) || tool.startsWith('mcp__')
}

function toolArguments(event: Record<string, unknown>): Record<string, unknown> {
  const input: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(event)) {
    if (!RESERVED.includes(key)) input[key] = value
  }
  return input
}

export const register: Register = (on, options) => {
  const settings = (options ?? {}) as Record<string, unknown>

  // A hook that throws or outruns its ten second budget is ABSENT, and what is
  // beneath it runs in its place. Every registration therefore carries a
  // .catch that answers the safe value itself; without one the guard would
  // fail open exactly when the service is in trouble.

  on('session.start', async ($, e, next) => {
    try {
      const reply = await ask($, settings, 'SessionStart', {})
      const specific = reply['hookSpecificOutput']
      const context = isRecord(specific) ? specific['additionalContext'] : undefined
      briefing = typeof context === 'string' ? context : null
    } catch {
      briefing = OFFLINE_BRIEFING
    }
    briefed = false
    return next(e)
  }).catch(() => undefined)

  on('prompt.submit', async ($, e, next) => {
    let text = e.text
    try {
      const reply = await ask($, settings, 'PromptSubmit', { prompt: e.text, cwd: await $.session.cwd() })
      if (typeof reply['text'] === 'string') text = reply['text']
    } catch {
      return { drop: DROP_OFFLINE }
    }
    // The session briefing rides the first prompt: session.start's own result
    // is echoed by core and cannot put anything in front of the model.
    const extra = briefed ? [] : briefing ? [briefing] : []
    briefed = true
    return next({ ...e, text, context: [...(e.context ?? []), ...extra] })
  }).catch(() => ({ drop: DROP_OFFLINE }))

  on('tool.call', async ($, e, next) => {
    let event: Record<string, unknown> = { ...e }
    if (guarded(e.tool)) {
      try {
        const reply = await ask($, settings, 'ToolCall', { tool: e.tool, input: toolArguments(event) })
        if (typeof reply['deny'] === 'string') return { deny: reply['deny'] }
        if (isRecord(reply['input'])) event = { ...event, ...reply['input'] }
      } catch {
        return { deny: DENY_OFFLINE }
      }
    }

    const answer: any = await next(event as any)
    if (!inspected(e.tool) || answer?.result === undefined) return answer
    try {
      const reply = await ask($, settings, 'ToolResult', { tool: e.tool, input: {}, result: answer.result })
      if (reply['result'] === undefined) return answer
      const context = Array.isArray(reply['context']) ? (reply['context'] as string[]) : answer.context
      // `ref` names core's own messages, which still hold the real values:
      // returning it would make core use them verbatim and ignore this result.
      return { result: reply['result'], context }
    } catch {
      return { result: withheld(e.tool, answer.result), context: [OFFLINE_CONTEXT] }
    }
  }).catch(async ($, e, next) => {
    // next is replay-safe here: when the hook had already run the tool, this
    // resolves to what that call settled to, running nothing again.
    if (!next.called) return { deny: DENY_OFFLINE }
    const answer: any = await next(e)
    if (answer?.result === undefined) return answer
    return { result: withheld(e.tool, answer.result), context: [OFFLINE_CONTEXT] }
  })

  on('session.compact', async ($, e, next) => {
    let messages = e.messages
    try {
      const down = await ask($, settings, 'Compact', { messages })
      if (Array.isArray(down['messages'])) messages = down['messages'] as typeof messages
    } catch {
      return { skip: SKIP_OFFLINE }
    }
    const answer = await next({ ...e, messages })
    if (answer.skip !== undefined) return answer
    try {
      const up = await ask($, settings, 'Compact', { messages: answer.messages })
      if (Array.isArray(up['messages'])) return { ...answer, messages: up['messages'] as typeof answer.messages }
      return answer
    } catch {
      return { skip: SKIP_OFFLINE }
    }
  }).catch(() => ({ skip: SKIP_OFFLINE }))
}
