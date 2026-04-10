# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

HTTP proxy that routes API requests through Claude Code's subscription billing instead of Extra Usage. Intercepts requests between client platforms (OpenClaw, Hermes) and `api.anthropic.com`, applies 7-layer detection bypass transformations outbound, and reverse-maps responses inbound. Zero dependencies — Node.js built-ins only.

## Running

```bash
node proxy.js                          # Start (default port 18801 + any profiles)
node proxy.js --port 19000             # Custom port
node proxy.js --config /path/to.json   # Custom config
node setup.js                          # Auto-detect credentials and generate config
node troubleshoot.js                   # Diagnose 8 layers independently
curl http://127.0.0.1:18801/health     # Health check (per-profile)
```

No build step, no linter, no test suite. Manual testing via `troubleshoot.js` or direct curl.

## Architecture

### Request Flow (7 Layers)

```
Client (:18801/:18802)
  → processBody():
    Layer 2: String sanitization (33 split/join patterns, unquoted, global)
    Layer 3: Tool name renames (29 quoted patterns, "exec" → "Bash")
    Layer 6: Property name renames (8 quoted patterns, "session_id" → "thread_id")
    Layer 4: System prompt template strip (~28K → ~0.5K paraphrase)
    Layer 5: Tool description strip + CC stub injection (5 fake tools)
    Layer 1: Billing header injection (84-char CC identifier into system array)
  → HTTPS to api.anthropic.com (OAuth token + 6 beta flags)
  → reverseMap(): tool names → property names → string replacements
  → Response back to client
```

### Multi-Profile System

Root config = default OpenClaw profile (port 18801, all 7 layers enabled). Additional profiles under `"profiles"` key get their own port and rules, sharing credentials. Each profile has independent `/health`.

Profiles default to all v2 layers **disabled** — enable explicitly if needed.

## Critical Configuration Gotcha

**`config.json` values override defaults entirely — no merging.** If `config.json` has `"replacements": [...]`, the 33-entry `DEFAULT_REPLACEMENTS` in proxy.js is completely ignored. To customize, either:
- Omit the key (fall through to defaults)
- Copy the full default array and modify

Currently: `config.json` omits `replacements`/`reverseMap` for the root profile (uses all defaults) and specifies them explicitly for the Hermes profile.

## Replacement Ordering

Longer substrings MUST come before shorter ones in replacement arrays:
- `sessions_yield_interrupt` before `sessions_yield`
- `lcm_expand_query` before `lcm_expand`
- `clawhub.com` before `clawhub`

Split/join is sequential — a shorter pattern matching first will corrupt the longer one.

## Quoted vs Unquoted Replacements

- **Layer 2 (strings):** Unquoted `m.split(find).join(replace)` — matches anywhere in body
- **Layers 3+6 (tools/properties):** Quoted `m.split('"'+orig+'"').join('"'+cc+'"')` — only matches JSON keys, avoids corrupting data values

## Reverse Mapping

Every `[A, B]` in `replacements` needs `[B, A]` in `reverseMap`. Missing entries cause silent response corruption — model outputs sanitized names that the client can't parse.

Reverse order: tool names (quoted, most specific) → property names (quoted) → string replacements (unquoted).

Applied to: SSE streaming chunks (real-time), buffered JSON responses, and error responses.

## System Prompt Stripping (Layer 4)

Looks for `"You are a personal assistant"` as start marker and `"AGENTS.md"` as end marker. Strips the config section between them (>1000 chars threshold) and inserts a prose paraphrase. If markers don't match, stripping silently skips. Update `IDENTITY_MARKER` if OpenClaw changes its system prompt format.

## Credentials

Auto-detected in order: `config.credentialsPath` → `~/.claude/.credentials.json` → `~/.claude/credentials.json` → macOS Keychain. Uses first non-empty file. BOM is stripped automatically. Token is re-read from disk per request (no caching of stale tokens).

## Detection Debugging

When Anthropic returns "out of extra usage" (detection failure), the proxy:
1. Logs `DETECTION! Body: Xb` to console
2. Dumps the transformed request body to `/tmp/proxy_detected_{profile}_{reqnum}.json`

Analyze dumps to find remaining trigger keywords: `python3 -c "import json; body=json.dumps(json.load(open('/tmp/proxy_detected_openclaw_1.json'))); [print(f'{body.count(t)}x {t}') for t in ['OpenClaw','openclaw','HEARTBEAT','clawhub','clawd','sessions_spawn'] if body.count(t)]"`

## Key Constants (proxy.js header)

- `BILLING_BLOCK`: 84-char CC billing identifier injected into system prompt
- `REQUIRED_BETAS`: 6 beta flags required for OAuth + CC features
- `CC_TOOL_STUBS`: 5 minimal tool schemas (Glob, Grep, Agent, NotebookEdit, TodoRead)
- `DEFAULT_REPLACEMENTS`: 33 string sanitization patterns
- `DEFAULT_TOOL_RENAMES`: 29 tool name → PascalCase CC mappings
- `DEFAULT_PROP_RENAMES`: 8 property name mappings
- `DEFAULT_REVERSE_MAP`: 33 reverse string patterns

## Git Workflow

Commit and push after every logical change. config.json is gitignored (contains local credential paths). The remote setup:
- `origin` → `saenidev/agent-proxy` (private fork)
- `upstream` → `zacdcook/openclaw-billing-proxy` (public source)

Do not include `Co-Authored-By` lines in commits.

## When Adding New Trigger Keywords

1. Add `[trigger, replacement]` to `DEFAULT_REPLACEMENTS` (respect ordering)
2. Add `[replacement, trigger]` to `DEFAULT_REVERSE_MAP`
3. If it's a tool name, add to `DEFAULT_TOOL_RENAMES` instead (quoted matching)
4. If it's a schema property, add to `DEFAULT_PROP_RENAMES` instead
5. For profile-specific triggers, add to the profile's `replacements`/`reverseMap` in `config.json`
6. Test: restart proxy, send request, check for `DETECTION!` in logs
