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
  → HTTPS to api.anthropic.com (OAuth token + 7 required betas, fast-mode gated to opus-4-6)
  → reverseMap(): tool names → property names → string replacements
  → Response back to client
```

### Multi-Profile System

Root config = default OpenClaw profile (port 18801, all 7 layers enabled). Additional profiles under `"profiles"` key get their own port and rules, sharing credentials. Each profile has independent `/health`.

Profiles default to v2 layers (toolRenames, propRenames, stripSystemConfig, stripToolDescriptions, injectCCStubs, stripTrailingAssistantPrefill) **disabled** — enable per-profile as needed. The Hermes profile currently runs with `stripToolDescriptions`, `injectCCStubs`, `stripTrailingAssistantPrefill` on, plus 47 `mcp_*`→PascalCase tool renames. `stripSystemConfig` stays off because its `IDENTITY_MARKER` only matches OpenClaw's prompt format.

### Emulated Claude Code Version

`CC_VERSION` (proxy.js:39) must stay reasonably close to a real CC release — Anthropic gates model-family access by CC version. Opus 4.7 subscription billing requires ≥ 2.1.112 (CC 2.1.97 gets routed to Extra Usage). Bump when Anthropic releases new models. Salt (`59cf53e54c78`) and indices `[4,7,20]` haven't changed across 2.1.97→2.1.112; verify by inspecting the CC binary (`strings $(readlink -f $(which claude)) | grep 59cf53e54c78`) before assuming.

### Model-Gated Betas

`fast-mode-2026-02-01` is Opus 4.6-exclusive. Sending it with any other model (4.7, Sonnet, Haiku) makes Anthropic reject subscription billing. The proxy gates this via the `MODEL_GATED_BETAS` table (proxy.js) that runs after `REQUIRED_BETAS` are added. To gate a new beta, add `{ beta, test: m => /regex/.test(m) }` to the table.

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

- `CC_VERSION`: Emulated Claude Code version; controls billing fingerprint + which models Anthropic will bill to subscription
- `BILLING_HASH_SALT` / `BILLING_HASH_INDICES`: Fingerprint inputs — must match the real CC binary for the emulated version
- `REQUIRED_BETAS`: 7 always-on beta flags (OAuth, CC core, tool use, thinking, caching, effort, context management)
- `MODEL_GATED_BETAS`: Betas sent only when the request's `model` matches a predicate (currently: fast-mode → opus-4-6 only)
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
3. If it's a tool name, add to `DEFAULT_TOOL_RENAMES` instead (quoted matching, auto-reversed by `reverseMap()`)
4. If it's a schema property, add to `DEFAULT_PROP_RENAMES` instead
5. For profile-specific triggers, add to the profile's `replacements` / `toolRenames` / `propRenames` / `reverseMap` in `config.json`
6. Test: restart proxy, send request, check for `DETECTION!` in logs

## When Debugging "Out of Extra Usage" on a Specific Model

If requests pass for some models but fail for others (e.g. Opus 4.6 works, Opus 4.7 fails), the issue is likely **not** a sanitization miss. Check in this order:

1. **Minimal-request sanity check** — `curl` the proxy with `{"model":"<model>","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`. If this fails, it's a billing-path issue (version, gated beta, subscription tier). If it passes, the request's *content* is the problem.
2. **Version gating** — bump `CC_VERSION` to the current installed CC (`claude --version`). Older CC versions aren't authorized for newer model families.
3. **Model-gated betas** — verify `MODEL_GATED_BETAS` correctly excludes model-exclusive betas (fast-mode, etc.) from incompatible models.
4. **Tool-name fingerprinting** — if minimal passes but real requests fail, bisect the request (strip thinking, tools, output_config, system) against the proxy to isolate the trigger. If tools are the cause, add `toolRenames` so every tool name looks like CC PascalCase.
5. **Tool-set bisection** — keep the request minimal but include the tools; progressively shrink the tool list. A characteristic prefix set (e.g. `mcp_*`) is almost always the fingerprint.
