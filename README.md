# VitaSentrion 🛡️

**The Zero-Dependency Firewall, Loop Breaker & Quality Linter for AI Coding Agents**
*A VitaLogic Labs Open-Source Research Project — [https://vitalogiclabs.com](https://vitalogiclabs.com)*

VitaSentrion is a lightweight, zero-dependency security firewall, runaway loop breaker, and code quality linter designed for developers running autonomous AI coding agents (Claude Code, Cursor, Cline, Roo Code, Aider, OpenCode).

## Why VitaSentrion?

Autonomous coding agents are powerful, but suffer from three critical failure modes:
1. Runaway Loops & Token Drain: Calling the same tool or editing the same file repeatedly without verification.
2. Security & Sandbox Escape: Unauthorized network connections to host SSH (:22), private subnets, or metadata IPs (169.254.169.254).
3. Repository Vandalism: Deleting test assertions, leaving scratch scripts (debug_test.py), and skipping git commits.

## Key Capabilities

- Pre-Tool Hook Guard (vitasentrion guard): Intercepts tool calls via stdin (Claude Code PreToolUse compatible). Blocks destructive commands, RFC1918/SSH escapes, and halts after 3 consecutive identical calls (exit code 2).
- Live Git & PR Scanner (vitasentrion scan): Scans any Git repository or PR diff (--base origin/main) for test weakening (deleted assertions), scratch files, uncommitted changes, and leaked API keys.
- Multi-Format Session Auditor (vitasentrion audit): Audits Claude Code JSONL, Cline JSON, and OpenAI/Hermes traces into ANSI, Markdown, or JSON scorecards.

## Quick Start

```bash
pip install .          # zero dependencies, Python 3.10+
vitasentrion -v
```

Three commands:

```bash
# 1. Pre-tool hook guard (reads a hook payload on stdin, exit 2 = blocked)
echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | vitasentrion guard

# 2. Repository / PR scan (run in a git repo)
vitasentrion scan .                       # whole working tree
vitasentrion scan . --base origin/main    # PR diff only

# 3. Session audit (Claude Code JSONL, Cline JSON, OpenAI/Hermes traces)
vitasentrion audit ~/claude-sessions/abc.jsonl --format markdown
```

Exit codes: `0` = clean, `1` = threshold tripped (`--fail-on warn|fail`), `2` = tool call blocked by the guard.

## Integrating the Guard

### Claude Code (`.claude/settings.json`)

Claude Code PreToolUse hooks receive the payload on stdin; a non-zero exit blocks the call and stderr is fed back to the model.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "vitasentrion guard" }
        ]
      }
    ]
  }
}
```

### Cline

Cline supports the same Claude-compatible `PreToolUse` hook (Cline 3.36+; enable **Hooks** in settings). A hook is a small script — create `~/.cline/hooks/PreToolUse.sh` (project-level: `clinerules/hooks/PreToolUse.sh`):

```bash
#!/usr/bin/env bash
exec vitasentrion guard
```

```bash
chmod +x ~/.cline/hooks/PreToolUse.sh
```

Cline serializes `tool_input` to a JSON string; the guard parses both object and string forms.

### GitHub Actions (CI)

```yaml
# .github/workflows/vitasentrion.yml
name: agent-safety
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install .
      - run: vitasentrion scan . --base origin/main --fail-on warn --format markdown
```

### Loop-breaker state

The guard keeps its loop-breaker state outside your repo (default: the OS temp dir, keyed by workspace path). Reset a stuck state with:

```bash
vitasentrion guard --reset
```

State older than one hour is discarded automatically, so an idle workspace never inherits a stale run. Every evaluated call is also appended to a ground-truth JSONL log next to the state file (auto-rotated at 5 MB), which `vitasentrion audit` can read back.

## Configuration (vitasentrion.toml)

VitaSentrion works with zero configuration. To tune it, drop a `vitasentrion.toml` in the target directory / repo root (the search stops at the repo root), or point at one explicitly with `--config <path>` on `audit`, `scan` and `guard`:

```toml
[guard]
max_consecutive_edits = 3      # R1 threshold (loop breaker + rules)
state_ttl_seconds = 3600       # loop-breaker state TTL
ignore_paths = [".scratch/*"]  # paths skipped by guard / scan
redact_secrets = true          # R5: replace secrets with [REDACTED:<TYPE>] instead of blocking

[rules]
R3 = "warn"                    # per-rule action: block | warn | ignore
R4 = "ignore"
R5 = "redact"                  # same as redact_secrets, per-rule form
R9 = "block"                   # repo injection scan: escalate warn -> fail

[custom]
blocked_commands = ["docker\s+system\s+prune"]  # extra R4 regexes
secret_patterns = ["hunter2{3,}"]                # extra R5 regexes
```

- No config file = the built-in defaults, exactly as before.
- `warn` downgrades a rule's finding (the guard lets WARN findings through); `ignore` disables the rule.
- **Secret redaction mode** (`redact_secrets = true` or `R5 = "redact"`): instead of hard-blocking a tool call whose arguments contain a credential, the call is allowed with a WARN finding, and every secret is replaced with a typed placeholder — `[REDACTED:OPENAI_KEY]`, `[REDACTED:AWS_KEY]`, `[REDACTED:ANTHROPIC_KEY]`, `[REDACTED:GITHUB_TOKEN]`, `[REDACTED:PRIVATE_KEY]`, `[REDACTED:GENERIC_SECRET]`. The guard's `events.jsonl` audit log, its loop-breaker state file and all scorecard reports then contain only redacted snippets — plaintext credentials never hit disk.
- Parsing uses stdlib `tomllib` (Python 3.11+); on 3.10 it uses `tomli` if installed, otherwise defaults apply with a warning. Unknown keys or invalid values fail loudly with an error.

## Rules Reference

- R1 LoopEntrapment: >=3 consecutive identical tool calls or >3 edits to same file without test.
- R2 TestIntegrity: Modified code without tests, failing test runs, or deleted assertions.
- R3 ScratchPollution: Temporary debug files left outside .scratch/.
- R4 GitHygiene: Uncommitted changes or destructive git commands (reset --hard, clean -f).
- R5 SecretLeakage: Leaked credentials (AWS, OpenAI, Anthropic, GitHub, Private Keys, .env). With redaction mode on (`redact_secrets = true` or `R5 = "redact"`), calls are allowed with a WARN finding and every secret becomes `[REDACTED:<TOKEN_TYPE>]` in the audit log and reports.
- R6 NetworkScopeEscape: Private subnets (RFC1918), metadata IPs, and SSH port 22.
- R7 TaintRelay: Network egress blocked while the session window still contains a sensitive-file read (live guard only).
- R8 EventsChainTampered: The guard's events log is hash-chained (SHA-256); `audit` flags any modified or deleted line.
- R9 RepoInjection: `scan` flags instruction files (AGENTS.md, .cursorrules, *.prompt, .github/ docs) containing override phrases ("ignore previous instructions"), hidden Unicode (zero-width / bidi), or base64 payload blobs. Defaults to warn; set `R9 = "block"` to fail the scan.

## License

MIT License. Developed by VitaLogic Labs ([https://vitalogiclabs.com](https://vitalogiclabs.com)).
