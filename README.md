# vitasentrion

A pre-tool-call guard, repository scanner, and session auditor for AI
coding agents (Claude Code, Cline, Cursor, Roo Code). Python 3.10+,
standard library only. No network access, no model in the loop, no
daemon.

## Architecture

One rule engine, three entry points, one shared data model.

```text
                 +---------------------+
  hook payload ->| guard (live)        |-> allow (exit 0) / block (exit 2)
  (stdin JSON)   |  R1 R4 R5 R6 R7    |-> events.jsonl (SHA-256 chained)
                 +---------------------+
                            |  the event log is itself a valid trace
                            v
                 +---------------------+
  session logs ->| audit (post-hoc)    |-> scorecard (console / md / json)
  (JSONL/JSON)   |  R1-R8              |
                 +---------------------+
                 +---------------------+
  git repo ----->| scan                |-> scorecard, incl. R9
  (worktree/PR)  |  R2 R3 R4 R5 + R9  |
                 +---------------------+
```

- `guard` — reads one tool-call payload on stdin (Claude Code
  PreToolUse shape, Cline shape, or a generic `{"name", "arguments"}`
  mapping), evaluates the live rules, and exits 0 (allow) or 2 (block;
  the reason goes to stderr so the agent can read it back). Every
  evaluated call, allowed or blocked, is appended to a hash-chained
  JSONL event log. The loop breaker keeps its state in a file outside
  the repo.
- `audit` — parses recorded sessions (Claude Code JSONL, Cline JSON,
  OpenAI/Hermes traces, or the guard's own event log) into a
  `SessionTrace` and evaluates rules post-hoc, producing a scorecard in
  console, Markdown, or JSON.
- `scan` — builds a `SessionTrace` from a git working tree or a PR diff
  (`--base origin/main`) via `git status`/`git diff`, and adds the
  repo-wide R9 instruction-file scan.

All three paths feed the same `SessionTrace` model and the same rule
functions in `rules.py`. The guard's event log is a first-class audit
source: a session the guard watched live can be re-audited later with
no extra logging setup. Each event line carries the SHA-256 hash of the
previous line; `audit` verifies the chain (R8), so a modified or
deleted line is detected.

## Scope and non-goals

What this is: an operational hook that inspects tool-call strings and
remembers call state. It is designed for cooperative, honest-but-
clumsy agents: it catches everyday failure modes (edit loops, deleted
assertions, destructive shell commands, leaked credentials) before they
reach the system.

What it is not:

- Not a sandbox. It uses no cgroups, namespaces, seccomp, eBPF, or any
  other kernel enforcement, and it cannot enforce anything the agent
  chooses to bypass. It inspects the arguments the agent announces; the
  agent's own sandbox is the enforcement layer. The two compose.
- Not an adversarial firewall. It pattern-matches command text and tool
  arguments. It does not catch evasion by dynamic execution, string
  concatenation, or obfuscated payloads (e.g. `eval "$(echo ... |
  base64 -d)"` or inline Python socket scripts).
- Not a network proxy. It matches explicit target IPs (RFC1918, IMDS
  169.254.169.254) and URLs in command text; it does not see raw
  sockets.
- Not measured. The rules catch the classes they match and nothing
  else. There is no published benchmark against attack suites yet.

## Install

Requires Python 3.10 or newer; no external dependencies.

```bash
pip install .
vitasentrion --help
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`
(`warn|fail`, audit/scan only), `2` call blocked by the guard.

## CLI usage

### 1. Pre-tool hook (`guard`)

Reads a JSON payload on stdin. Exits 0 if allowed, 2 if blocked
(reason on stderr, fed back into the agent context).

```bash
# Clean command (exits 0):
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | vitasentrion guard

# Destructive command (blocked, exits 2):
echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"}}' | vitasentrion guard
```

Loop-breaker state lives in the system temp directory and expires
after one hour of inactivity. To reset manually:

```bash
vitasentrion guard --reset
```

The event log next to the state file is auto-rotated at 5 MB; the
rotated copy keeps the oldest events.

### 2. Session audit (`audit`)

```bash
vitasentrion audit session.jsonl
vitasentrion audit session.jsonl --format markdown
vitasentrion audit session.jsonl --fail-on warn
```

### 3. Repository scan (`scan`)

```bash
# Scan local working tree:
vitasentrion scan .

# Scan a pull request diff in CI:
vitasentrion scan . --base origin/main --format markdown
```

## Configuration (vitasentrion.toml)

VitaSentrion searches for `vitasentrion.toml` in the target directory
and its parents up to the repository root; `--config <path>` overrides
the search. All options are optional — omitting the file keeps the
defaults below. Unknown sections, keys, rule ids, and invalid values
are rejected with an error rather than ignored. Parsing uses stdlib
`tomllib` (Python 3.11+); on 3.10 it uses `tomli` if installed,
otherwise defaults apply with a warning.

```toml
[guard]
max_consecutive_edits = 3          # R1 threshold (default: 3)
state_ttl_seconds = 3600           # state expiration window (default: 3600)
ignore_paths = [".scratch/*"]      # paths skipped by guard / scan
redact_secrets = false             # R5: redact instead of block (default: false)

[rules]
# Actions: "block" (fail), "warn", "ignore"; R5 also accepts "redact"
R3 = "warn"                        # downgrade scratch file pollution
R4 = "block"                       # destructive git commands fail
R5 = "redact"                      # replace secrets with [REDACTED:<TYPE>]
R9 = "warn"                        # repo injection detection (default)

[custom]
blocked_commands = []              # extra regexes for R4
secret_patterns = []               # extra regexes for R5
```

Secret redaction mode (`redact_secrets = true` or `R5 = "redact"`)
changes R5 from a hard block to: allow the call, emit a WARN finding,
and replace every matched credential with a typed placeholder —
`[REDACTED:OPENAI_KEY]`, `[REDACTED:ANTHROPIC_KEY]`,
`[REDACTED:AWS_KEY]`, `[REDACTED:GITHUB_TOKEN]`,
`[REDACTED:PRIVATE_KEY]`, or `[REDACTED:GENERIC_SECRET]` for custom
patterns. The event log, the loop-breaker state file, and all
scorecard formats then contain only the placeholders; plaintext
credentials never reach disk.

## Rules reference

Every rule's action is configurable; the table lists what each rule
detects and its default action with no config file.

| Rule | Name | Layer | Default | Description |
|------|------|-------|---------|-------------|
| R1 | LoopEntrapment | guard, audit | block | N consecutive identical tool calls, or repeated edits to one file without a test run between. |
| R2 | TestIntegrity | audit, scan | block | Code changed without accompanying test execution; failing test runs; deleted assertions. |
| R3 | ScratchPollution | audit, scan | warn | Temporary debug scripts left outside designated scratch directories. |
| R4 | GitHygiene | guard, scan, audit | block | Destructive git/shell commands (reset --hard, clean -f, rm -rf /); uncommitted diffs. |
| R5 | SecretLeakage | guard, scan, audit | block | API tokens and private keys (OpenAI, Anthropic, AWS, GitHub, SSH keys); .env access. |
| R6 | NetworkScopeEscape | guard, audit | block | Explicit targets in private subnets (RFC1918), IMDS (169.254.169.254), SSH/port 22, sudo, curl-piped-to-shell; writes outside the workspace root. |
| R7 | TaintRelay | guard | block | Network egress while the recent-call window still contains a sensitive-file read (.env, .ssh/*). |
| R8 | EventsChainTampered | audit | block | Verifies the SHA-256 hash chain across events.jsonl lines; flags modified, deleted, or reordered entries. |
| R9 | RepoInjection | scan | warn | Instruction files (AGENTS.md, .cursorrules, *.prompt, .github docs) containing override phrases, hidden Unicode, or base64 payload blobs. |

`warn` downgrades the finding (the guard lets warnings through);
`ignore` disables the rule. R9 defaults to warn because documentation
that discusses prompts legitimately contains "ignore previous
instructions"-style text; set `R9 = "block"` to fail a scan on any
hit.

## Agent integration examples

### Claude Code (`~/.claude/settings.json`)

PreToolUse hooks receive the payload on stdin; a non-zero exit blocks
the call and stderr is shown to the model.

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

### Cline (`~/.cline/hooks/PreToolUse.sh`)

Cline supports the same Claude-compatible PreToolUse hook (Cline
3.36+; enable Hooks in settings). Project-level:
`clinerules/hooks/PreToolUse.sh`.

```bash
#!/usr/bin/env bash
exec vitasentrion guard
```

Ensure the script is executable: `chmod +x ~/.cline/hooks/PreToolUse.sh`.
Cline serializes `tool_input` to a JSON string; the guard parses both
the object and string forms.

### GitHub Actions (`.github/workflows/safety.yml`)

```yaml
name: agent-safety
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install .
      - run: vitasentrion scan . --base origin/main --fail-on warn --format markdown
```

## Development

The package is standard library only by design; the test suite needs
nothing beyond it.

```bash
python -m unittest discover -s tests   # 405 tests
```

SPEC.md is the contract: exact detection patterns, the config schema,
the trace model, and the wiring rules. PLAN.md records milestone
decisions.

## License

MIT. Developed by VitaLogic Labs.
