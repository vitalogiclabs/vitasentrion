# VitaSentrion 🛡️
### The Zero-Dependency Circuit Breaker, Pre-Tool Guard & Session Linter for AI Coding Agents
*A VitaLogic Labs Open-Source Research Project — https://vitalogiclabs.com*

VitaSentrion is a lightweight, zero-dependency runtime guardrail, runaway loop breaker, and code quality linter designed for developers running autonomous AI coding agents (Claude Code, Cursor, Cline, Roo Code, Aider, OpenCode).

> **Threat Model & Philosophy:** VitaSentrion is an ultra-fast, zero-infra **seatbelt** for honest-but-clumsy agents. It catches runaway edit loops, accidental destructive commands (`git reset --hard`), credential leaks, and test-gutting. It is a cooperative pre-tool hook, not an adversarial kernel/eBPF sandbox.

---

### Why VitaSentrion?
Autonomous coding agents are powerful, but suffer from three everyday operational headaches:
1. **Runaway Loops & Token Drain:** Calling the same tool or editing the same file repeatedly in circles without running tests.
2. **Accidental Footguns & Secret Leaks:** Hallucinating destructive commands (`git reset --hard`, `rm -rf`), leaking API keys into bash arguments, or hitting cloud metadata endpoints (`169.254.169.254`).
3. **Repository Vandalism:** Silently deleting test assertions to force a "green" run, leaving scratch scripts (`debug_test.py`), and abandoning uncommitted diffs.

---

### Key Capabilities
- **Pre-Tool Hook Guard (`vitasentrion guard`)**: Intercepts tool calls via stdin (Claude Code & Cline `PreToolUse` compatible). Blocks destructive commands, metadata/SSH targets, secret leaks, and trips a stateful circuit-breaker after 3 consecutive identical edits (exit code 2).
- **Live Git & PR Scanner (`vitasentrion scan`)**: Scans any Git repo or PR diff (`--base origin/main`) for test weakening (deleted assertions), scratch files, uncommitted changes, and leaked API tokens.
- **Multi-Format Session Auditor (`vitasentrion audit`)**: Audits Claude Code JSONL, Cline JSON, and OpenAI/Hermes traces into ANSI, Markdown, or JSON scorecards.
- **Zero Dependencies:** Pure Python 3.10+ standard library. No background daemons, no external wheels.

---

### Quick Start
```bash
# In your virtual environment:
pip install .
vitasentrion --help

Three core commands:
Bash

# 1. Pre-tool hook guard (stdin payload, exit 2 = blocked)
echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | vitasentrion guard

# 2. Repository / PR scan (run in a git repo)
vitasentrion scan .                       # whole working tree
vitasentrion scan . --base origin/main    # PR diff only

# 3. Session audit (Claude Code JSONL, Cline JSON, OpenAI/Hermes traces)
vitasentrion audit session.jsonl --format markdown

Exit codes: 0 = clean, 1 = finding threshold tripped, 2 = tool call blocked by guard.
Integrating the Guard
Claude Code (~/.claude/settings.json)

Claude Code PreToolUse hooks receive payloads on stdin; exit 2 blocks execution and feeds stderr back to the model context:
JSON

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

Cline (~/.cline/hooks/PreToolUse.sh)

Cline (3.36+) supports hook scripts:
Bash

#!/usr/bin/env bash
exec vitasentrion guard

(Make it executable: chmod +x ~/.cline/hooks/PreToolUse.sh)
Rules Reference

    R1 LoopEntrapment: >=3 consecutive identical tool calls or >3 edits to same file without tests.

    R2 TestIntegrity: Code modified without tests, failing test runs, or deleted assertions.

    R3 ScratchPollution: Temporary debug files left outside .scratch/.

    R4 GitHygiene: Uncommitted changes or destructive git commands (reset --hard, clean -f).

    R5 SecretLeakage: Inline credentials (AWS, OpenAI, Anthropic, GitHub, Private Keys, .env).

    R6 NetworkScopeEscape: Explicit target strings for private subnets (RFC1918), metadata IPs (169.254.169.254), and SSH port 22.

License

MIT License. Developed by VitaLogic Labs.
