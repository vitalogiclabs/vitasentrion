# M4.5 — Core Correctness & Unification Amendments

Spec: SPEC.md section 3 (5 amendments). Standard library only.

## Amendments & decisions

### A1 — Shared detection logic (rules.py, guard.py)
- Single source of truth lives in `rules.py`; `guard.py` imports from it.
  - `BLOCKED_IP_NETS` (ipaddress: 10/8, 172.16/12, 192.168/16, 169.254/16)
  - `IPV4_RE` (strict 4-octet literal, digit-boundary guards)
  - `SSH_COMMAND_RE` (word-boundary ssh/scp), `SSH_PORT_RE` = `(?<!\d):22(?!\d)`
    (digit lookbehind added so "12:22:05" never matches)
  - `PIPE_TO_SHELL_RE`
  - `DESTRUCTIVE_GIT_OPS` = git reset --hard, git clean -f, git push --force,
    git push -f, git checkout --, rm -rf .git  (+ `ROOT_WIPE_RE` for `rm -rf /`)
  - `SECRET_PATTERNS` (already in rules.py; guard imports it for R5)
  - helper `find_destructive_ops(text)`, `find_network_hits(text)` in rules.py
- rules.py R6 rewritten on top of these (replaces old `NETWORK_TARGETS`
  substring list). `NETWORK_TARGETS` removed.
- guard.py keeps public aliases in `__all__` (DESTRUCTIVE_GIT_COMMANDS,
  BLOCKED_IP_NETS, ROOT_WIPE_RE, PIPE_TO_SHELL_RE) pointing at rules.py objects.
- scanner.py: no A1 change needed (its labeled SECRET_PATTERNS stay local;
  A5 only).

### A2 — R1 & R2 precision (rules.py)
- R1(b): per-file edit counter since last test command; trigger when the
  SAME file is edited > 3 times (4th edit). Edits without an extractable
  path are not counted. 4 distinct files without tests = allowed.
- R1 fuzzy: >= 3 consecutive calls, same tool + same primary file path
  (content/line args may differ). Primary path via shared
  `extract_primary_path(arguments)` (ordered PATH_ARG_KEYS, recursive).
- R2(a): triggers only if at least one modified/created file is a code file.
  Non-code = suffix .md/.txt/.rst or basename .gitignore / license /
  readme (case-insensitive).
- guard.py loop breaker: state entries are [tool_name, args_json, path]
  (3-tuples; the run length is derived from consecutive entries, never
  stored — test_guard.test_state_persisted_across_calls pins the shape).
  Run continues on exact (tool,args) OR same tool + same path (fuzzy).
  Stale state (> 1h idle, per state-file mtime) starts a fresh run;
  `vitasentrion guard --reset` clears the state file.

### A3 — parsers.py `_last_test_passed`
- fail if nonzero failure/error count `[1-9]\d*\s*(?:failed|failures?|errors?)`,
  or "traceback", or "exit code 1", or is_error.
- pass only on runner summaries: `\d+ passed`, `Ran N tests...OK`
  (case-insensitive, DOTALL), or word `\bpassed\b`.
- "5 passed, 0 failed" -> True.  "connection ok" -> None. Bare ok/success
  no longer pass.

### A4 — guard R5 + events JSONL; parsers native JSONL
- `evaluate_hook_payload` checks SECRET_PATTERNS on the call text; blocks
  with R5 finding (pattern reported, never the secret value).
- Every evaluated event (allowed AND blocked) appended as one JSONL line to
  `<state_file_stem>.events.jsonl` next to the state file. Line shape is a
  Claude-style top-level tool_use event ({"type": "tool_use", "tool_name",
  "arguments", "session_id", "workspace_root", "timestamp", "allowed",
  "reason"}) so `parse_trace` accepts the file natively with no special
  case (verified by a round-trip test).

### A5 — scanner.py base_ref
- `scan_git_repo(repo_path, base_ref=None)`, `audit_git_repo(repo_path,
  base_ref=None)`.
- With base_ref: run `git diff <base>...HEAD` (weakened assertions + secrets
  merged/deduped) and `git diff --name-status <base>...HEAD`
  (A->files_created, M/R/D/C->files_modified) so R3 sees committed scratch
  files. Invalid base_ref -> RuntimeError (fail loud in CI).

## Files
- vitasentrion/rules.py (A1, A2)
- vitasentrion/guard.py (A1, A2 fuzzy, A4)
- vitasentrion/parsers.py (A3; A4 no change needed — verified by test)
- vitasentrion/scanner.py (A5)
- tests/test_models_and_rules.py, test_guard.py, test_parsers.py,
  test_scanner.py, (test_cli.py if signatures affect it)

## Checklist
- [x] a1: A1 rules.py R6 ipaddress + unified destructive patterns
- [x] a2: A2 R1 same-file loop + fuzzy loop, R2 code-file-only
- [x] a3: A3 _last_test_passed verdict fix
- [x] a4: A4 guard R5 blocking + events JSONL + parse_trace round-trip
- [x] a5: A5 scanner base_ref diff scanning
- [x] a6: tests updated for all 5 amendments
- [x] a7: unittest discover 100% pass + commit
  (closed October, 20, 2026: all five amendments verified present in
  rules.py / guard.py / parsers.py / scanner.py; 328 tests green.)

# M6 — R7 Taint Relay (guard)

Source: research/vitasentrion-comparison/rapor-claude-codex-round2.md,
P0-b. Cheapest practical form of CaMeL (2503.18813) / MELON (2502.05174)
dataflow control; no competitor in the guard niche has it.

## Decision D1 — what taints
A call is TAINTED when its primary path argument names a sensitive file
(rules.py `is_sensitive_path`: .env, .ssh/*, *credentials*, *id_rsa*,
*id_ed25519*, *private key*, keychain, /etc/passwd|shadow|sudoers,
~/.aws/credentials) or its command text touches a sensitive-file token.
Note: command-text reads of .env are already R6-blocked; the real taint
source is path-argument reads (read_file path=".env"), which R6 does
not see today.

## Decision D2 — what is a sink
A call is an EGRESS when its tool name matches NETWORK_TOOL_RE
(web|fetch|http|browser|request|net) or its command text contains an
http(s):// URL or curl/wget. R6 already blocks private/link-local/ssh
targets; R7 catches the *public* egress that R6 lets through.
Out-of-root writes are already R6-blocked; no separate sink needed.

## Decision D3 — window and state shape
Reuse the loop-breaker state file (same TTL, same reset). Entry shape
grows from 3-tuple to 4-tuple: [tool, args_json, path, tainted 0|1].
Old 3-tuples load as tainted=0 (back-compat). Window = the last
_MAX_REMEMBERED (5) calls. reset_state deletes the file, so it clears
taint too (already true).

## Decision D4 — where R7 runs
In the stateful section of evaluate_hook_payload, after state load and
before the loop breaker. A blocked R7 call does NOT append to state, so
the taint stays in the window until it ages out. Finding: R7
TaintRelay, Severity.FAIL, reason "taint relay".

## Files
- vitasentrion/rules.py (is_sensitive_path, NETWORK_TOOL_RE, EGRESS_TEXT_RE)
- vitasentrion/guard.py (taint flag in state, R7 check)
- tests/test_guard.py (state shape 4-tuple, R7 positives/negatives)

## Checklist
- [x] m6.1: rules.py shared detectors
- [x] m6.2: guard.py R7 taint relay
- [x] m6.3: tests green (new R7 cases + updated state-shape test)
- [x] m6.4: full suite + commit (336 tests, October, 20, 2026)

# M7 — Hash-chained events JSONL (P1-a)

Each events line carries prev_hash + hash (SHA-256 over prev_hash +
canonical line content minus the two chain fields). verify_events_chain
(guard.py) returns an R8 EventsChainTampered finding on any modified or
deleted line; `vitasentrion audit <x>.jsonl` folds it into the
scorecard. Stdlib hashlib only, ~40 lines.

## Checklist
- [x] m7.1: chain fields written on append (prev_hash from last line)
- [x] m7.2: verify_events_chain + CLI audit wiring
- [x] m7.3: tests (clean chain, modified line, deleted line, legacy log)
- [x] m7.4: full suite + commit (341 tests, October, 20, 2026)

# M8 — Declarative configuration file (P0-a)

Source: research/vitasentrion-comparison round-2 report, P0-a. Adds a
`vitasentrion.toml` config file; no config file = today's hardcoded
defaults, byte-for-byte. All wiring is via OPTIONAL keyword arguments
(`config=None`) so every existing SPEC.md signature stays valid.

## Decision D1 — new module `vitasentrion/config.py`
- `VitaConfig` dataclass: max_consecutive_edits (3), state_ttl_seconds
  (3600), ignore_paths (()), rule_actions ({}), blocked_commands (()),
  secret_patterns (()), source path. `default_config()` = today's
  constants.
- `load_config(path=None, start_dir=None)`: explicit path missing ->
  ConfigError (fail loud); otherwise search `vitasentrion.toml` walking
  up from start_dir, stopping at the git root (.git) or fs root; not
  found -> defaults.
- TOML: `try: import tomllib` (3.11+) `except ImportError: import
  tomli`; neither -> defaults with a one-line stderr warning. Unknown
  sections/keys, bad rule ids/actions, invalid regexes -> ConfigError.
- `path_matches_ignore(path, patterns)`: fnmatch over the path and every
  trailing path segment, so `.scratch/*` matches `foo/.scratch/x.py`.
- `effective_rule_severity(config, rule_id, default)`: block -> default
  severity, warn -> WARN, ignore -> None (skip).

## Decision D2 — semantics of the keys
- `[guard].max_consecutive_edits` = the single R1 threshold: guard loop
  breaker trips at run >= N; rules R1(a) identical run >= N; R1(c)
  same-file edits > N. Default 3 = current behavior.
- `[guard].state_ttl_seconds` replaces STATE_TTL_SECONDS in the stale
  check. `[guard].ignore_paths`: a call whose primary path matches is
  allowed unchecked by the guard (event still logged); the scanner drops
  matching paths from modified/created/uncommitted sets.
- `[rules]` R1..R8 = block|warn|ignore. In evaluate_trace: ignore skips
  the rule, warn downgrades the finding. In the guard: ignore skips that
  check, warn keeps the finding but allows the call (only FAIL blocks).
- `[custom].blocked_commands` extend R4 (treated as destructive ops);
  `[custom].secret_patterns` extend R5 (rules + guard).

## Files
- vitasentrion/config.py (new)
- vitasentrion/rules.py (evaluate_trace/rule_rN optional config kwarg)
- vitasentrion/guard.py (evaluate_hook_payload config kwarg, TTL,
  threshold, ignore_paths, rule actions, custom patterns)
- vitasentrion/scanner.py (scan_git_repo/audit_git_repo config kwarg,
  ignore_paths filtering)
- vitasentrion/cli.py (--config for audit/scan/guard)
- tests/test_config.py (new)

## Checklist
- [x] m8.1: config.py + unit tests (valid toml, missing -> defaults,
      custom threshold applied, rule disabled)
- [x] m8.2: rules.py wiring
- [x] m8.3: guard.py wiring (note: "warn" findings are returned on the
      allowed path too; only FAIL blocks)
- [x] m8.4: scanner.py + cli.py wiring (R8 action honored in audit)
- [x] m8.5: docs (SPEC.md section 4, README.md) + full suite + commit
      (366 tests, October, 20, 2026)

# M9 — R9 RepoInjection: repo-borne injection scan (P1-b)

Source: research/vitasentrion-comparison/rapor-claude-codex-round2.md,
P1-b (grounding: RepoGuardBench, WebInject, InjecAgent). Nobody in the
guard niche scans the repo itself for prompt-injection payloads planted
in instruction files. Owner-confirmed decisions (October, 20, 2026).

## Decision D1 — rule identity and default action
- Rule ID R9 (RepoInjection). Scanner-only (the live guard never sees
  repo files); wired into audit_git_repo, so `vitasentrion scan` reports
  it. R9 added to config.RULE_IDS.
- Default action "warn" (finding Severity.WARN): docs/tests that
  *discuss* prompts must not hard-block. [rules] R9 = "block" escalates
  to FAIL; "ignore" skips. Note: unlike R1-R8, R9's default action is
  "warn", so the severity mapping is: default/warn -> WARN, block ->
  FAIL, ignore -> skip.

## Decision D2 — target files (instruction/prompt files)
is_instruction_file(path): basename matches AGENTS.md / CLAUDE.md /
GEMINI.md / .cursorrules / *.prompt / *prompt*.md|txt /
*instruction*.md|txt (case-insensitive), OR any .md/.markdown under
.github/. Walk all files under the repo root (skip .git/), drop
ignore_paths (M8) before reading.

## Decision D3 — detectors (three, per owner spec)
1. OVERRIDE_PATTERNS: "ignore (all )?previous instructions",
   "disregard ... system prompt", "forget (all )?(previous|prior)
   instructions", "override (all )?(previous|prior|system)",
   "new instructions:".
2. HIDDEN_UNICODE_RE: [\u200b\u200c\u200d\ufeff\u202e\u202c]
   (zero-width + BOM + bidi override/clear).
3. BASE64_BLOB_RE: [A-Za-z0-9+/]{48,}={0,2} token inside an
   instruction file (payload marker).
Findings report file + detector name + line number, never the full
line content (keeps reports short, avoids echoing the payload).

## Files
- vitasentrion/config.py (R9 in RULE_IDS)
- vitasentrion/scanner.py (is_instruction_file, detect_repo_injections,
  audit_git_repo folds R9 into the scorecard honoring [rules].R9)
- tests/test_repo_injection.py (new)

## Checklist
- [x] m9.1: scanner.py detectors + targeting
- [x] m9.2: audit_git_repo wiring + config R9 (implementation note:
      rule_action() gained a `default` parameter because R9's default
      action is "warn", unlike R1-R8)
- [x] m9.3: unit tests (detectors, targeting, ignore_paths, actions, CLI)
- [x] m9.4: docs (SPEC.md section 5, README.md) + full suite + commit
      (382 tests, October, 20, 2026)

