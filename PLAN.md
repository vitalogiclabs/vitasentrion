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
- [ ] a1: A1 rules.py R6 ipaddress + unified destructive patterns
- [ ] a2: A2 R1 same-file loop + fuzzy loop, R2 code-file-only
- [ ] a3: A3 _last_test_passed verdict fix
- [ ] a4: A4 guard R5 blocking + events JSONL + parse_trace round-trip
- [ ] a5: A5 scanner base_ref diff scanning
- [ ] a6: tests updated for all 5 amendments
- [ ] a7: unittest discover 100% pass + commit
