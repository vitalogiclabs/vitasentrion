# PLAN-native-user — guard configurability on branch `native-user`

Baseline (recorded October, 23, 2026): `pytest tests/ -q` on master @ 9588b68 ->
**405 passed, 50 subtests passed in 2.08s** (venv `.venv`, pytest 9.x, Python 3.14).

The repository's own PLAN.md is the product spec — not touched. This file is the
work plan for the six requested changes.

## Decisions

1. **workspace_root (a)** — new `[guard] workspace_root` (absolute path). Resolution
   chain, most specific first:
   - guard: explicit `workspace_root=` param > `[guard].workspace_root` > payload `cwd` > `os.getcwd()`
   - cli `guard`: `--workspace` > `[guard].workspace_root` > cwd
   - parsers: trace metadata > `parse_trace(..., config=cfg).workspace_root` > `os.getcwd()`
   - rules R6: `trace.workspace_root` > `config.workspace_root` > `os.getcwd()`
   `SessionTrace.workspace_root` default becomes `""` (unset marker); the layers above
   fill it. The hard-coded `/workspace` disappears from models.py and parsers.py.
   The Hermes plugin (`~/.hermes/plugins/vitasentrion-guard/__init__.py`) is NOT touched
   (operator-owned, locked); it goes through `evaluate_hook_payload`, so honouring
   `config.workspace_root` there covers the plugin's cwd fallback without a plugin edit.

2. **allow_hosts (b)** — `[guard] allow_hosts = ["host:port", ...]`, validated
   (host + numeric port, lowercased). Shared `find_network_hits(text, config)` in
   rules.py (single source of truth, used by guard `_check_network` and post-hoc R6).
   Suppression is per-occurrence and exact:
   - a blocked IPv4 hit is ignored only when immediately followed by `:<port>` and
     `ip:port` is an exact allow entry (port token must end at a non-word char);
   - a `:22` hit is ignored only when the host token directly before it forms an
     exact `host:22` allow entry;
   - `ssh`/`scp` command hits are never suppressed by allow_hosts.
   Consequences (tested): same host other port still blocked, host without port still
   blocked, other private IPs still blocked, `allowed; blocked` chain still blocked.

3. **allow_sudo (c)** — `[guard] allow_sudo = ["/abs/path", ...]` (validated absolute).
   Shared `find_sudo_hits(text, config)`: each `sudo <token>` occurrence is ignored only
   when `<token>` equals an allowed path exactly (quotes stripped). `sudo -u x /path`,
   other sudo commands and chains (`sudo <allowed>; sudo <other>`) still block.
   Post-hoc R6 (`"sudo " in blob`) switches to the same helper.

4. **R6 content exemption (d)** — for tools `Write, Edit, MultiEdit, NotebookEdit,
   write_file, patch, edit_file, apply_patch`, the content keys
   `content, new_string, old_string, new_str, old_str, edits, new_source, patch, diff, input`
   are excluded from R6 command/sudo/network/pipe-to-shell/sensitive-token text (guard
   `_evaluate_one` and post-hoc `rule_r6`). R5 secret scanning keeps scanning ALL
   argument content (guard scans the full canonical args blob; post-hoc R5 unchanged).
   Scope escapes keep running over path arguments unchanged.

5. **R7 taint source (e)** — `_is_tainted_call` uses the same content-exempt text, so
   writing file content that mentions `.env`/`id_rsa`/... does not taint. Path-based
   taint (read of a sensitive path) and command-text taint are unchanged.

6. **taint_seconds (f)** — `[guard] taint_seconds` (default 300). State entries become
   5-tuples `[tool, args_json, path, tainted, ts]`. An egress is R7-blocked only if a
   tainted entry carries a timestamp with `now - ts <= taint_seconds`; entries without a
   timestamp (legacy 3/4-tuples) count as expired. Tests use a fake clock swapped into
   `vitasentrion.guard.time`, never `sleep`.

## Files

- vitasentrion/config.py — 4 new [guard] keys + validation + defaults
- vitasentrion/models.py — workspace_root default ""
- vitasentrion/parsers.py — parse_trace(source, *, config=None), cwd fallback
- vitasentrion/cli.py — guard cmd resolution chain
- vitasentrion/guard.py — config-aware root, R6 content exemption, allow_hosts/allow_sudo
  wiring, taint ts + expiry
- vitasentrion/rules.py — find_sudo_hits, find_network_hits(config), content-exempt blob
  for post-hoc R6
- tests/test_config.py, test_guard.py, test_models_and_rules.py, test_parsers.py — new
  tests + two updated default assertions (models default "", parser default cwd)
- CHANGES-native-user.md

## Checklist (= todo ids)

- [x] base: baseline recorded
- [x] plan: this file
- [ ] cfg: config keys + validation tests
- [ ] ws: workspace_root chain (a)
- [ ] hosts: allow_hosts (b)
- [ ] sudo: allow_sudo (c)
- [ ] content: R6 content exemption (d)
- [ ] taint: R7 taint content (e)
- [ ] expiry: taint_seconds (f)
- [ ] docs: CHANGES-native-user.md, full suite, commits

## Constraint notes

- Existing tests are never weakened or deleted; the two assertions that encode the
  old hard-coded `/workspace` default are updated to the new specified behaviour and
  called out in CHANGES-native-user.md.
- `~/.hermes/plugins/**` is read-only reference here; never written.
