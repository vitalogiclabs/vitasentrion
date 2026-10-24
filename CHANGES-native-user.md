# CHANGES-native-user

Branch `native-user`, October, 23, 2026. Six changes to the guard rules,
each with unit tests (positive and negative cases). Baseline on `master`:
405 passed, 50 subtests. Final on this branch: 484 passed, 50 subtests.
No existing test was weakened or deleted. The only baseline assertions
edited were the two that pinned the old hard-coded `/workspace` default
(in `test_models_and_rules.py` and `test_parsers.py`); they now assert
the new unset/config behavior. Everything else passes unchanged.

## What changed and why

### a. `[guard].workspace_root` replaces hard-coded `/workspace`

The workspace root was hard-coded to `/workspace` in `models.py`
(`SessionTrace.workspace_root` default), `parsers.py` (`parse_trace`)
and the plugin hook (process cwd fallback). A user whose project lives
somewhere else got scope checks against the wrong directory.

- `vitasentrion.toml` gains `[guard].workspace_root` (absolute path).
- `SessionTrace.workspace_root` now defaults to `""` (unset marker).
- Resolution chain everywhere (`parsers.parse_trace`, `guard`, rule
  engine R6, `cli guard`): explicit argument / trace metadata >
  `[guard].workspace_root` config > payload `cwd` > process cwd.
  No `/workspace` default remains anywhere in the package (one config
  docstring uses it as an illustrative example).

### b. `[guard].allow_hosts` — exact host:port exemptions for R6

R6 blocked every private-IP target. Local tooling (dev servers on
127.0.0.1:PORT) was impossible to allow without disabling the check.

- `rules.find_network_hits(text, config)` (shared by the live guard and
  the post-hoc R6 scan) drops only hits whose **exact** `host:port`
  pair is in `allow_hosts`.
- Still blocked: the same host on another port, the host with no port,
  other private IPs, and a chain that mixes an allowed target with a
  blocked one (`curl a; curl b` — b still trips R6).

### c. `[guard].allow_sudo` — exact path exemptions for R6 sudo

Blanket `sudo` blocking made sanctioned helper binaries unusable.

- `rules.find_sudo_hits(text, config)` suppresses exactly
  `sudo <listed-abs-path>`; any other sudo form (bare `sudo`, other
  paths, relative paths, options) still hits R6.
- Chaining does not launder it: `sudo /usr/bin/mytool && sudo apt-get
  install x` is still blocked. Allowed sudo also does not excuse R4
  destructive operations.

### d. R6 command checks scan commands and paths, not file bodies

`Write`/`Edit`/`MultiEdit`/`NotebookEdit` payloads carry large file
bodies; scanning them as commands meant documentation that *mentions*
`sudo`, `curl ... | sh`, `.env` or `id_rsa` was blocked as an escape.

- The guard builds the R6 scan text from command/argument material
  with file-body keys (`content`, `new_string`, `old_string`,
  `new_source`, ...) excluded for write/edit tools; path arguments are
  still scanned.
- The post-hoc rule engine mirrors this via `rules._command_blob()`.
- Unchanged on purpose: **R5 secret scanning still scans file
  content** (a written AWS key is still blocked), and **writes outside
  `workspace_root` are still blocked**.

### e. R7 taint: content mentions do not taint

Previously any call whose text mentioned a sensitive token (including
file content being written) tainted the session.

- `_is_tainted_call` excludes file-body arguments for write/edit
  tools; a sensitive path argument or a sensitive token in a command
  still taints. Writing docs that mention `.env` no longer blocks
  later egress; `read_file path=".env"` still does.

### f. R7 taint expiry: `[guard].taint_seconds`

Taint previously persisted until it aged out of the 5-call window or
the state file's hour TTL — egress could stay blocked for a long time
after the sensitive read.

- Tainted state entries gained a 5th element: the epoch-seconds
  timestamp (`guard._now_ts()`, an injectable clock — tests use a fake
  clock, never sleep).
- An egress call is blocked only if a tainted entry is at most
  `taint_seconds` old (default 300; `now - ts <= limit`).
- Legacy entries without a timestamp (3- and 4-tuples) count as
  **expired**: an old untimestamped taint never blocks.

### g. `python -m vitasentrion` — `__main__.py` ported back

The native-user port dropped the module entry point that the old plugin
build shipped, so `python -m vitasentrion` failed with
`No module named vitasentrion.__main__`.

- `vitasentrion/__main__.py` is a verbatim port from the removed plugin
  backup (`~/.hermes/plugin-yedekleri/vitasentrion-guard-kaldirildi-20261023-2135/`):
  `sys.exit(main())` from `cli.main`.

### h. `[guard].state_dir` + `VITASENTRION_STATE_DIR` fallback ported back

The plugin build let the guard's state + events files live outside the
system temp dir; the native port lost the whole feature (the key was an
"unknown [guard] key" error).

- `config.py`: `VitaConfig.state_dir` (`None` -> tempdir default),
  `[guard].state_dir` key (validated: non-empty string, stripped), and
  the `VITASENTRION_STATE_DIR` env fallback — the env value applies when
  the config file does not set the key; when both are set, the config
  value wins. `default_config()` (no config file) picks up the env var.
- `guard.py`: `resolve_state_dir()` (absolute used as given, relative
  against the workspace root, `~` expanded);
  `_default_state_file(root, state_dir)`; the state dir is a HARD block
  in `_scope_escape_paths` — any write into it is R6-blocked even when
  it sits inside the workspace or the scratch dir, checked before the
  scratch exceptions, and a configured state_dir never widens the
  scratch exception; `evaluate_hook_payload` resolves the chain
  config > env > tempdir and creates the directory so events are not
  dropped.
- `cli.py`: `guard --reset` honors `cfg.state_dir`.

## New `[guard]` keys

```toml
[guard]
workspace_root = "/home/ismail/projects/app"  # scope root; default: payload cwd, else process cwd
allow_hosts    = ["127.0.0.1:8080", "localhost:5432"]  # exact host:port pairs R6 ignores
allow_sudo     = ["/usr/bin/mytool"]          # exact absolute paths allowed as `sudo <path>`
taint_seconds  = 300                          # R7 taint lifetime in seconds (default 300)
state_dir      = ".vitasentrion"              # guard state/events location (default: system temp dir;
                                              # relative paths resolve against the workspace root;
                                              # VITASENTRION_STATE_DIR is the env fallback, config wins)
```

All five keys are validated at load: `workspace_root` must be an
absolute path, `allow_hosts` entries must be `host:port`, `allow_sudo`
entries absolute paths, `taint_seconds` a non-negative integer,
`state_dir` a non-empty string.
Unknown `[guard]` keys are rejected as before.

## Tests

New test classes: `TestConfigWorkspaceRoot`, `TestAllowHosts`,
`TestAllowSudo`, `TestWriteContentVsCommands`,
`TestTaintContentAndExpiry` (guard) plus rule-engine counterparts in
`test_models_and_rules.py` and parser/config coverage in
`test_parsers.py` / `test_config.py`. Ported features add
`StateDirConfigTests` (config), `StateDirGuardTests` (guard) and
`tests/test_main.py` (`python -m vitasentrion` via subprocess: help,
version, allow -> 0, block -> 2).

Run: `python -m pytest tests/ -q` -> 484 passed, 50 subtests passed.

## Commits on `native-user`

- (a) workspace_root setting replaces hardcoded /workspace defaults
- (b) allow_hosts setting — exact host:port exemptions
- (d) R6 command checks skip written file bodies; R5 and scope unchanged
  (this commit also carries the (c) allow_sudo implementation)
- (e,f) R7 taint content fix + taint_seconds expiry
- (g,h) port __main__.py + [guard].state_dir / VITASENTRION_STATE_DIR
  from the removed plugin build, with tests

Not pushed (no push access from this workspace); left here for review.
