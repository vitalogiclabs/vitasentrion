"""Pre-execution guard for VitaSentrion (SPEC milestone M4).

``evaluate_hook_payload`` sits in front of a tool call (a hook) and
decides whether the call may run, mirroring the post-hoc rules on the
subset a guard can see from a single invocation:

- ``R4`` GitHygiene — destructive git / shell commands are blocked.
- ``R6`` NetworkAndScopeEscape — traffic to private / link-local
  networks, ``ssh`` / ``scp`` and port ``:22``, ``sudo``, pipes into a
  shell, reads of sensitive files (``.env``, ``.ssh/id_rsa``,
  ``/etc/passwd``, ``/etc/shadow``), and writes outside the workspace
  root are blocked.  ``/tmp`` (and the platform temp dir) are allowed
  scratch space.
- ``R1`` LoopEntrapment — a stateful breaker stops a run of identical
  (tool, arguments) pairs before it burns tokens.  M4.5 amendment 2
  adds a *fuzzy* breaker: a run of the same tool targeting the same
  file path (content / line arguments may differ) also trips.
- ``R5`` SecretLeakage (M4.5 amendment 4) — a call whose command /
  content material matches a secret pattern is blocked before it runs.
- ``R7`` TaintRelay (M6) — a sensitive-file read inside the remembered
  window taints the session; any network egress (web/fetch/http tool,
  http(s) URL, curl/wget) inside that window is blocked, so freshly-read
  credentials cannot leave the machine.

The hook is format-agnostic: it understands Claude Code ``PreToolUse``
payloads (``tool_name`` / ``tool_input``), Cline-style payloads (where
``tool_input`` is a JSON *string*), and a generic ``{'name': ...,
'arguments': {...}}`` shape.  ``workspace_root`` defaults to the
process cwd and the hook state file to a key derived from the workspace
root (never written inside the user's repository).

M4.5 amendment 1: all destructive / network detection lives in
:mod:`vitasentrion.rules` and is imported here — the guard and the
post-hoc rule engine share one source of truth and cannot drift apart.

Ground truth (M4.5 amendment 4): every evaluated event is appended as
one JSONL line to ``<state_file_stem>.events.jsonl`` next to the state
file, in the Claude top-level ``tool_use`` shape, so
:func:`vitasentrion.parsers.parse_trace` accepts the log natively.

Python 3.10+ standard library only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from .models import Finding, Severity
from .config import (
    DEFAULT_STATE_TTL_SECONDS,
    VitaConfig,
    path_matches_ignore,
    redaction_enabled,
    rule_action,
)
from .rules import (
    BLOCKED_IP_NETS,
    DESTRUCTIVE_GIT_OPS,
    EGRESS_TEXT_RE,
    ENV_FILE_RE,
    NETWORK_TOOL_TOKENS,
    PIPE_TO_SHELL_RE,
    REDACTED_TEMPLATE,
    ROOT_WIPE_RE,
    SECRET_PATTERNS,
    SENSITIVE_PATH_TOKENS,
    SSH_ID_RSA_MARKER,
    extract_primary_path,
    extra_secret_patterns,
    find_destructive_ops,
    find_network_hits,
    is_sensitive_path,
    redact_args,
    redact_text,
)

__all__ = [
    "LOOP_BREAKER_MESSAGE",
    "DESTRUCTIVE_GIT_OPS",
    "DESTRUCTIVE_GIT_COMMANDS",
    "ROOT_WIPE_RE",
    "BLOCKED_IP_NETS",
    "PIPE_TO_SHELL_RE",
    "evaluate_hook_payload",
    "reset_state",
    "STATE_TTL_SECONDS",
    "_extract_call",
    "_default_state_file",
    "_canonical_args_json",
    "_iter_path_values",
    "_is_tainted_call",
    "_is_egress_call",
    "verify_events_chain",
]

# Backwards-compatible alias (M4 named it DESTRUCTIVE_GIT_COMMANDS; M4.5
# unified the source of truth in rules.py under DESTRUCTIVE_GIT_OPS).
DESTRUCTIVE_GIT_COMMANDS = DESTRUCTIVE_GIT_OPS

LOOP_BREAKER_MESSAGE = "Loop Breaker: 3 consecutive identical tool calls"

# sudo as a command (word-boundary protected so "sudo.rs" never matches).
SUDO_RE = re.compile(r"(?:^|[\s;&|])sudo\b")

SENSITIVE_FILE_TOKENS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "~/.aws/credentials",
    "~/.ssh/id_ed25519",
    "login.keychain",
)

# Argument keys that carry command / content material — the text the R4 /
# R5 / R6 checks run over.  (Path and string-diff keys are checked
# separately for scope escapes, not as command text.)
_SCAN_ARG_KEYS = frozenset(
    (
        "command", "cmd", "code", "script", "shell_command", "bash_command",
        "input", "patch", "text", "data", "content", "output",
    )
)

# State entry shape: [tool_name, canonical_args_json, primary_path,
# tainted 0|1]. The run length is derived from consecutive entries, never
# stored, so the persisted state stays a plain JSON *list* of 4-tuples
# (M6 grew the shape from 3 to 4; 3-tuples load as untainted).
_MAX_REMEMBERED = 5

# Loop-breaker state older than this (by the state file's mtime, which
# doubles as the last-activity timestamp) is treated as a fresh session,
# so an idle workspace cannot be blocked by a stale run of calls.
STATE_TTL_SECONDS = 3600

# The events JSONL is ground truth, not a cache: rotate once it outgrows
# this so an always-on hook cannot fill the disk (oldest kept as .1).
_EVENTS_MAX_BYTES = 5 * 1024 * 1024


def _default_state_file(workspace_root: str) -> Path:
    """Deterministic state file in the system temp dir, keyed by workspace.

    The file lives in ``tempfile.gettempdir()`` (never inside the user's
    repository) and is derived from a sha256 of the resolved workspace
    root, so the same workspace maps to the same file on any machine.
    """
    digest = hashlib.sha256(os.path.realpath(workspace_root).encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"vitasentrion-guard-{digest}.json"


def _events_file(state_file: Path) -> Path:
    """Ground-truth events log next to the state file (M4.5 A4).

    ``state.json`` -> ``state.events.jsonl`` in the same directory.
    """
    return state_file.with_name(f"{state_file.stem}.events.jsonl")


def _extract_call(payload: dict) -> tuple[str, dict]:
    """Normalise the supported payload shapes to (tool_name, args).

    Claude Code ``PreToolUse`` carries ``tool_name`` + ``tool_input``
    (a dict, or a JSON string under Cline); some emitters use
    ``arguments`` instead of ``tool_input``.  The generic shape is
    ``{'name': ..., 'arguments': {...}}``.
    """
    if not isinstance(payload, dict):
        return "unknown", {}

    if "tool_name" in payload:
        raw = payload.get("tool_input", payload.get("arguments"))
        args: Any = raw
        if isinstance(raw, str):
            try:
                args = json.loads(raw)
            except (ValueError, TypeError):
                args = {"input": raw}
        if not isinstance(args, dict):
            args = {}
        return str(payload["tool_name"]), args

    if "name" in payload:
        args = payload.get("arguments") or {}
        if not isinstance(args, dict):
            args = {}
        return str(payload["name"]), args

    return "unknown", {}


def _canonical_args_json(args: dict) -> str:
    """Stable serialisation so argument order never breaks identity."""
    return json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)


def _iter_path_values(obj: Any) -> list[str]:
    """Collect string values from path-bearing keys (flat and nested)."""
    out: list[str] = []
    path_keys = (
        "path", "file_path", "filepath", "file", "filename",
        "target", "dest", "destination", "to", "output_path",
    )

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and isinstance(value, str):
                    if key.lower() in path_keys:
                        out.append(value)
                else:
                    _walk(value)
        elif isinstance(node, (list, tuple)):
            for item in node:
                _walk(item)

    _walk(obj)
    return out


def _primary_path(args: dict) -> str:
    """First path-like argument of a call (empty string when none).

    Delegates to :func:`rules.extract_primary_path` (M4.5 A2), so the
    same file is detected even when content / line arguments differ.
    """
    return extract_primary_path(args) or ""


def _call_text(args: dict) -> str:
    """The command / content material of a call (R4 / R5 / R6 target)."""
    parts = [
        value
        for key, value in args.items()
        if isinstance(value, str) and key.lower() in _SCAN_ARG_KEYS
    ]
    return "\n".join(parts)


def _is_tainted_call(name: str, args: dict, path: str) -> bool:
    """M6 (R7): does this call read sensitive material?

    Taint sources: a primary path argument naming a sensitive file
    (``read_file path=".env"`` — R6 does not block these reads), or any
    path argument / command text touching a sensitive-file token.
    """
    if is_sensitive_path(path):
        return True
    for value in _iter_path_values(args):
        if is_sensitive_path(value):
            return True
    text = _call_text(args).lower()
    return any(token in text for token in SENSITIVE_PATH_TOKENS)


def _is_egress_call(name: str, args: dict) -> bool:
    """M6 (R7): does this call send data over the network?

    Sink by tool name (web / fetch / http / browser / request) or by
    command text (http(s) URL, curl / wget). Private / link-local /
    ssh targets are already blocked by R6; R7 catches the public egress
    R6 lets through.
    """
    low_name = name.lower()
    if any(token in low_name for token in NETWORK_TOOL_TOKENS):
        return True
    return bool(EGRESS_TEXT_RE.search(_call_text(args)))


def _check_destructive(text: str) -> list[str]:
    """Destructive git/shell ops present in *text* (shared, M4.5 A1)."""
    return find_destructive_ops(text)


def _check_network(text: str) -> list[tuple[str, str]]:
    """Network / scope-escape hits in *text* (shared, M4.5 A1).

    Returns ``(label, description)`` pairs: blocked IPv4 networks
    (checked with the :mod:`ipaddress` module), ``:22`` and
    ``ssh``/``scp``.  Timestamps (``12:22:05``), versions (``v10.0.5``)
    and identifiers (``ssh_key``) never match.
    """
    return find_network_hits(text)


def _workspace_root_for(
    payload: dict,
    workspace_root: Optional[str],
    config: Optional[VitaConfig] = None,
) -> str:
    """Resolve the root scope checks run against.

    Chain: explicit argument > ``[guard].workspace_root`` config setting >
    payload ``cwd`` > process cwd.  (There is no hardcoded default.)
    """
    if workspace_root:
        return str(workspace_root)
    if config is not None and config.workspace_root:
        return config.workspace_root
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd:
        return cwd
    return os.getcwd()


def _scope_escape_paths(args: dict, root: str) -> list[str]:
    """Path arguments that land outside the workspace root (R6)."""
    root_norm = os.path.normpath(root)
    temp_root = os.path.normpath(tempfile.gettempdir())
    escapes: list[str] = []

    for path in _iter_path_values(args):
        if not path.startswith("/"):
            # Relative path: block only when '..' climbs out of the root.
            resolved = os.path.normpath(os.path.join(root_norm, path))
            if os.path.commonpath([root_norm, resolved]) != root_norm:
                escapes.append(
                    f"relative path {path!r} resolves outside workspace"
                )
            continue
        # Absolute path: allowed inside the root or in scratch space.
        if path == root or path.startswith(root_norm.rstrip("/") + "/"):
            continue
        if path.startswith(temp_root + "/") or path == temp_root:
            continue
        if path == "/tmp" or path.startswith("/tmp/"):
            continue
        escapes.append(f"target {path!r} outside workspace")

    return escapes


def _apply_rule_action(
    config: Optional[VitaConfig], rule_id: str, finding: Finding
) -> Optional[Finding]:
    """Honor a [rules] action for a guard finding (M8).

    ``ignore`` drops the finding; ``warn`` downgrades it to WARN, which
    lets the call through (only FAIL findings block the guard).
    """
    action = rule_action(config, rule_id)
    if action == "ignore":
        return None
    if action == "warn" and finding.severity is not Severity.WARN:
        return Finding(
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            severity=Severity.WARN,
            message=finding.message,
            details=finding.details,
        )
    return finding


def _evaluate_one(
    name: str, args: dict, root: str, config: Optional[VitaConfig] = None
) -> tuple[bool, str, list[Finding]]:
    """Run the R4 / R5 / R6 checks for one normalised call.

    All checks run and their findings are combined, so a single call can
    report both (e.g. ``sudo rm -rf /`` -> R4 *and* R6).  *config* (M8)
    optionally extends the command/secret patterns and applies per-rule
    actions (block / warn / ignore).
    """
    text = _call_text(args)
    text_low = text.lower()

    findings: list[Finding] = []
    reasons: list[str] = []

    # --- R4: destructive commands (shared detection, M4.5 A1) -------------
    ops = _check_destructive(text_low)
    # [custom].blocked_commands regexes extend R4 (M8).
    for pattern in config.blocked_commands if config else ():
        if re.search(pattern, text, re.IGNORECASE):
            ops.append(pattern)
    if ops:
        finding = _apply_rule_action(
            config, "R4",
            Finding(
                rule_id="R4",
                rule_name="GitHygiene",
                severity=Severity.FAIL,
                message="Destructive git/shell command blocked",
                details=[
                    f"tool '{name}' contains destructive op '{op}'"
                    for op in ops
                ],
            ),
        )
        if finding is not None:
            findings.append(finding)
            reasons.append("destructive command")

    # --- R5: secret leakage (M4.5 A4) -------------------------------------
    # A secret being *written or echoed* by this call is blocked before it
    # runs: the full canonical argument blob is scanned so secrets in any
    # argument (command, new_string, content, ...) are caught.  Only the
    # pattern is reported, never the secret material itself.
    # M10 (P2-a): with redaction mode on, the call is allowed and the
    # finding is WARN with typed placeholders; the events log stores the
    # redacted arguments (see _append_event).
    args_blob = _canonical_args_json(args)
    if redaction_enabled(config):
        _, secret_types = redact_text(args_blob, config)
        if secret_types:
            finding = Finding(
                rule_id="R5",
                rule_name="SecretLeakage",
                severity=Severity.WARN,
                message="Secret redacted in tool arguments",
                details=[
                    f"tool '{name}' argument redacted as "
                    f"{REDACTED_TEMPLATE.format(token=t)}"
                    for t in secret_types
                ],
            )
            findings.append(finding)
    else:
        secret_hits = [
            p.pattern
            for p in SECRET_PATTERNS + extra_secret_patterns(config)
            if p.search(args_blob)
        ]
        if secret_hits:
            finding = _apply_rule_action(
                config, "R5",
                Finding(
                    rule_id="R5",
                    rule_name="SecretLeakage",
                    severity=Severity.FAIL,
                    message="Secret leakage blocked in tool arguments",
                    details=[
                        f"tool '{name}' argument matches secret pattern {pat!r}"
                        for pat in secret_hits
                    ],
                ),
            )
            if finding is not None:
                findings.append(finding)
                reasons.append("secret leakage in arguments")

    # --- R6: network / scope escapes --------------------------------------
    r6_details: list[str] = []

    if SUDO_RE.search(text_low):
        r6_details.append(f"tool '{name}' invokes sudo (privilege escalation)")

    if PIPE_TO_SHELL_RE.search(text):
        r6_details.append(
            f"tool '{name}' pipes a downloaded script into a shell"
        )

    for _label, desc in _check_network(text_low):
        r6_details.append(f"tool '{name}' {desc}")

    for token in SENSITIVE_FILE_TOKENS:
        if token in text_low:
            r6_details.append(f"tool '{name}' touches sensitive file {token!r}")
    if ENV_FILE_RE.search(text):
        r6_details.append(f"tool '{name}' touches a .env file")
    if SSH_ID_RSA_MARKER in text_low:
        r6_details.append(f"tool '{name}' touches {SSH_ID_RSA_MARKER!r}")

    r6_details.extend(
        f"tool '{name}' writes {what}" for what in _scope_escape_paths(args, root)
    )

    if r6_details:
        finding = _apply_rule_action(
            config, "R6",
            Finding(
                rule_id="R6",
                rule_name="NetworkAndScopeEscape",
                severity=Severity.FAIL,
                message="Network / scope escape blocked",
                details=r6_details,
            ),
        )
        if finding is not None:
            findings.append(finding)
            reasons.append("network/scope escape")

    # M8: a [rules] action of "warn" keeps the finding but downgrades it
    # to WARN; only FAIL findings block the call.
    if any(f.severity is Severity.FAIL for f in findings):
        return False, "; ".join(reasons), findings

    return True, "Allowed", findings


def _load_state(state_file: Path) -> list:
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def reset_state(state_file: Path) -> bool:
    """Delete the loop-breaker state file.

    Returns ``True`` if a state file was removed, ``False`` if there was
    none.  The events JSONL is deliberately kept: it is ground-truth
    audit material, not breaker state.
    """
    try:
        state_file.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def _save_state(state_file: Path, entries: list) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(
        json.dumps(entries[-_MAX_REMEMBERED:], indent=2),
        encoding="utf-8",
    )


def _entry_matches(entry: list, name: str, args_json: str, path: str) -> bool:
    """Does a state entry continue this call's run?

    Exact: same tool + same canonical arguments.  Fuzzy (M4.5 A2): same
    tool + same primary path — only when the path is non-empty, so a
    pathless call falls back to the exact comparison.
    """
    e_tool = entry[0] if len(entry) > 0 else None
    e_args = entry[1] if len(entry) > 1 else None
    e_path = entry[2] if len(entry) > 2 else ""
    if e_tool != name:
        return False
    if e_args == args_json:
        return True
    return bool(path) and bool(e_path) and e_path == path


def _run_length(entries: list, name: str, args_json: str, path: str) -> int:
    """Length of the consecutive run ending at *entries*[-1] + this call."""
    length = 0
    for entry in reversed(entries):
        if not isinstance(entry, list) or not _entry_matches(
            entry, name, args_json, path
        ):
            break
        length += 1
    return length


def _chain_hash(prev_hash: str, body: dict) -> str:
    """M7 (P1-a): SHA-256 over prev_hash + canonical line content.

    The hash covers everything except the ``prev_hash`` / ``hash``
    fields themselves, so a verifier can recompute it from the line.
    """
    content = json.dumps(
        {k: v for k, v in body.items() if k not in ("prev_hash", "hash")},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256((prev_hash + content).encode("utf-8")).hexdigest()


def _last_chain_hash(events: Path) -> str:
    """Hash of the last line of the events log ('0'*64 if none)."""
    try:
        with events.open("rb") as fh:
            fh.seek(0, 2)
            pos, chunk = fh.tell(), b""
            while pos > 0 and b"\n" not in chunk:
                step = min(65536, pos)
                pos -= step
                fh.seek(pos)
                chunk = fh.read(step) + chunk
            last = chunk.rstrip(b"\n").split(b"\n")[-1] if chunk.strip() else b""
        if last:
            return str(json.loads(last).get("hash") or "") or "0" * 64
    except (OSError, ValueError):
        pass
    return "0" * 64


def verify_events_chain(events_file: Path) -> list[Finding]:
    """M7 (P1-a): verify the hash chain of an events JSONL log.

    Returns [] for a clean chain, else one R8 EventsChainTampered
    finding listing every broken link (missing/invalid chain fields,
    content modified, or a line deleted — each line's prev_hash must
    equal the previous line's hash).
    """
    problems: list[str] = []
    prev = "0" * 64
    try:
        lines = events_file.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [
            Finding(
                rule_id="R8",
                rule_name="EventsChainTampered",
                severity=Severity.FAIL,
                message=f"Events log unreadable: {exc}",
            )
        ]
    for i, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            problems.append(f"line {i}: not valid JSON")
            continue
        claimed, got_prev = obj.get("hash"), obj.get("prev_hash")
        if got_prev != prev:
            problems.append(
                f"line {i}: prev_hash mismatch (line deleted or reordered)"
            )
        recomputed = _chain_hash(str(got_prev or ""), obj)
        if claimed != recomputed:
            problems.append(f"line {i}: content modified (hash mismatch)")
        prev = str(claimed) if isinstance(claimed, str) and claimed else "0" * 64
    if not problems:
        return []
    return [
        Finding(
            rule_id="R8",
            rule_name="EventsChainTampered",
            severity=Severity.FAIL,
            message=f"Events log hash chain broken ({len(problems)} problem(s))",
            details=problems[:20],
        )
    ]


def _append_event(
    state_file: Path,
    *,
    name: str,
    args: dict,
    root: str,
    allowed: bool,
    reason: str,
    config: Optional[VitaConfig] = None,
) -> None:
    """Append one evaluated event as a Claude ``tool_use`` JSONL line (A4).

    The line shape is exactly what
    :func:`vitasentrion.parsers.parse_trace` already understands for
    top-level ``tool_use`` lines, so the log is a first-class,
    natively-parsable trace source.  Recording is best-effort: a write
    error never blocks the hook.

    M10 (P2-a): when redaction mode is on, the recorded *arguments* are
    the redacted form — credentials never sit plaintext in the audit log.
    """
    if redaction_enabled(config):
        redacted = redact_args(args, config)
        args = redacted if isinstance(redacted, dict) else {}
    line = {
        "type": "tool_use",
        "tool_name": name,
        "arguments": args,
        "session_id": hashlib.sha256(
            os.path.realpath(root).encode("utf-8")
        ).hexdigest()[:12],
        "workspace_root": root,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "allowed": allowed,
        "reason": reason,
    }
    events = _events_file(state_file)
    try:
        # Best-effort rotation so an always-on hook cannot fill the disk:
        # once the log outgrows _EVENTS_MAX_BYTES, the oldest copy is kept
        # as "<log>.1" and a fresh log starts.  The audit tail is still
        # parseable; only the very oldest events are dropped.
        try:
            size = events.stat().st_size
        except OSError:
            size = 0  # first event: nothing to rotate
        if size > _EVENTS_MAX_BYTES:
            try:
                events.replace(events.with_name(events.name + ".1"))
            except OSError:
                events.unlink(missing_ok=True)
        with events.open("a", encoding="utf-8") as fh:
            line["prev_hash"] = _last_chain_hash(events)
            line["hash"] = _chain_hash(line["prev_hash"], line)
            fh.write(json.dumps(line, default=str) + "\n")
    except OSError:
        pass


def evaluate_hook_payload(
    payload: dict,
    *,
    workspace_root: Optional[str] = None,
    state_file: Optional[Path] = None,
    config: Optional[VitaConfig] = None,
) -> tuple[bool, str, list[Finding]]:
    """Evaluate one tool-call payload against the guard rules.

    Parameters
    ----------
    payload:
        A Claude Code ``PreToolUse`` object, a Cline object (``tool_input``
        as a JSON string), or a generic ``{'name': ..., 'arguments': {...}}``
        mapping.  An optional ``cwd`` key is honoured as the workspace root
        when *workspace_root* is not given.
    workspace_root:
        The repository / sandbox root the call must stay inside.  When not
        given, the ``[guard].workspace_root`` config setting is used, then
        the payload ``cwd``, then :func:`os.getcwd` (no hardcoded default).
    state_file:
        Where the stateful loop-breaker run is persisted.  Defaults to a
        sha256-keyed file in the system temp dir (never inside the repo).
    config:
        Optional :class:`~vitasentrion.config.VitaConfig` (M8): overrides
        the loop threshold, state TTL, ignore paths, per-rule actions and
        custom command/secret patterns.  ``None`` keeps the hardcoded
        default behaviour.

    Returns
    -------
    ``(allowed, reason, findings)`` — ``allowed`` is ``False`` when any R4 /
    R5 / R6 check fires or the stateful R1 loop breaker trips.  Every
    evaluated event (allowed and blocked) is appended to the events JSONL
    log next to *state_file* (M4.5 A4).
    """
    if not isinstance(payload, dict):
        return True, "Allowed (empty payload)", []

    name, args = _extract_call(payload)
    root = _workspace_root_for(payload, workspace_root, config)
    sf = Path(state_file) if state_file else _default_state_file(root)

    # --- [guard].ignore_paths: skip checks, still log the event (M8) -----
    if config is not None and config.ignore_paths:
        ignored_path = _primary_path(args)
        if ignored_path and path_matches_ignore(
            ignored_path, config.ignore_paths
        ):
            _append_event(
                sf, name=name, args=args, root=root,
                allowed=True, reason="Allowed (ignored path)",
                config=config,
            )
            return True, "Allowed (ignored path)", []

    # --- R4 / R5 / R6 checks ----------------------------------------------
    allowed, reason, findings = _evaluate_one(name, args, root, config)

    # Record the evaluated event as ground-truth JSONL (M4.5 A4).
    _append_event(
        sf,
        name=name,
        args=args,
        root=root,
        allowed=allowed,
        reason=reason,
        config=config,
    )

    # Destructive / network / secret blocks return before the loop
    # breaker: they must not count toward (or reset) a run.
    if not allowed:
        return allowed, reason, findings

    # --- R1: stateful loop breaker (exact + fuzzy same-file, M4.5 A2) ------
    # Stale check BEFORE any save: the state file's mtime is the last
    # activity time, so an idle workspace (> STATE_TTL_SECONDS) gets a
    # fresh breaker run instead of inheriting a stale one.
    sf_mtime = None
    try:
        sf_mtime = sf.stat().st_mtime
    except OSError:
        pass
    ttl = config.state_ttl_seconds if config else STATE_TTL_SECONDS
    stale = sf_mtime is not None and (time.time() - sf_mtime) > ttl
    entries = [] if stale else _load_state(sf)
    if not stale:
        # Keep an *active* run alive for the full TTL regardless of how the
        # call resolves: the blocked path below does not write the state
        # file, so without this touch a relentless loop would age out after
        # the last allowed call and the breaker would drop.  A genuinely
        # idle state is NOT touched (stale), so it still ages out and the
        # next call starts a fresh run.
        try:
            os.utime(sf, None)
        except OSError:
            pass
    args_json = _canonical_args_json(args)
    # M10: with redaction mode on, the persisted loop-breaker state also
    # carries only redacted arguments.
    if redaction_enabled(config):
        redacted = redact_args(args, config)
        if isinstance(redacted, dict):
            args_json = _canonical_args_json(redacted)
    path = _primary_path(args)

    # --- R7: taint relay (M6) ----------------------------------------------
    # A sensitive read inside the remembered window taints the session:
    # any network egress inside that window is blocked, so freshly-read
    # secrets/credentials cannot leave the machine (CaMeL-style control,
    # PLAN.md M6). A blocked egress does NOT append to state, so the
    # taint stays until it ages out of the window or reset_state clears
    # the file.
    if _is_egress_call(name, args):
        tainted_at = next(
            (
                i
                for i, entry in enumerate(entries)
                if isinstance(entry, list) and len(entry) > 3 and entry[3]
            ),
            None,
        )
        if tainted_at is not None:
            source = entries[tainted_at][0] if entries[tainted_at] else "unknown"
            finding = _apply_rule_action(
                config, "R7",
                Finding(
                    rule_id="R7",
                    rule_name="TaintRelay",
                    severity=Severity.FAIL,
                    message="Network egress blocked after sensitive read",
                    details=[
                        f"tool '{name}' would send data out while the "
                        f"session window still contains a sensitive read "
                        f"(source tool '{source}')"
                    ],
                ),
            )
            if finding is not None and finding.severity is Severity.FAIL:
                return False, "taint relay", [finding]

    length = _run_length(entries, name, args_json, path) + 1
    threshold = config.max_consecutive_edits if config else 3
    if length >= threshold:
        finding = _apply_rule_action(
            config, "R1",
            Finding(
                rule_id="R1",
                rule_name="LoopEntrapment",
                severity=Severity.FAIL,
                message="Repeated identical call blocked",
                details=[
                    f"tool '{name}' invoked {length} times in a row "
                    f"with identical arguments"
                    + (f" on path {path!r}" if path else "")
                ],
            ),
        )
        if finding is not None and finding.severity is Severity.FAIL:
            # Stay blocked: do NOT append, so the persisted run keeps
            # counting and further identical calls stay blocked.
            return False, LOOP_BREAKER_MESSAGE, [finding]
        if finding is not None:
            # M8 "warn": allow the call but report the WARN finding.
            _save_state(
                sf,
                entries
                + [[name, args_json, path,
                    int(_is_tainted_call(name, args, path))]],
            )
            return True, "Allowed", findings + [finding]

    _save_state(
        sf,
        entries + [[name, args_json, path, int(_is_tainted_call(name, args, path))]],
    )
    # M8: a [rules] "warn" action keeps findings at WARN severity; the
    # call is allowed but the caller still receives them.
    return True, "Allowed", findings
