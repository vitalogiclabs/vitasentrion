"""VitaSentrion Command Line Interface."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from vitasentrion import __version__
from vitasentrion.config import ConfigError, load_config
from vitasentrion.guard import (
    evaluate_hook_payload,
    reset_state,
    verify_events_chain,
    _default_state_file,
)
from vitasentrion.models import Finding, Severity
from vitasentrion.parsers import parse_trace
from vitasentrion.reporters import render_scorecard
from vitasentrion.rules import evaluate_trace
from vitasentrion.scanner import audit_git_repo


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vitasentrion",
        description="VitaSentrion by VitaLogic Labs — The Zero-Dependency Firewall, Loop Breaker & Linter for AI Coding Agents."
    )
    parser.add_argument("-v", "--version", action="version", version=f"VitaSentrion {__version__} (VitaLogic Labs)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_audit = subparsers.add_parser("audit", help="Audit an agent session transcript or event log")
    p_audit.add_argument("target", help="Path to transcript file (.jsonl or .json) or raw JSON string")
    p_audit.add_argument("--config", default=None, help="Path to vitasentrion.toml (default: search target dir / repo root)")
    p_audit.add_argument("--fail-on", choices=["warn", "fail"], default="fail", help="Severity threshold for exit code 1")
    p_audit.add_argument("--format", choices=["console", "markdown", "json"], default="console")
    p_audit.set_defaults(func=cmd_audit)

    p_scan = subparsers.add_parser("scan", help="Scan a git repository for agent vandalism and weakened tests")
    p_scan.add_argument("repo_path", nargs="?", default=".", help="Path to git repository (default: current dir)")
    p_scan.add_argument("--base", default=None, help="Base git ref for PR diff scanning (e.g. origin/main or HEAD~1)")
    p_scan.add_argument("--config", default=None, help="Path to vitasentrion.toml (default: search repo dir / repo root)")
    p_scan.add_argument("--fail-on", choices=["warn", "fail"], default="fail", help="Severity threshold for exit code 1")
    p_scan.add_argument("--format", choices=["console", "markdown", "json"], default="console")
    p_scan.set_defaults(func=cmd_scan)

    p_guard = subparsers.add_parser("guard", help="Pre-tool hook guard reading JSON from stdin (Claude Code hook compatible)")
    p_guard.add_argument("--workspace", default=None, help="Workspace root directory")
    p_guard.add_argument("--state-file", default=None, help="Path to persistent state file")
    p_guard.add_argument("--config", default=None, help="Path to vitasentrion.toml (default: search workspace dir / repo root)")
    p_guard.add_argument("--reset", action="store_true", help="Delete the loop-breaker state file and exit (0)")
    p_guard.set_defaults(func=cmd_guard)

    return parser


def _load_cli_config(args, start_dir):
    """Resolve --config / auto-discovery for a command (M8)."""
    try:
        return load_config(
            path=Path(args.config) if args.config else None,
            start_dir=start_dir,
        )
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        return None


def cmd_audit(args) -> int:
    target_str = args.target.strip()
    is_file = False
    if not (target_str.startswith("{") or target_str.startswith("[")):
        try:
            p = Path(target_str)
            is_file = p.exists() and p.is_file()
        except OSError:
            is_file = False

    if is_file:
        trace = parse_trace(Path(target_str))
    else:
        try:
            trace = parse_trace(target_str)
        except Exception:
            print(f"Error: Target '{args.target}' does not exist and is not valid JSON.", file=sys.stderr)
            return 1

    cfg = _load_cli_config(args, Path(target_str).parent if is_file else Path.cwd())
    if cfg is None:
        return 1
    card = evaluate_trace(trace, config=cfg)
    # M7 (P1-a): an events JSONL written by the guard carries a hash
    # chain; verify it and fold any tamper finding into the scorecard.
    if is_file and Path(target_str).suffix == ".jsonl":
        chain_findings = verify_events_chain(Path(target_str))
        # M8: [rules].R8 = "warn" downgrades, "ignore" skips the check.
        from vitasentrion.config import effective_rule_severity
        kept = []
        for f in chain_findings:
            sev = effective_rule_severity(cfg, "R8", f.severity)
            if sev is None:
                continue
            if sev is not f.severity:
                f = Finding(rule_id=f.rule_id, rule_name=f.rule_name,
                            severity=sev, message=f.message,
                            details=f.details)
            kept.append(f)
        card.findings.extend(kept)
        card.fail_count += sum(1 for f in kept if f.severity is Severity.FAIL)
        card.warn_count += sum(1 for f in kept if f.severity is Severity.WARN)
        if kept and card.verdict is Severity.PASS:
            card.verdict = (Severity.FAIL
                            if card.fail_count else Severity.WARN)
    print(render_scorecard(card, fmt=args.format))

    if args.fail_on == "warn":
        return 0 if (card.fail_count == 0 and card.warn_count == 0) else 1
    return 0 if card.fail_count == 0 else 1


def cmd_scan(args) -> int:
    repo = Path(args.repo_path).resolve()
    res = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"'{repo}' is not inside a git repository.")

    cfg = _load_cli_config(args, repo)
    if cfg is None:
        return 1
    card = audit_git_repo(repo, base_ref=args.base, config=cfg)
    print(render_scorecard(card, fmt=args.format))

    if args.fail_on == "warn":
        return 0 if (card.fail_count == 0 and card.warn_count == 0) else 1
    return 0 if card.fail_count == 0 else 1


def cmd_guard(args) -> int:
    state_path = Path(args.state_file).resolve() if args.state_file else None
    ws_from_cli = bool(args.workspace)
    cli_ws = Path(args.workspace).resolve() if args.workspace else Path.cwd()

    cfg = _load_cli_config(args, cli_ws)
    if cfg is None:
        return 1

    # Chain: --workspace flag > [guard].workspace_root setting > cwd.
    if ws_from_cli:
        ws_root = cli_ws
    elif cfg.workspace_root:
        ws_root = Path(cfg.workspace_root)
    else:
        ws_root = Path.cwd()

    if args.reset:
        sf = state_path if state_path else _default_state_file(
            str(ws_root), cfg.state_dir
        )
        removed = reset_state(sf)
        print(f"VitaSentrion: loop-breaker state {'reset' if removed else 'not present'} ({sf})")
        return 0

    raw = sys.stdin.read().strip()
    if not raw:
        return 0
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            sys.stderr.write("VitaSentrion: payload must be a JSON object.\n")
            return 2
    except Exception as e:
        sys.stderr.write(f"VitaSentrion: invalid JSON on stdin: {e}\n")
        return 2

    allowed, reason, findings = evaluate_hook_payload(
        payload, state_file=state_path, workspace_root=ws_root, config=cfg
    )
    if allowed:
        return 0
    else:
        sys.stderr.write(f"VitaSentrion Hook Blocked: {reason}\n")
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
