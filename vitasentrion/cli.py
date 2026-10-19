"""VitaSentrion Command Line Interface."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from vitasentrion import __version__
from vitasentrion.guard import evaluate_hook_payload, reset_state, _default_state_file
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
    p_audit.add_argument("--fail-on", choices=["warn", "fail"], default="fail", help="Severity threshold for exit code 1")
    p_audit.add_argument("--format", choices=["console", "markdown", "json"], default="console")
    p_audit.set_defaults(func=cmd_audit)

    p_scan = subparsers.add_parser("scan", help="Scan a git repository for agent vandalism and weakened tests")
    p_scan.add_argument("repo_path", nargs="?", default=".", help="Path to git repository (default: current dir)")
    p_scan.add_argument("--base", default=None, help="Base git ref for PR diff scanning (e.g. origin/main or HEAD~1)")
    p_scan.add_argument("--fail-on", choices=["warn", "fail"], default="fail", help="Severity threshold for exit code 1")
    p_scan.add_argument("--format", choices=["console", "markdown", "json"], default="console")
    p_scan.set_defaults(func=cmd_scan)

    p_guard = subparsers.add_parser("guard", help="Pre-tool hook guard reading JSON from stdin (Claude Code hook compatible)")
    p_guard.add_argument("--workspace", default=None, help="Workspace root directory")
    p_guard.add_argument("--state-file", default=None, help="Path to persistent state file")
    p_guard.add_argument("--reset", action="store_true", help="Delete the loop-breaker state file and exit (0)")
    p_guard.set_defaults(func=cmd_guard)

    return parser


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

    card = evaluate_trace(trace)
    print(render_scorecard(card, fmt=args.format))

    if args.fail_on == "warn":
        return 0 if (card.fail_count == 0 and card.warn_count == 0) else 1
    return 0 if card.fail_count == 0 else 1


def cmd_scan(args) -> int:
    repo = Path(args.repo_path).resolve()
    res = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"'{repo}' is not inside a git repository.")

    card = audit_git_repo(repo, base_ref=args.base)
    print(render_scorecard(card, fmt=args.format))

    if args.fail_on == "warn":
        return 0 if (card.fail_count == 0 and card.warn_count == 0) else 1
    return 0 if card.fail_count == 0 else 1


def cmd_guard(args) -> int:
    state_path = Path(args.state_file).resolve() if args.state_file else None
    ws_root = Path(args.workspace).resolve() if args.workspace else Path.cwd()

    if args.reset:
        sf = state_path if state_path else _default_state_file(str(ws_root))
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

    allowed, reason, findings = evaluate_hook_payload(payload, state_file=state_path, workspace_root=ws_root)
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
