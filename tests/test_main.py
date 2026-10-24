"""Unit tests for vitasentrion.__main__ — the `python -m vitasentrion` entry.

Covers: module invocation via subprocess (--help, --version) and a real
guard dispatch through stdin proving ``sys.exit(main())`` wiring.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_module(*args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "vitasentrion", *args],
        input=stdin,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )


class ModuleEntryPointTests(unittest.TestCase):
    def test_help_via_module(self):
        proc = run_module("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("usage: vitasentrion", proc.stdout)

    def test_version_via_module(self):
        proc = run_module("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("VitaSentrion", proc.stdout)

    def test_guard_dispatch_via_module(self):
        # A safe call goes through the full guard path and exits 0.
        payload = json.dumps(
            {"name": "terminal", "arguments": {"command": "echo hi"}}
        )
        proc = run_module(
            "guard", "--workspace", str(REPO_ROOT), stdin=payload
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_blocked_call_exits_2_via_module(self):
        # The entry point propagates the guard's block exit code.
        payload = json.dumps(
            {"name": "terminal", "arguments": {"command": "sudo rm -rf /"}}
        )
        proc = run_module(
            "guard", "--workspace", str(REPO_ROOT), stdin=payload
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("Blocked", proc.stderr)


if __name__ == "__main__":
    unittest.main()
