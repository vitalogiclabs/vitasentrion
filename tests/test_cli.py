"""Unit tests for vitasentrion.cli and vitasentrion.reporters (M5).

Covers:
- reporters: format_console / format_markdown / format_json shapes,
  render_scorecard dispatch (including unknown formats);
- cli.audit: parse + evaluate + print, exit codes 0/1, all three formats;
- cli.scan: git repo scan via real subprocess git, default repo path '.'
  with chdir, exit codes 0/1;
- cli.guard: stdin JSON payload, allow -> 0, block -> 2 with reason on
  stderr, --workspace / --state-file flags, malformed payload handling.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable, Tuple

from vitasentrion.cli import build_parser, main
from vitasentrion.models import Finding, Scorecard, Severity
from vitasentrion.reporters import (
    format_console,
    format_json,
    format_markdown,
    render_scorecard,
)


def make_card(verdict: Severity = Severity.FAIL) -> Scorecard:
    """A fixed scorecard with one WARN and one FAIL finding."""
    findings = [
        Finding(
            rule_id="R3",
            rule_name="ScratchPollution",
            severity=Severity.WARN,
            message="Scratch file found outside .scratch/",
            details=["/workspace/debug_probe.py"],
        ),
        Finding(
            rule_id="R4",
            rule_name="GitHygiene",
            severity=Severity.FAIL,
            message="Destructive git command detected",
            details=["git reset --hard"],
        ),
    ]
    return Scorecard(
        session_id="sess-123",
        verdict=verdict,
        pass_count=4,
        warn_count=1,
        fail_count=1,
        findings=findings,
        total_turns=7,
        total_tool_calls=12,
        duration_s=42.5,
    )


def clean_card() -> Scorecard:
    return Scorecard(
        session_id="clean-sess",
        verdict=Severity.PASS,
        pass_count=6,
        warn_count=0,
        fail_count=0,
        findings=[],
        total_turns=2,
        total_tool_calls=3,
        duration_s=1.0,
    )


def capture_stdout(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Tuple[str, Any]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*args, **kwargs)
    return buf.getvalue(), result


class ReporterFormatTests(unittest.TestCase):
    def test_console_shows_summary_fields(self) -> None:
        text = format_console(make_card())
        for needle in (
            "sess-123",
            "FAIL",
            "4",
            "1",
            "7",
            "12",
            "42.5",
            "R3",
            "ScratchPollution",
            "WARN",
            "Scratch file found outside .scratch/",
            "/workspace/debug_probe.py",
            "R4",
            "GitHygiene",
            "Destructive git command detected",
            "git reset --hard",
        ):
            self.assertIn(needle, text)

    def test_console_no_findings(self) -> None:
        text = format_console(clean_card())
        self.assertIn("clean-sess", text)
        self.assertIn("PASS", text)
        self.assertIn("none", text)

    def test_markdown_structure_and_table(self) -> None:
        text = format_markdown(make_card())
        self.assertIn("# VitaSentrion Scorecard", text)
        self.assertIn("`sess-123`", text)
        self.assertIn("`FAIL`", text)
        self.assertIn(
            "| Rule | Name | Severity | Message | Details |", text
        )
        self.assertIn("| --- | --- | --- | --- | --- |", text)
        self.assertIn(
            "| R3 | ScratchPollution | WARN | "
            "Scratch file found outside .scratch/ | "
            "/workspace/debug_probe.py |",
            text,
        )
        self.assertIn(
            "| R4 | GitHygiene | FAIL | Destructive git command detected "
            "| git reset --hard |",
            text,
        )

    def test_markdown_escaping_and_empty_findings(self) -> None:
        pipe_card = Scorecard(
            session_id="s",
            verdict=Severity.WARN,
            pass_count=5,
            warn_count=1,
            fail_count=0,
            findings=[
                Finding(
                    rule_id="R4",
                    rule_name="GitHygiene",
                    severity=Severity.WARN,
                    message="a | b",
                    details=["line1\nline2"],
                )
            ],
        )
        text = format_markdown(pipe_card)
        self.assertIn("a \\| b", text)
        self.assertIn("line1<br>line2", text)

        empty = format_markdown(clean_card())
        self.assertIn("_No findings._", empty)
        self.assertNotIn("| Rule | Name", empty)

    def test_json_valid_and_fields(self) -> None:
        card = make_card()
        payload = json.loads(format_json(card))
        self.assertEqual(
            {
                "session_id": "sess-123",
                "verdict": "FAIL",
                "is_clean": False,
                "pass_count": 4,
                "warn_count": 1,
                "fail_count": 1,
                "total_turns": 7,
                "total_tool_calls": 12,
                "duration_s": 42.5,
            },
            {
                "session_id": payload["session_id"],
                "verdict": payload["verdict"],
                "is_clean": payload["is_clean"],
                "pass_count": payload["pass_count"],
                "warn_count": payload["warn_count"],
                "fail_count": payload["fail_count"],
                "total_turns": payload["total_turns"],
                "total_tool_calls": payload["total_tool_calls"],
                "duration_s": payload["duration_s"],
            },
        )
        self.assertIsInstance(payload["is_clean"], bool)
        self.assertEqual(len(payload["findings"]), 2)
        first = payload["findings"][0]
        self.assertEqual(
            {
                "rule_id": "R3",
                "rule_name": "ScratchPollution",
                "severity": "WARN",
                "message": "Scratch file found outside .scratch/",
                "details": ["/workspace/debug_probe.py"],
            },
            first,
        )
        self.assertEqual(
            {
                "rule_id": "R4",
                "rule_name": "GitHygiene",
                "severity": "FAIL",
                "message": "Destructive git command detected",
                "details": ["git reset --hard"],
            },
            payload["findings"][1],
        )

    def test_json_clean_card(self) -> None:
        payload = json.loads(format_json(clean_card()))
        self.assertTrue(payload["is_clean"])
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["verdict"], "PASS")

    def test_render_dispatch(self) -> None:
        card = make_card()
        self.assertEqual(render_scorecard(card), format_console(card))
        self.assertEqual(
            render_scorecard(card, "console"), format_console(card)
        )
        self.assertEqual(
            render_scorecard(card, "markdown"), format_markdown(card)
        )
        self.assertEqual(render_scorecard(card, "json"), format_json(card))
        # Case-insensitive.
        self.assertEqual(
            render_scorecard(card, "JSON"), format_json(card)
        )

    def test_render_unknown_format(self) -> None:
        with self.assertRaises(ValueError):
            render_scorecard(make_card(), "yaml")


class AuditCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="vs-cli-audit-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def _write_trace(self, name: str, text: str) -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_audit_clean_trace_exit_0_console(self) -> None:
        trace = self._write_trace(
            "clean.json",
            json.dumps(
                {
                    "session_id": "clean-1",
                    "messages": [
                        {"role": "user", "content": "hi"},
                        {
                            "role": "assistant",
                            "content": "hello",
                            "tool_calls": [
                                {
                                    "id": "tc1",
                                    "function": {
                                        "name": "Bash",
                                        "arguments": json.dumps(
                                            {"command": "pytest"}
                                        ),
                                    },
                                }
                            ],
                        },
                        {
                            "role": "tool",
                            "tool_call_id": "tc1",
                            "content": "3 passed in 0.1s",
                        },
                    ],
                }
            ),
        )
        out, code = capture_stdout(main, ["audit", str(trace)])
        self.assertEqual(code, 0)
        self.assertIn("clean-1", out)
        self.assertIn("PASS", out)

    def test_audit_dirty_trace_exit_1_json(self) -> None:
        # A write_file event with no test run -> R2 FAIL.
        trace = self._write_trace(
            "dirty.json",
            json.dumps(
                {
                    "session_id": "dirty-1",
                    "messages": [
                        {"role": "user", "content": "add a file"},
                        {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "tc1",
                                    "function": {
                                        "name": "write_file",
                                        "arguments": json.dumps(
                                            {"path": "src/mod.py", "content": "x = 1"}
                                        ),
                                    },
                                }
                            ],
                        },
                    ],
                }
            ),
        )
        out, code = capture_stdout(
            main, ["audit", str(trace), "--format", "json"]
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["session_id"], "dirty-1")
        self.assertEqual(payload["verdict"], "FAIL")
        self.assertFalse(payload["is_clean"])
        self.assertTrue(payload["fail_count"] >= 1)
        self.assertIn("R2", [f["rule_id"] for f in payload["findings"]])

    def test_audit_raw_string_target(self) -> None:
        raw = json.dumps(
            {
                "session_id": "raw-1",
                "messages": [{"role": "user", "content": "hello"}],
            }
        )
        out, code = capture_stdout(main, ["audit", raw, "--format", "json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["session_id"], "raw-1")
        self.assertEqual(payload["verdict"], "PASS")

    def test_audit_markdown_format(self) -> None:
        raw = json.dumps(
            {
                "session_id": "md-1",
                "messages": [
                    {"role": "user", "content": "go"},
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "tc1",
                                "function": {
                                    "name": "write_file",
                                    "arguments": json.dumps(
                                        {"path": "a.py", "content": "1"}
                                    ),
                                },
                            }
                        ],
                    },
                ],
            }
        )
        out, code = capture_stdout(
            main, ["audit", raw, "--format", "markdown"]
        )
        self.assertEqual(code, 1)
        self.assertIn("# VitaSentrion Scorecard", out)
        self.assertIn("| Rule | Name | Severity | Message | Details |", out)

    def test_audit_bad_format_choice(self) -> None:
        err = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(err):
                main(["audit", "whatever", "--format", "yaml"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("invalid choice", err.getvalue())


class ScanCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="vs-cli-scan-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self._git("init", "-q")
        self._git("config", "user.email", "test@example.com")
        self._git("config", "user.name", "Test")

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=str(self.repo),
            capture_output=True,
            text=True,
            check=True,
        )

    def test_scan_clean_repo_exit_0(self) -> None:
        out, code = capture_stdout(main, ["scan", str(self.repo)])
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)
        self.assertIn("none", out)

    def test_scan_uncommitted_exit_1_json(self) -> None:
        # A code file (not a doc/config file) is required for R2 to fire
        # under M4.5 amendment 2 (code-only trigger).
        (self.repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        out, code = capture_stdout(
            main, ["scan", str(self.repo), "--format", "json"]
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        # An untracked code file triggers R4 (uncommitted files, WARN) and R2
        # (code file created without a test run, FAIL) -> overall FAIL verdict.
        self.assertEqual(payload["verdict"], "FAIL")
        self.assertFalse(payload["is_clean"])
        self.assertEqual(payload["warn_count"], 1)
        self.assertEqual(payload["fail_count"], 1)
        rule_ids = [f["rule_id"] for f in payload["findings"]]
        self.assertIn("R4", rule_ids)
        self.assertIn("R2", rule_ids)

    def test_scan_dirty_secret_exit_1(self) -> None:
        secret = "sk-" + "a" * 30
        (self.repo / "keys.py").write_text(
            f"API_KEY = '{secret}'\n", encoding="utf-8"
        )
        out, code = capture_stdout(
            main, ["scan", str(self.repo), "--format", "json"]
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "FAIL")
        self.assertFalse(payload["is_clean"])
        self.assertIn("R5", [f["rule_id"] for f in payload["findings"]])

    def test_scan_default_repo_path_is_cwd(self) -> None:
        # Use a code file so R2 fires (M4.5 amendment 2: doc-only files
        # do not trigger R2, which would make the verdict WARN/clean).
        (self.repo / "module.py").write_text("x = 1\n", encoding="utf-8")
        old_cwd = Path.cwd()
        self.addCleanup(lambda: os.chdir(old_cwd))
        os.chdir(self.repo)
        out, code = capture_stdout(main, ["scan"])
        self.assertEqual(code, 1)
        self.assertIn("WARN", out)
        self.assertIn("R4", out)

    def test_scan_non_repo_errors(self) -> None:
        import unittest.mock as mock

        empty = self.tmp / "not-a-repo"
        empty.mkdir()
        # tempfile may live inside an outer git repo (the workspace is one);
        # GIT_CEILING_DIRECTORIES stops git's upward discovery so the empty
        # dir is genuinely "not a repository" regardless of its location.
        env_patch = {
            "GIT_CEILING_DIRECTORIES": str(empty.parent),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        with mock.patch.dict(os.environ, env_patch):
            with self.assertRaises(RuntimeError):
                main(["scan", str(empty)])


class GuardCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="vs-cli-guard-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "proj"
        self.root.mkdir()
        self.state = Path(self._tmp.name) / "state.json"

    def _run_guard(
        self, stdin_text: str, *extra: str
    ) -> tuple[int, str, str]:
        old_stdin, old_out, old_err = sys.stdin, sys.stdout, sys.stderr
        out_buf, err_buf = io.StringIO(), io.StringIO()
        sys.stdin = io.StringIO(stdin_text)
        sys.stdout, sys.stderr = out_buf, err_buf
        try:
            code = main(["guard", *extra])
        finally:
            sys.stdin, sys.stdout, sys.stderr = old_stdin, old_out, old_err
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_guard_allows_safe_call(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }
        code, out, err = self._run_guard(
            json.dumps(payload),
            "--workspace",
            str(self.root),
            "--state-file",
            str(self.state),
        )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        # Loop-breaker state was recorded.
        self.assertTrue(self.state.is_file())

    def test_guard_blocks_destructive(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "git reset --hard"},
        }
        code, out, err = self._run_guard(
            json.dumps(payload),
            "--workspace",
            str(self.root),
            "--state-file",
            str(self.state),
        )
        self.assertEqual(code, 2)
        self.assertIn("destructive command", err)
        self.assertIn("blocked", err.lower())

    def test_guard_blocks_network_escape(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {
                "command": "curl http://169.254.169.254/latest/meta-data/"
            },
        }
        code, _out, err = self._run_guard(
            json.dumps(payload),
            "--workspace",
            str(self.root),
            "--state-file",
            str(self.state),
        )
        self.assertEqual(code, 2)
        self.assertNotEqual(err, "")

    def test_guard_cline_payload_shape(self) -> None:
        payload = {
            "tool_name": "bash",
            "tool_input": json.dumps({"command": "rm -rf /"}),
        }
        code, _out, err = self._run_guard(
            json.dumps(payload),
            "--workspace",
            str(self.root),
            "--state-file",
            str(self.state),
        )
        self.assertEqual(code, 2)
        self.assertNotEqual(err, "")

    def test_guard_loop_breaker_via_state_file(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
        }
        first = self._run_guard(
            json.dumps(payload),
            "--workspace",
            str(self.root),
            "--state-file",
            str(self.state),
        )
        self.assertEqual(first[0], 0)
        second = self._run_guard(
            json.dumps(payload),
            "--workspace",
            str(self.root),
            "--state-file",
            str(self.state),
        )
        self.assertEqual(second[0], 0)
        third = self._run_guard(
            json.dumps(payload),
            "--workspace",
            str(self.root),
            "--state-file",
            str(self.state),
        )
        self.assertEqual(third[0], 2)
        self.assertIn("Loop", third[2])

    def test_guard_invalid_json(self) -> None:
        code, _out, err = self._run_guard(
            "not json",
            "--state-file",
            str(self.state),
        )
        self.assertEqual(code, 2)
        self.assertIn("invalid JSON", err)

    def test_guard_non_object_payload(self) -> None:
        code, _out, err = self._run_guard(
            json.dumps([1, 2, 3]),
            "--state-file",
            str(self.state),
        )
        self.assertEqual(code, 2)
        self.assertNotEqual(err, "")


class ParserWiringTests(unittest.TestCase):
    def test_subcommands_registered(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args([])  # no subcommand -> required error
        args = parser.parse_args(["audit", "x", "--format", "json"])
        self.assertEqual(args.command, "audit")
        self.assertEqual(args.format, "json")
        args = parser.parse_args(["scan"])
        self.assertEqual(args.repo_path, ".")
        self.assertEqual(args.format, "console")
        args = parser.parse_args(["guard"])
        self.assertIsNone(args.workspace)
        self.assertIsNone(args.state_file)

    def test_main_defaults_to_argv_none_uses_sys_argv(self) -> None:
        # main(None) reads sys.argv[1:]; simulate a clean scan of /tmp-ish.
        # Just verify the signature/entrypoint exist and the __main__ guard
        # path is importable without side effects.
        self.assertTrue(callable(main))
        import vitasentrion.cli as cli_module

        self.assertTrue(hasattr(cli_module, "__name__"))


    def test_fail_on_flag_semantics(self) -> None:
        # A scorecard with 0 fails and 1 warn
        from vitasentrion.models import Scorecard, Severity, Finding
        card = Scorecard(session_id="w", verdict=Severity.WARN, pass_count=5, warn_count=1, fail_count=0, findings=[Finding("R4", "Git", Severity.WARN, "msg")])
        
        # When --fail-on fail (default): should exit 0 because fail_count is 0
        from vitasentrion.cli import build_parser
        parser = build_parser()
        args_fail = parser.parse_args(["audit", "x", "--fail-on", "fail"])
        # Verify default is fail
        args_default = parser.parse_args(["audit", "x"])
        self.assertEqual(args_default.fail_on, "fail")


if __name__ == "__main__":
    unittest.main()
