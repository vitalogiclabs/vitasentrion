"""Unit tests for vitasentrion.parsers (SPEC milestone M2)."""
from __future__ import annotations

import io
import json
import os
import unittest
from pathlib import Path

from vitasentrion.config import VitaConfig
from vitasentrion.models import SessionTrace, ToolEvent
from vitasentrion.parsers import (
    _content_to_text,
    _git_status_uncommitted,
    _last_test_passed,
    _parse_timestamp,
    _try_jsonl,
    parse_trace,
)

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

CLAUDE_JSONL = [
    {
        "type": "summary",
        "sessionId": "cc-sess-1",
        "cwd": "/ws/proj",
        "summary": "fix bug",
    },
    {
        "type": "user",
        "timestamp": "2026-10-18T10:00:00Z",
        "sessionId": "cc-sess-1",
        "cwd": "/ws/proj",
        "message": {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "t1",
                    "content": "1 passed in 0.02s",
                }
            ],
        },
    },
    {
        "type": "assistant",
        "timestamp": "2026-10-18T10:00:05Z",
        "sessionId": "cc-sess-1",
        "cwd": "/ws/proj",
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": "Let me patch the file.",
                },
                {
                    "type": "tool_use",
                    "id": "t2",
                    "name": "Edit",
                    "input": {"file_path": "src/app.py", "old_string": "a", "new_string": "b"},
                },
            ],
        },
    },
    {
        "type": "assistant",
        "timestamp": "2026-10-18T10:00:10Z",
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "t3",
                    "name": "Write",
                    "input": {"file_path": "src/new_module.py", "content": "x = 1\n"},
                }
            ],
        },
    },
    {
        "type": "assistant",
        "timestamp": "2026-10-18T10:00:15Z",
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "t4",
                    "name": "Bash",
                    "input": {"command": "pytest -q"},
                }
            ],
        },
    },
    {
        "type": "user",
        "timestamp": "2026-10-18T10:00:20Z",
        "message": {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "t4",
                    "content": "3 failed, 1 passed",
                    "is_error": True,
                }
            ],
        },
    },
    {
        "type": "assistant",
        "timestamp": "2026-10-18T10:00:25Z",
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "t5",
                    "name": "Bash",
                    "input": {
                        "command": "git status --porcelain",
                    },
                }
            ],
        },
    },
    {
        "type": "user",
        "timestamp": "2026-10-18T10:00:30Z",
        "message": {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "t5",
                    "content": " M src/app.py\n?? src/new_module.py",
                }
            ],
        },
    },
]


def claude_jsonl_text() -> str:
    return "\n".join(json.dumps(line) for line in CLAUDE_JSONL)


CLINE_TASK = {
    "taskId": "cline-42",
    "workspace": "/ws/cline",
    "createdAt": "2026-10-18T09:00:00.000Z",
    "updatedAt": "2026-10-18T09:05:00.000Z",
    "history": [
        {
            "role": "user",
            "content": "please fix the login",
            "timestamp": "2026-10-18T09:00:00Z",
        },
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "I will update the auth module."},
                {
                    "type": "tool_use",
                    "id": "cu1",
                    "name": "patch",
                    "input": {"path": "auth/login.py", "old_string": "x", "new_string": "y"},
                },
            ],
            "timestamp": "2026-10-18T09:01:00Z",
        },
        {
            "role": "tool",
            "tool_use_id": "cu1",
            "content": [{"type": "text", "text": "file updated"}],
            "timestamp": "2026-10-18T09:01:30Z",
        },
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "cu2",
                    "name": "write_file",
                    "input": {"path": "auth/session.py", "content": "class S: pass\n"},
                }
            ],
            "timestamp": "2026-10-18T09:02:00Z",
        },
        {
            "role": "tool",
            "tool_use_id": "cu2",
            "content": "created auth/session.py",
            "timestamp": "2026-10-18T09:02:10Z",
        },
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "cu3",
                    "name": "run_command",
                    "input": {"command": "python -m unittest discover"},
                }
            ],
            "timestamp": "2026-10-18T09:03:00Z",
        },
        {
            "role": "tool",
            "tool_use_id": "cu3",
            "content": "OK (5 tests)",
            "timestamp": "2026-10-18T09:03:20Z",
        },
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "cu4",
                    "name": "Bash",
                    "input": {"command": "git status --porcelain"},
                }
            ],
            "timestamp": "2026-10-18T09:04:00Z",
        },
        {
            "role": "tool",
            "tool_use_id": "cu4",
            "content": " M auth/login.py\n?? auth/session.py",
            "timestamp": "2026-10-18T09:04:05Z",
        },
    ],
}


def openai_messages() -> list[dict]:
    return [
        {
            "role": "user",
            "content": "refactor the cli",
            "timestamp": "2026-10-18T08:00:00Z",
        },
        {
            "role": "assistant",
            "content": "Working on it.",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "write_file",
                        "arguments": json.dumps({"path": "cli/main.py", "content": "def main(): pass\n"}),
                    },
                },
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {
                        "name": "patch",
                        "arguments": json.dumps({"path": "cli/args.py", "old_string": "a", "new_string": "b"}),
                    },
                },
            ],
            "timestamp": "2026-10-18T08:00:30Z",
        },
        {
            "role": "tool",
            "tool_call_id": "call_1",
            "content": "ok",
        },
        {
            "role": "tool",
            "tool_call_id": "call_2",
            "content": "ok",
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_3",
                    "type": "function",
                    "function": {
                        "name": "terminal",
                        "arguments": json.dumps({"command": "npm test"}),
                    },
                }
            ],
            "timestamp": "2026-10-18T08:01:00Z",
        },
        {
            "role": "tool",
            "tool_call_id": "call_3",
            "content": "Test Suites: 3 passed, 3 total\nTests: 12 passed, 12 total",
        },
        {
            "role": "assistant",
            "content": "Done.",
            "timestamp": "2026-10-18T08:01:30Z",
        },
    ]


def openai_doc() -> dict:
    return {
        "session_id": "oa-sess",
        "cwd": "/ws/oa",
        "messages": openai_messages(),
    }


def openai_jsonl_text() -> str:
    return "\n".join(json.dumps(line) for line in openai_messages())


# ---------------------------------------------------------------------------
# Helpers: low-level functions
# ---------------------------------------------------------------------------

class TestLowLevelHelpers(unittest.TestCase):
    def test_try_jsonl_valid(self):
        self.assertEqual(_try_jsonl('{"a": 1}\n\n{"b": 2}'), [{"a": 1}, {"b": 2}])

    def test_try_jsonl_bad_line_returns_none(self):
        self.assertIsNone(_try_jsonl('{"a": 1}\nnot json'))

    def test_try_jsonl_blank_returns_none(self):
        self.assertIsNone(_try_jsonl(""))
        self.assertIsNone(_try_jsonl("   \n\n"))

    def test_parse_timestamp_iso_z_suffix(self):
        dt = _parse_timestamp("2026-10-18T10:00:00Z")
        assert dt is not None
        self.assertEqual(dt.utcoffset().total_seconds(), 0.0)

    def test_parse_timestamp_iso_with_offset(self):
        dt = _parse_timestamp("2026-10-18T10:00:00+02:00")
        assert dt is not None
        self.assertEqual(dt.utcoffset().total_seconds(), 7200.0)

    def test_parse_timestamp_epoch_seconds_and_millis(self):
        secs = _parse_timestamp(1760000000)
        millis = _parse_timestamp(1760000000000)
        assert secs is not None
        assert millis is not None
        self.assertEqual(secs.timestamp(), millis.timestamp())

    def test_parse_timestamp_bad_values(self):
        self.assertIsNone(_parse_timestamp("nope"))
        self.assertIsNone(_parse_timestamp(None))
        self.assertIsNone(_parse_timestamp(True))
        self.assertIsNone(_parse_timestamp(-5))
        self.assertIsNone(_parse_timestamp(""))

    def test_content_to_text_string_none_list(self):
        self.assertEqual(_content_to_text("hi"), "hi")
        self.assertEqual(_content_to_text(None), "")
        self.assertEqual(
            _content_to_text(
                ["a", {"type": "text", "text": "b"}, {"type": "x", "content": ["c"]}]
            ),
            "a\nb\nc",
        )
        self.assertEqual(_content_to_text({"weird": 1}), str({"weird": 1}))

    def test_last_test_passed_variants(self):
        self.assertTrue(_last_test_passed("12 passed in 0.1s", False))
        self.assertTrue(_last_test_passed("OK (3 tests)", False))
        self.assertFalse(_last_test_passed("FAILED: 1 failure", False))
        self.assertFalse(_last_test_passed("2 failed, 1 passed", False))
        self.assertFalse(_last_test_passed("traceback (most recent call last)", False))
        self.assertFalse(_last_test_passed("", True))
        self.assertIsNone(_last_test_passed("", False))
        self.assertIsNone(_last_test_passed("output without verdict", False))

    # --- M4.5 amendment 3: precise pass/fail verdicts ---
    def test_zero_failed_with_passed_is_pass(self):
        # "5 passed, 0 failed" MUST be a pass (failure count is 0).
        self.assertTrue(_last_test_passed("5 passed, 0 failed", False))
        self.assertTrue(_last_test_passed("12 passed, 0 failed, 1 skipped", False))

    def test_nonzero_failure_or_error_count_is_fail(self):
        self.assertFalse(_last_test_passed("1 failed, 3 passed", False))
        self.assertFalse(_last_test_passed("0 failed, 2 errors", False))
        self.assertFalse(_last_test_passed("3 errors in 0.2s", False))

    def test_arbitrary_ok_substring_is_not_a_pass(self):
        # "connection ok" / "all systems ok" are not test-runner summaries.
        self.assertIsNone(_last_test_passed("connection ok", False))
        self.assertIsNone(_last_test_passed("all systems ok", False))
        self.assertIsNone(_last_test_passed("build finished successfully", False))

    def test_ran_tests_ok_summary_is_pass(self):
        # Python unittest style: "Ran N tests ... OK".
        self.assertTrue(_last_test_passed("Ran 3 tests in 0.01s\nOK", True))
        self.assertFalse(
            _last_test_passed("Ran 3 tests in 0.01s\n\nFAILED (failures=1)", False)
        )

    def test_git_status_porcelain(self):
        files = _git_status_uncommitted(
            "git status --porcelain", " M a.py\n?? b.py\nR  old.py -> new.py\n"
        )
        self.assertEqual(files, {"a.py", "b.py", "new.py"})

    def test_git_status_humane(self):
        files = _git_status_uncommitted(
            "git status",
            "On branch main\nChanges not staged:\n  modified:   a.py\n  new file:   b.py\n",
        )
        self.assertEqual(files, {"a.py", "b.py"})

    def test_git_status_requires_git_status_command(self):
        self.assertEqual(_git_status_uncommitted("ls", " M a.py"), set())


# ---------------------------------------------------------------------------
# Claude Code (.jsonl)
# ---------------------------------------------------------------------------

class TestParseClaudeCode(unittest.TestCase):
    def setUp(self):
        self.trace = parse_trace(claude_jsonl_text())

    def test_returns_session_trace(self):
        self.assertIsInstance(self.trace, SessionTrace)

    def test_session_id_and_workspace_from_metadata(self):
        self.assertEqual(self.trace.session_id, "cc-sess-1")
        self.assertEqual(self.trace.workspace_root, "/ws/proj")

    def test_tool_events(self):
        names = [e.tool_name for e in self.trace.tool_events]
        self.assertEqual(names, ["Edit", "Write", "Bash", "Bash"])
        self.assertIsInstance(self.trace.tool_events[0], ToolEvent)

    def test_arguments_parsed(self):
        edit = self.trace.tool_events[0]
        self.assertEqual(edit.arguments["file_path"], "src/app.py")
        bash = self.trace.tool_events[2]
        self.assertEqual(bash.arguments["command"], "pytest -q")

    def test_output_matched_by_tool_id(self):
        pytest_event = self.trace.tool_events[2]
        self.assertEqual(pytest_event.output, "3 failed, 1 passed")
        self.assertTrue(pytest_event.is_error)
        # Edit had no recorded result.
        self.assertEqual(self.trace.tool_events[0].output, "")
        self.assertFalse(self.trace.tool_events[0].is_error)
        # The stray early tool_result (t1) does not leak into any event.
        for event in self.trace.tool_events:
            self.assertNotEqual(event.output, "1 passed in 0.02s")

    def test_files_created_and_modified(self):
        self.assertEqual(self.trace.files_modified, {"src/app.py"})
        self.assertEqual(self.trace.files_created, {"src/new_module.py"})

    def test_test_runs_count_and_last_result(self):
        self.assertEqual(self.trace.test_runs_count, 1)
        self.assertIs(self.trace.last_test_passed, False)

    def test_uncommitted_files_from_git_status(self):
        self.assertEqual(
            self.trace.uncommitted_files, {"src/app.py", "src/new_module.py"}
        )

    def test_turns_count_user_and_assistant_lines(self):
        # 7 lines of type user/assistant carry messages.
        self.assertEqual(self.trace.turns_count, 7)

    def test_duration_s_from_timestamps(self):
        self.assertEqual(self.trace.duration_s, 30.0)

    def test_parses_from_path_and_path_object(self):
        with self.subTest():
            import tempfile, os
            fd, path = tempfile.mkstemp(suffix=".jsonl")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(claude_jsonl_text())
                via_str = parse_trace(path)
                via_obj = parse_trace(Path(path))
            finally:
                os.unlink(path)
        self.assertEqual(via_str.session_id, "cc-sess-1")
        self.assertEqual(via_obj.session_id, "cc-sess-1")
        self.assertEqual(len(via_str.tool_events), 4)
        self.assertEqual(len(via_obj.tool_events), 4)

    def test_parses_from_file_like_object(self):
        fh = io.StringIO(claude_jsonl_text())
        trace = parse_trace(fh)
        self.assertEqual(trace.session_id, "cc-sess-1")
        self.assertEqual(len(trace.tool_events), 4)

    def test_top_level_tool_use_and_tool_result_lines(self):
        text = "\n".join(
            json.dumps(line)
            for line in (
                {"type": "tool_use", "id": "a1", "name": "Edit",
                 "input": {"file_path": "x.py"}},
                {"type": "tool_result", "tool_use_id": "a1", "content": "done"},
            )
        )
        trace = parse_trace(text)
        self.assertEqual(len(trace.tool_events), 1)
        self.assertEqual(trace.tool_events[0].tool_name, "Edit")
        self.assertEqual(trace.tool_events[0].output, "done")
        self.assertEqual(trace.files_modified, {"x.py"})


# ---------------------------------------------------------------------------
# Cline / Roo Code (JSON)
# ---------------------------------------------------------------------------

class TestParseCline(unittest.TestCase):
    def setUp(self):
        self.trace = parse_trace(json.dumps(CLINE_TASK))

    def test_session_id_and_workspace(self):
        self.assertEqual(self.trace.session_id, "cline-42")
        self.assertEqual(self.trace.workspace_root, "/ws/cline")

    def test_tool_events(self):
        self.assertEqual(
            [e.tool_name for e in self.trace.tool_events],
            ["patch", "write_file", "run_command", "Bash"],
        )

    def test_arguments_and_outputs(self):
        self.assertEqual(self.trace.tool_events[0].arguments["path"], "auth/login.py")
        self.assertEqual(self.trace.tool_events[1].output, "created auth/session.py")
        self.assertEqual(self.trace.tool_events[2].output, "OK (5 tests)")

    def test_files(self):
        self.assertEqual(self.trace.files_modified, {"auth/login.py"})
        self.assertEqual(self.trace.files_created, {"auth/session.py"})

    def test_test_runs_and_result(self):
        self.assertEqual(self.trace.test_runs_count, 1)
        self.assertIs(self.trace.last_test_passed, True)

    def test_uncommitted_files(self):
        self.assertEqual(self.trace.uncommitted_files, {"auth/login.py", "auth/session.py"})

    def test_turns_count_excludes_tool_role(self):
        # 1 user + 4 assistant = 5; the 4 tool messages do not count.
        self.assertEqual(self.trace.turns_count, 5)

    def test_duration_s(self):
        # First message 09:00:00Z to last 09:04:05Z.
        self.assertEqual(self.trace.duration_s, 245.0)

    def test_plain_message_list_without_wrapper(self):
        trace = parse_trace(json.dumps(CLINE_TASK["history"]))
        self.assertEqual(len(trace.tool_events), 4)
        self.assertEqual(trace.files_modified, {"auth/login.py"})


# ---------------------------------------------------------------------------
# OpenAI / Hermes (JSON and JSONL)
# ---------------------------------------------------------------------------

class TestParseOpenAI(unittest.TestCase):
    def test_json_document_with_messages_wrapper(self):
        trace = parse_trace(json.dumps(openai_doc()))
        self.assertEqual(trace.session_id, "oa-sess")
        self.assertEqual(trace.workspace_root, "/ws/oa")
        self.assertEqual(
            [e.tool_name for e in trace.tool_events],
            ["write_file", "patch", "terminal"],
        )
        self.assertEqual(trace.files_created, {"cli/main.py"})
        self.assertEqual(trace.files_modified, {"cli/args.py"})
        self.assertEqual(trace.test_runs_count, 1)
        self.assertIs(trace.last_test_passed, True)
        # arguments were JSON strings; now dicts
        self.assertEqual(trace.tool_events[0].arguments["path"], "cli/main.py")

    def test_jsonl_of_messages(self):
        trace = parse_trace(openai_jsonl_text())
        self.assertEqual(len(trace.tool_events), 3)
        self.assertEqual(
            [e.tool_name for e in trace.tool_events],
            ["write_file", "patch", "terminal"],
        )
        self.assertIs(trace.last_test_passed, True)

    def test_duration_from_message_timestamps(self):
        trace = parse_trace(openai_jsonl_text())
        self.assertEqual(trace.duration_s, 90.0)

    def test_turns_count(self):
        trace = parse_trace(openai_jsonl_text())
        # 1 user + 3 assistant (the 3 tool messages excluded)
        self.assertEqual(trace.turns_count, 4)

    def test_plain_message_list_json(self):
        trace = parse_trace(json.dumps(openai_messages()))
        self.assertEqual(len(trace.tool_events), 3)


# ---------------------------------------------------------------------------
# Detection / edge cases
# ---------------------------------------------------------------------------

class TestDetectionAndEdgeCases(unittest.TestCase):
    def test_unrecognized_content_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_trace("hello world, not json at all")

    def test_empty_content_returns_minimal_trace(self):
        trace = parse_trace("")
        self.assertEqual(trace.session_id, "unknown")
        self.assertEqual(trace.tool_events, [])
        self.assertEqual(trace.duration_s, 0.0)

    def test_bad_extension_but_json_content_detected(self):
        # Content is a JSON object even though the name says .jsonl
        # (no line parsing needed because the whole thing parses as JSON...
        # actually .jsonl prefers line-wise; use a single-line JSON object).
        doc = json.dumps(openai_doc())
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(doc)
            trace = parse_trace(path)
            self.assertEqual(trace.session_id, "oa-sess")
            self.assertEqual(len(trace.tool_events), 3)
        finally:
            os.unlink(path)

    def test_jsonl_content_with_plain_json_extension(self):
        # JSONL content saved as .json: line-wise parsing must still kick in
        # because the whole text is not a single JSON document.
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(claude_jsonl_text())
            trace = parse_trace(path)
            self.assertEqual(trace.session_id, "cc-sess-1")
            self.assertEqual(len(trace.tool_events), 4)
        finally:
            os.unlink(path)

    def test_string_source_that_is_not_an_existing_path(self):
        # A string is treated as raw content: valid JSON parses,
        # a path-looking string that is not valid JSON raises ValueError.
        content = json.dumps(openai_doc())
        trace = parse_trace(content)
        self.assertEqual(trace.session_id, "oa-sess")
        with self.assertRaises(ValueError):
            parse_trace("/nonexistent/dir/trace.jsonl")

    def test_session_id_fallback_to_name_stem(self):
        import tempfile, os
        lines = [
            {"type": "assistant", "message": {"role": "assistant",
             "content": [{"type": "tool_use", "id": "1", "name": "Bash",
                          "input": {"command": "ls"}}]}}
        ]
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(json.dumps(l) for l in lines))
            trace = parse_trace(path)
            stem = Path(path).stem
            self.assertEqual(trace.session_id, stem)
        finally:
            os.unlink(path)

    def test_session_id_fallback_to_fingerprint_for_content_string(self):
        content = json.dumps([{"role": "assistant", "content": "hi"}])
        a = parse_trace(content)
        b = parse_trace(content)
        self.assertEqual(a.session_id, b.session_id)
        self.assertTrue(len(a.session_id) >= 12)

    def test_unsupported_source_type_raises(self):
        with self.assertRaises(TypeError):
            parse_trace(12345)  # type: ignore[arg-type]

    def test_missing_tool_result_yields_empty_output(self):
        content = json.dumps(
            {
                "session_id": "s",
                "messages": [
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "c1",
                                "function": {"name": "Write",
                                             "arguments": {"path": "z.py"}},
                            }
                        ],
                    }
                ],
            }
        )
        trace = parse_trace(content)
        self.assertEqual(trace.tool_events[0].output, "")
        self.assertFalse(trace.tool_events[0].is_error)

    def test_no_test_commands_means_zero_and_none(self):
        trace = parse_trace(claude_jsonl_text().replace("pytest -q", "ls"))
        self.assertEqual(trace.test_runs_count, 0)
        self.assertIsNone(trace.last_test_passed)

    def test_apply_patch_tool_paths(self):
        patch_body = (
            "*** Add File: new_a.py\n"
            "+print(1)\n"
            "*** Update File: old_b.py\n"
            "@@ -1 +1 @@\n"
            "-a\n"
            "+b\n"
        )
        content = json.dumps(
            {
                "messages": [
                    {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "p1",
                                "function": {
                                    "name": "apply_patch",
                                    "arguments": {"patch": patch_body},
                                },
                            }
                        ],
                    }
                ]
            }
        )
        trace = parse_trace(content)
        self.assertEqual(trace.files_created, {"new_a.py"})
        self.assertEqual(trace.files_modified, {"old_b.py"})

    def test_workspace_root_defaults_when_absent(self):
        content = json.dumps([{"role": "assistant", "content": "hi"}])
        trace = parse_trace(content)
        # No hardcoded /workspace: the fallback is the process cwd.
        self.assertEqual(trace.workspace_root, os.getcwd())

    def test_workspace_root_config_setting_used_when_absent(self):
        content = json.dumps([{"role": "assistant", "content": "hi"}])
        cfg = VitaConfig(workspace_root="/srv/my-app")
        trace = parse_trace(content, config=cfg)
        self.assertEqual(trace.workspace_root, "/srv/my-app")

    def test_workspace_root_metadata_beats_config_setting(self):
        content = json.dumps(
            {"session_id": "s", "workspace_root": "/trace/root",
             "messages": [{"role": "assistant", "content": "hi"}]}
        )
        cfg = VitaConfig(workspace_root="/srv/my-app")
        trace = parse_trace(content, config=cfg)
        self.assertEqual(trace.workspace_root, "/trace/root")

    def test_tool_event_arguments_never_a_string(self):
        trace = parse_trace(claude_jsonl_text())
        for event in trace.tool_events:
            self.assertIsInstance(event.arguments, dict)

    def test_duration_explicit_metadata_key_wins(self):
        doc = dict(openai_doc())
        doc["duration_s"] = 123.5
        trace = parse_trace(json.dumps(doc))
        self.assertEqual(trace.duration_s, 123.5)

    def test_is_error_false_for_success_tool_result(self):
        trace = parse_trace(claude_jsonl_text())
        git_event = self._event_by_command(trace, "git status --porcelain")
        assert git_event is not None
        self.assertFalse(git_event.is_error)

    @staticmethod
    def _event_by_command(trace, command):
        for event in trace.tool_events:
            if event.arguments.get("command") == command:
                return event
        return None


if __name__ == "__main__":
    unittest.main()
