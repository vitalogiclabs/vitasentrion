"""Unit tests for the declarative configuration file (SPEC milestone M8, P0-a).

Covers: valid TOML loading, missing file -> hardcoded defaults, explicit
--config override, custom threshold applied (guard + rules), rule
disabled / downgraded, ignore_paths, custom patterns, and validation
errors.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vitasentrion.cli import main as cli_main
from vitasentrion.config import (
    ConfigError,
    default_config,
    find_config_file,
    load_config,
    path_matches_ignore,
)
from vitasentrion.guard import evaluate_hook_payload
from vitasentrion.models import SessionTrace, Severity, ToolEvent
from vitasentrion.rules import evaluate_trace
from vitasentrion.scanner import scan_git_repo


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=str(cwd), check=True,
        capture_output=True, text=True,
    )


class ConfigLoadingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write_config(self, text: str, name: str = "vitasentrion.toml") -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    # --- defaults when no config file exists ------------------------------

    def test_missing_file_uses_defaults(self):
        cfg = load_config(start_dir=self.root)
        self.assertTrue(cfg.is_default)
        self.assertEqual(cfg.max_consecutive_edits, 3)
        self.assertEqual(cfg.state_ttl_seconds, 3600)
        self.assertEqual(cfg.ignore_paths, ())
        self.assertEqual(cfg.rule_actions, {})
        self.assertEqual(cfg.blocked_commands, ())
        self.assertEqual(cfg.secret_patterns, ())

    def test_default_config_matches_hardcoded_values(self):
        cfg = default_config()
        self.assertEqual(cfg.max_consecutive_edits, 3)
        self.assertEqual(cfg.state_ttl_seconds, 3600)

    # --- valid TOML --------------------------------------------------------

    def test_valid_toml_full_schema(self):
        self.write_config(
            """
[guard]
max_consecutive_edits = 5
state_ttl_seconds = 120
ignore_paths = [".scratch/*", "build/**"]

[rules]
R3 = "warn"
R7 = "block"
R4 = "ignore"

[custom]
blocked_commands = ["docker\\\\s+system\\\\s+prune"]
secret_patterns = ["hunter2{3,}"]
"""
        )
        cfg = load_config(start_dir=self.root)
        self.assertEqual(cfg.max_consecutive_edits, 5)
        self.assertEqual(cfg.state_ttl_seconds, 120)
        self.assertEqual(cfg.ignore_paths, (".scratch/*", "build/**"))
        self.assertEqual(
            cfg.rule_actions, {"R3": "warn", "R7": "block", "R4": "ignore"}
        )
        self.assertEqual(cfg.blocked_commands, ("docker\\s+system\\s+prune",))
        self.assertEqual(cfg.secret_patterns, ("hunter2{3,}",))
        self.assertIsNotNone(cfg.source)

    def test_search_walks_up_to_repo_root(self):
        self.write_config("[guard]\nmax_consecutive_edits = 9\n")
        _git(self.root, "init")
        nested = self.root / "a" / "b"
        nested.mkdir(parents=True)
        found = find_config_file(nested)
        self.assertEqual(found, self.root / "vitasentrion.toml")
        cfg = load_config(start_dir=nested)
        self.assertEqual(cfg.max_consecutive_edits, 9)

    def test_search_stops_at_repo_root_without_config(self):
        _git(self.root, "init")
        nested = self.root / "sub"
        nested.mkdir()
        # A config OUTSIDE the repo (in the temp parent) must not leak in.
        outer = self.root.parent / "vitasentrion.toml"
        outer.write_text("[guard]\nmax_consecutive_edits = 99\n")
        try:
            self.assertIsNone(find_config_file(nested))
            self.assertTrue(load_config(start_dir=nested).is_default)
        finally:
            outer.unlink(missing_ok=True)

    def test_explicit_config_override(self):
        path = self.write_config(
            "[guard]\nmax_consecutive_edits = 7\n", name="custom.toml"
        )
        cfg = load_config(path=path)
        self.assertEqual(cfg.max_consecutive_edits, 7)

    # --- validation errors -------------------------------------------------

    def test_explicit_missing_config_raises(self):
        with self.assertRaises(ConfigError):
            load_config(path=self.root / "nope.toml")

    def test_invalid_toml_raises(self):
        path = self.write_config("this is not = valid = toml")
        with self.assertRaises(ConfigError):
            load_config(path=path)

    def test_unknown_section_key_rule_and_action_raise(self):
        for bad in (
            "[bogus]\nx = 1\n",
            "[guard]\nnope = 1\n",
            "[rules]\nR99 = \"warn\"\n",
            "[rules]\nR3 = \"explode\"\n",
            "[guard]\nmax_consecutive_edits = 0\n",
            "[custom]\nsecret_patterns = [\"([unclosed\"]\n",
        ):
            with self.subTest(bad=bad):
                path = self.write_config(bad)
                with self.assertRaises(ConfigError):
                    load_config(path=path)

    # --- ignore-path matching ----------------------------------------------

    def test_path_matches_ignore(self):
        self.assertTrue(path_matches_ignore(".scratch/x.py", (".scratch/*",)))
        self.assertTrue(
            path_matches_ignore("/w/foo/.scratch/x.py", (".scratch/*",))
        )
        self.assertTrue(path_matches_ignore("build/out.js", ("build/*",)))
        self.assertFalse(path_matches_ignore("src/app.py", (".scratch/*",)))
        self.assertFalse(path_matches_ignore("src/app.py", ()))


class ConfigAppliedToRulesTests(unittest.TestCase):
    """The loaded config must actually change rule-engine behaviour."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _loop_trace(self, n: int = 3) -> SessionTrace:
        trace = SessionTrace(session_id="s")
        ev = ToolEvent(tool_name="read_file", arguments={"path": "a.py"})
        trace.tool_events = [
            ToolEvent(tool_name="read_file",
                      arguments={"path": "a.py", "n": i})
            for i in range(n)
        ]
        del ev
        return trace

    def test_custom_threshold_applied_in_rules(self):
        path = self.root / "vitasentrion.toml"
        path.write_text("[guard]\nmax_consecutive_edits = 4\n")
        cfg = load_config(start_dir=self.root)

        # 3 same-file calls: under default 3 R1 fires, under 4 it must not.
        trace = self._loop_trace(3)
        self.assertTrue(any(f.rule_id == "R1"
                            for f in evaluate_trace(trace).findings))
        card = evaluate_trace(trace, config=cfg)
        self.assertFalse(any(f.rule_id == "R1" for f in card.findings))

        # 4 same-file calls: fires again under threshold 4.
        card = evaluate_trace(self._loop_trace(4), config=cfg)
        self.assertTrue(any(f.rule_id == "R1" for f in card.findings))

    def test_rule_disabled_in_audit(self):
        path = self.root / "vitasentrion.toml"
        path.write_text("[rules]\nR1 = \"ignore\"\n")
        cfg = load_config(start_dir=self.root)
        trace = self._loop_trace(3)
        card = evaluate_trace(trace, config=cfg)
        self.assertFalse(any(f.rule_id == "R1" for f in card.findings))
        self.assertEqual(card.verdict, Severity.PASS)

    def test_rule_downgraded_to_warn(self):
        path = self.root / "vitasentrion.toml"
        path.write_text("[rules]\nR1 = \"warn\"\n")
        cfg = load_config(start_dir=self.root)
        trace = self._loop_trace(3)
        card = evaluate_trace(trace, config=cfg)
        r1 = [f for f in card.findings if f.rule_id == "R1"]
        self.assertEqual(len(r1), 1)
        self.assertEqual(r1[0].severity, Severity.WARN)
        self.assertEqual(card.verdict, Severity.WARN)

    def test_custom_secret_pattern_in_rules(self):
        path = self.root / "vitasentrion.toml"
        path.write_text('[custom]\nsecret_patterns = ["topsecret-\\\\w+"]\n')
        cfg = load_config(start_dir=self.root)
        trace = SessionTrace(session_id="s")
        trace.tool_events = [
            ToolEvent(tool_name="echo", arguments={"text": "topsecret-abc"})
        ]
        card = evaluate_trace(trace, config=cfg)
        self.assertTrue(any(f.rule_id == "R5" for f in card.findings))
        # Without the config the same trace is clean.
        card2 = evaluate_trace(trace)
        self.assertFalse(any(f.rule_id == "R5" for f in card2.findings))

    def test_custom_blocked_command_in_rules(self):
        path = self.root / "vitasentrion.toml"
        path.write_text('[custom]\nblocked_commands = ["docker\\\\s+system\\\\s+prune"]\n')
        cfg = load_config(start_dir=self.root)
        trace = SessionTrace(session_id="s")
        trace.tool_events = [
            ToolEvent(tool_name="terminal",
                      arguments={"command": "docker system prune -af"})
        ]
        card = evaluate_trace(trace, config=cfg)
        r4 = [f for f in card.findings if f.rule_id == "R4"]
        self.assertEqual(len(r4), 1)
        self.assertEqual(r4[0].severity, Severity.FAIL)
        self.assertFalse(any(f.rule_id == "R4"
                             for f in evaluate_trace(trace).findings))


class ConfigAppliedToGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _call(self, n: int = 1):
        return {
            "tool_name": "read_file",
            "tool_input": {"path": "a.py", "n": n},
        }

    def test_custom_threshold_applied_in_guard(self):
        path = self.root / "vitasentrion.toml"
        path.write_text("[guard]\nmax_consecutive_edits = 5\n")
        cfg = load_config(start_dir=self.root)
        for i in range(4):
            allowed, _, _ = evaluate_hook_payload(
                self._call(i), workspace_root=str(self.root),
                state_file=self.state, config=cfg,
            )
            self.assertTrue(allowed, f"call {i} should be allowed")
        allowed, reason, findings = evaluate_hook_payload(
            self._call(9), workspace_root=str(self.root),
            state_file=self.state, config=cfg,
        )
        # 5th call in a row (same path, fuzzy loop) trips at threshold 5.
        self.assertFalse(allowed)
        self.assertEqual(findings[0].rule_id, "R1")

    def test_guard_default_still_blocks_third(self):
        for i in range(2):
            allowed, _, _ = evaluate_hook_payload(
                self._call(i), workspace_root=str(self.root),
                state_file=self.state,
            )
            self.assertTrue(allowed)
        allowed, _, findings = evaluate_hook_payload(
            self._call(9), workspace_root=str(self.root),
            state_file=self.state,
        )
        self.assertFalse(allowed)
        self.assertEqual(findings[0].rule_id, "R1")

    def test_rule_ignore_lets_guard_through(self):
        path = self.root / "vitasentrion.toml"
        path.write_text("[rules]\nR1 = \"ignore\"\n")
        cfg = load_config(start_dir=self.root)
        for i in range(6):
            allowed, _, findings = evaluate_hook_payload(
                self._call(i), workspace_root=str(self.root),
                state_file=self.state, config=cfg,
            )
            self.assertTrue(allowed)
            self.assertEqual(findings, [])

    def test_rule_warn_allows_with_warn_finding(self):
        path = self.root / "vitasentrion.toml"
        path.write_text("[rules]\nR6 = \"warn\"\n")
        cfg = load_config(start_dir=self.root)
        allowed, _, findings = evaluate_hook_payload(
            {"tool_name": "terminal",
             "tool_input": {"command": "ssh user@host"}},
            workspace_root=str(self.root), state_file=self.state, config=cfg,
        )
        self.assertTrue(allowed)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.WARN)

    def test_ignore_paths_skip_guard_checks(self):
        path = self.root / "vitasentrion.toml"
        path.write_text('[guard]\nignore_paths = [".scratch/*"]\n')
        cfg = load_config(start_dir=self.root)
        for i in range(6):
            allowed, _, findings = evaluate_hook_payload(
                {"tool_name": "write_file",
                 "tool_input": {"path": ".scratch/tmp.py", "content": "x",
                                "i": i}},
                workspace_root=str(self.root),
                state_file=self.state, config=cfg,
            )
            self.assertTrue(allowed)
            self.assertEqual(findings, [])

    def test_custom_secret_pattern_blocks_guard(self):
        path = self.root / "vitasentrion.toml"
        path.write_text('[custom]\nsecret_patterns = ["topsecret-\\\\w+"]\n')
        cfg = load_config(start_dir=self.root)
        allowed, _, findings = evaluate_hook_payload(
            {"tool_name": "terminal",
             "tool_input": {"command": "echo topsecret-abc"}},
            workspace_root=str(self.root), state_file=self.state, config=cfg,
        )
        self.assertFalse(allowed)
        self.assertEqual(findings[0].rule_id, "R5")


class ConfigAppliedToScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        _git(self.root, "init")
        _git(self.root, "config", "user.email", "t@example.com")
        _git(self.root, "config", "user.name", "Test")
        (self.root / "keep.py").write_text("x = 1\n")
        _git(self.root, "add", ".")
        _git(self.root, "commit", "-m", "init")

    def tearDown(self):
        self.tmp.cleanup()

    def test_ignore_paths_drop_files_from_scan(self):
        (self.root / "debug_x.py").write_text("print(1)\n")
        (self.root / "notes.md").write_text("hello\n")
        cfg_path = self.root / "vitasentrion.toml"
        cfg_path.write_text('[guard]\nignore_paths = ["*.md"]\n')
        cfg = load_config(start_dir=self.root)
        trace = scan_git_repo(self.root, config=cfg)
        self.assertIn("debug_x.py", trace.files_created)
        self.assertNotIn("notes.md", trace.files_created)
        self.assertNotIn("notes.md", trace.uncommitted_files)
        # Without config both show up.
        trace2 = scan_git_repo(self.root)
        self.assertIn("notes.md", trace2.files_created)


class ConfigCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _loop_trace_dict() -> dict:
        # 3 identical read_file tool_calls -> R1 fuzzy loop (same tool +
        # same path), in the messages format parse_trace understands.
        call = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": f"tc{i}",
                    "function": {
                        "name": "read_file",
                        "arguments": json.dumps({"path": "a.py"}),
                    },
                }
                for i in range(3)
            ],
        }
        return {"session_id": "s", "messages": [call]}

    def test_audit_uses_config_from_target_dir(self):
        trace = self._loop_trace_dict()
        trace_path = self.root / "trace.json"
        trace_path.write_text(json.dumps(trace))
        # No config yet: R1 fires -> exit 1.
        self.assertEqual(cli_main(["audit", str(trace_path)]), 1)
        # Auto-discovered config in the target dir: clean -> exit 0.
        (self.root / "vitasentrion.toml").write_text(
            "[rules]\nR1 = \"ignore\"\n"
        )
        self.assertEqual(cli_main(["audit", str(trace_path)]), 0)

    def test_audit_explicit_config_override(self):
        trace = self._loop_trace_dict()
        trace_path = self.root / "trace.json"
        trace_path.write_text(json.dumps(trace))
        cfg_path = self.root / "other.toml"
        cfg_path.write_text("[rules]\nR1 = \"ignore\"\n")
        self.assertEqual(
            cli_main(["audit", str(trace_path), "--config", str(cfg_path)]), 0
        )

    def test_invalid_config_exits_with_error(self):
        trace_path = self.root / "trace.json"
        trace_path.write_text(json.dumps({"session_id": "s"}))
        bad = self.root / "bad.toml"
        bad.write_text("[rules]\nR3 = \"explode\"\n")
        self.assertEqual(
            cli_main(["audit", str(trace_path), "--config", str(bad)]), 1
        )


# ---------------------------------------------------------------------------
# [guard] workspace_root / allow_hosts / allow_sudo / taint_seconds
# ---------------------------------------------------------------------------

class GuardSettingsConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write_config(self, text: str, name: str = "vitasentrion.toml") -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_new_guard_defaults(self):
        cfg = load_config(start_dir=self.root)
        self.assertIsNone(cfg.workspace_root)
        self.assertEqual(cfg.allow_hosts, ())
        self.assertEqual(cfg.allow_sudo, ())
        self.assertEqual(cfg.taint_seconds, 300)

    def test_new_guard_keys_valid(self):
        self.write_config(
            """
[guard]
workspace_root = "/srv/app/data/"
allow_hosts = ["10.1.2.3:8080", "Proxy.Example.COM:22"]
allow_sudo = ["/usr/local/sbin/hermes-apt-install"]
taint_seconds = 60
"""
        )
        cfg = load_config(start_dir=self.root)
        self.assertEqual(cfg.workspace_root, "/srv/app/data")
        self.assertEqual(
            cfg.allow_hosts, ("10.1.2.3:8080", "proxy.example.com:22")
        )
        self.assertEqual(
            cfg.allow_sudo, ("/usr/local/sbin/hermes-apt-install",)
        )
        self.assertEqual(cfg.taint_seconds, 60)

    def test_taint_seconds_zero_allowed(self):
        self.write_config("[guard]\ntaint_seconds = 0\n")
        self.assertEqual(load_config(start_dir=self.root).taint_seconds, 0)

    def test_workspace_root_relative_rejected(self):
        self.write_config('[guard]\nworkspace_root = "srv/app"\n')
        with self.assertRaises(ConfigError):
            load_config(start_dir=self.root)

    def test_workspace_root_non_string_rejected(self):
        self.write_config("[guard]\nworkspace_root = 5\n")
        with self.assertRaises(ConfigError):
            load_config(start_dir=self.root)

    def test_allow_hosts_without_port_rejected(self):
        self.write_config('[guard]\nallow_hosts = ["127.0.0.1"]\n')
        with self.assertRaises(ConfigError):
            load_config(start_dir=self.root)

    def test_allow_hosts_bad_port_rejected(self):
        self.write_config('[guard]\nallow_hosts = ["host:notaport"]\n')
        with self.assertRaises(ConfigError):
            load_config(start_dir=self.root)

    def test_allow_sudo_relative_path_rejected(self):
        self.write_config('[guard]\nallow_sudo = ["usr/bin/mytool"]\n')
        with self.assertRaises(ConfigError):
            load_config(start_dir=self.root)

    def test_taint_seconds_negative_rejected(self):
        self.write_config("[guard]\ntaint_seconds = -1\n")
        with self.assertRaises(ConfigError):
            load_config(start_dir=self.root)

    def test_taint_seconds_bool_rejected(self):
        self.write_config("[guard]\ntaint_seconds = true\n")
        with self.assertRaises(ConfigError):
            load_config(start_dir=self.root)


# ---------------------------------------------------------------------------
# [guard].state_dir + VITASENTRION_STATE_DIR fallback
# ---------------------------------------------------------------------------

class StateDirConfigTests(unittest.TestCase):
    ENV = "VITASENTRION_STATE_DIR"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._env = mock.patch.dict(os.environ)
        self._env.start()
        os.environ.pop(self.ENV, None)
        self.addCleanup(self._env.stop)

    def write_config(self, text: str, name: str = "vitasentrion.toml") -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_state_dir_default_none(self):
        cfg = load_config(start_dir=self.root)
        self.assertIsNone(cfg.state_dir)

    def test_state_dir_key_parsed_and_stripped(self):
        self.write_config('[guard]\nstate_dir = " .vitasentrion "\n')
        cfg = load_config(start_dir=self.root)
        self.assertEqual(cfg.state_dir, ".vitasentrion")

    def test_state_dir_empty_rejected(self):
        self.write_config('[guard]\nstate_dir = "   "\n')
        with self.assertRaises(ConfigError):
            load_config(start_dir=self.root)

    def test_state_dir_non_string_rejected(self):
        self.write_config("[guard]\nstate_dir = 5\n")
        with self.assertRaises(ConfigError):
            load_config(start_dir=self.root)

    def test_env_fallback_when_key_absent(self):
        os.environ[self.ENV] = "/srv/env-state"
        cfg = load_config(start_dir=self.root)
        self.assertEqual(cfg.state_dir, "/srv/env-state")

    def test_config_value_wins_over_env(self):
        os.environ[self.ENV] = "/srv/env-state"
        self.write_config('[guard]\nstate_dir = ".vs"\n')
        cfg = load_config(start_dir=self.root)
        self.assertEqual(cfg.state_dir, ".vs")

    def test_default_config_picks_up_env(self):
        os.environ[self.ENV] = "/srv/env-state"
        self.assertEqual(default_config().state_dir, "/srv/env-state")

    def test_default_config_none_without_env(self):
        self.assertIsNone(default_config().state_dir)

    def test_env_var_empty_means_none(self):
        os.environ[self.ENV] = "   "
        self.assertIsNone(load_config(start_dir=self.root).state_dir)


if __name__ == "__main__":
    unittest.main()
