"""Unit tests for secret redaction mode (SPEC milestone M10, P2-a).

Covers: the redaction helper (typed placeholders, overlap order, custom
patterns), both config switches ([guard].redact_secrets, [rules]
R5="redact") and their validation, the guard redact path (call allowed
with a WARN finding, events.jsonl and state file never contain plaintext
credentials, hash chain still verifies), the audit/scorecard path
(finding details and rendered reports show only redacted snippets), and
that the default (no config) behaviour is unchanged.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vitasentrion.cli import main as cli_main
from vitasentrion.config import ConfigError, load_config, redaction_enabled
from vitasentrion.guard import evaluate_hook_payload, verify_events_chain
from vitasentrion.models import SessionTrace, Severity, ToolEvent
from vitasentrion.reporters import render_scorecard
from vitasentrion.rules import (
    evaluate_trace,
    redact_args,
    redact_text,
    secret_token_type,
)
from vitasentrion.scanner import scan_git_repo

OPENAI_KEY = "sk-" + "aB3xK9qZ0mLp7Yt2Wu8Vd"  # 20+ chars after sk-
AWS_KEY = "AKIA" + "A1B2C3D4E5F6G7H8"
ANTHROPIC_KEY = "sk-ant-" + "Zr4t9Yq0mXp7Wk2Ld8Bn5Hs"
GITHUB_TOKEN = "ghp_" + "aB3xK9qZ0mLp7Yt2Wu8Vd4Fg"

SECRET_TOML = '[guard]\nredact_secrets = true\n'
RULE_TOML = '[rules]\nR5 = "redact"\n'


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=str(cwd), check=True,
        capture_output=True, text=True,
    )


class RedactionHelperTests(unittest.TestCase):
    def test_typed_placeholders(self):
        text = f"key={OPENAI_KEY} aws={AWS_KEY} gh={GITHUB_TOKEN}"
        out, types = redact_text(text)
        self.assertNotIn(OPENAI_KEY, out)
        self.assertNotIn(AWS_KEY, out)
        self.assertNotIn(GITHUB_TOKEN, out)
        self.assertIn("[REDACTED:OPENAI_KEY]", out)
        self.assertIn("[REDACTED:AWS_KEY]", out)
        self.assertIn("[REDACTED:GITHUB_TOKEN]", out)
        self.assertEqual(types, ["OPENAI_KEY", "AWS_KEY", "GITHUB_TOKEN"])

    def test_anthropic_claimed_before_openai(self):
        out, types = redact_text(f"token {ANTHROPIC_KEY}")
        self.assertEqual(out, "token [REDACTED:ANTHROPIC_KEY]")
        self.assertEqual(types, ["ANTHROPIC_KEY"])

    def test_private_key_marker(self):
        out, types = redact_text("-----BEGIN RSA PRIVATE KEY-----\nabc")
        self.assertIn("[REDACTED:PRIVATE_KEY]", out)
        self.assertEqual(types, ["PRIVATE_KEY"])

    def test_no_secret_untouched(self):
        out, types = redact_text("echo hello world")
        self.assertEqual(out, "echo hello world")
        self.assertEqual(types, [])

    def test_custom_pattern_generic_token(self):
        from vitasentrion.config import VitaConfig

        cfg = VitaConfig(secret_patterns=(r"tok_[A-Z0-9]{8}",))
        out, types = redact_text("use tok_ABCDEFG1 now", cfg)
        self.assertEqual(out, "use [REDACTED:GENERIC_SECRET] now")
        self.assertEqual(types, ["GENERIC_SECRET"])

    def test_secret_token_type_lookup(self):
        self.assertEqual(secret_token_type(r"AKIA[0-9A-Z]{16}"), "AWS_KEY")
        self.assertEqual(secret_token_type(r"whatever"), "GENERIC_SECRET")

    def test_redact_args_deep(self):
        args = {
            "command": f"export K={OPENAI_KEY}",
            "nested": {"list": [f"aws {AWS_KEY}", 42, None]},
        }
        out = redact_args(args)
        blob = json.dumps(out)
        self.assertNotIn(OPENAI_KEY, blob)
        self.assertNotIn(AWS_KEY, blob)
        self.assertIn("[REDACTED:OPENAI_KEY]", blob)
        self.assertIn("[REDACTED:AWS_KEY]", blob)
        self.assertEqual(out["nested"]["list"][1], 42)
        self.assertIsNone(out["nested"]["list"][2])
        # input not mutated
        self.assertIn(OPENAI_KEY, args["command"])


class ConfigSwitchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write_config(self, text: str) -> Path:
        path = self.root / "vitasentrion.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_guard_switch_enables(self):
        cfg = load_config(path=self.write_config(SECRET_TOML))
        self.assertTrue(cfg.redact_secrets)
        self.assertTrue(redaction_enabled(cfg))

    def test_rule_switch_enables(self):
        cfg = load_config(path=self.write_config(RULE_TOML))
        self.assertEqual(cfg.rule_actions["R5"], "redact")
        self.assertTrue(redaction_enabled(cfg))

    def test_default_off(self):
        cfg = load_config(start_dir=self.root)
        self.assertFalse(cfg.redact_secrets)
        self.assertFalse(redaction_enabled(cfg))
        self.assertFalse(redaction_enabled(None))

    def test_non_boolean_rejected(self):
        with self.assertRaises(ConfigError):
            load_config(path=self.write_config('[guard]\nredact_secrets = "yes"\n'))

    def test_redact_only_valid_for_r5(self):
        with self.assertRaises(ConfigError):
            load_config(path=self.write_config('[rules]\nR4 = "redact"\n'))


class GuardRedactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "state.json"
        (self.root / "vitasentrion.toml").write_text(SECRET_TOML, encoding="utf-8")
        self.cfg = load_config(path=self.root / "vitasentrion.toml")

    def tearDown(self):
        self.tmp.cleanup()

    def _payload(self, command: str) -> dict:
        return {"name": "terminal", "arguments": {"command": command}}

    def _events_text(self) -> str:
        events = self.root / "state.events.jsonl"
        return events.read_text(encoding="utf-8") if events.is_file() else ""

    def test_call_allowed_with_warn_finding(self):
        allowed, reason, findings = evaluate_hook_payload(
            self._payload(f"echo {OPENAI_KEY}"),
            state_file=self.state,
            workspace_root=str(self.root),
            config=self.cfg,
        )
        self.assertTrue(allowed)
        r5 = [f for f in findings if f.rule_id == "R5"]
        self.assertEqual(len(r5), 1)
        self.assertIs(r5[0].severity, Severity.WARN)
        joined = " ".join(r5[0].details)
        self.assertIn("[REDACTED:OPENAI_KEY]", joined)
        self.assertNotIn(OPENAI_KEY, joined)

    def test_events_log_never_contains_plaintext_secret(self):
        evaluate_hook_payload(
            self._payload(f"export AWS={AWS_KEY}; echo {OPENAI_KEY}"),
            state_file=self.state,
            workspace_root=str(self.root),
            config=self.cfg,
        )
        text = self._events_text()
        self.assertTrue(text)
        self.assertNotIn(AWS_KEY, text)
        self.assertNotIn(OPENAI_KEY, text)
        self.assertIn("[REDACTED:AWS_KEY]", text)
        self.assertIn("[REDACTED:OPENAI_KEY]", text)
        # the hash chain still verifies over redacted lines
        self.assertTrue(verify_events_chain(self.root / "state.events.jsonl") == [])

    def test_state_file_never_contains_plaintext_secret(self):
        evaluate_hook_payload(
            self._payload(f"echo {OPENAI_KEY}"),
            state_file=self.state,
            workspace_root=str(self.root),
            config=self.cfg,
        )
        if self.state.is_file():
            self.assertNotIn(OPENAI_KEY, self.state.read_text(encoding="utf-8"))

    def test_rule_switch_same_behaviour(self):
        cfg = load_config(path=self._write_rule_toml())
        allowed, _, findings = evaluate_hook_payload(
            self._payload(f"echo {OPENAI_KEY}"),
            state_file=self.state,
            workspace_root=str(self.root),
            config=cfg,
        )
        self.assertTrue(allowed)
        self.assertEqual(
            [f.rule_id for f in findings if f.severity is Severity.WARN],
            ["R5"],
        )

    def _write_rule_toml(self) -> Path:
        path = self.root / "r5.toml"
        path.write_text(RULE_TOML, encoding="utf-8")
        return path

    def test_default_config_still_blocks(self):
        allowed, reason, findings = evaluate_hook_payload(
            self._payload(f"echo {OPENAI_KEY}"),
            state_file=self.state,
            workspace_root=str(self.root),
        )
        self.assertFalse(allowed)
        self.assertIn("secret leakage", reason)
        self.assertTrue(any(f.severity is Severity.FAIL for f in findings))

    def test_redact_does_not_suppress_other_rules(self):
        # R4 still hard-blocks even with redaction on.
        allowed, reason, _ = evaluate_hook_payload(
            self._payload(f"git reset --hard # {OPENAI_KEY}"),
            state_file=self.state,
            workspace_root=str(self.root),
            config=self.cfg,
        )
        self.assertFalse(allowed)
        self.assertIn("destructive", reason)

    def test_cli_guard_exit_zero(self):
        payload = json.dumps(self._payload(f"echo {OPENAI_KEY}"))
        result = subprocess.run(
            [sys.executable, "-m", "vitasentrion.cli", "guard",
             "--state-file", str(self.state), "--config",
             str(self.root / "vitasentrion.toml")],
            input=payload, capture_output=True, text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(OPENAI_KEY, self._events_text())


class AuditRedactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _trace(self) -> SessionTrace:
        return SessionTrace(
            session_id="s1",
            tool_events=[
                ToolEvent(tool_name="terminal",
                          arguments={"command": f"echo {OPENAI_KEY}"}),
            ],
            leaked_secrets=[f"aws={AWS_KEY}", "BEGIN PRIVATE KEY"],
        )

    def _cfg(self):
        path = self.root / "vitasentrion.toml"
        path.write_text(SECRET_TOML, encoding="utf-8")
        return load_config(path=path)

    def test_finding_is_warn_with_redacted_details(self):
        card = evaluate_trace(self._trace(), config=self._cfg())
        r5 = [f for f in card.findings if f.rule_id == "R5"]
        self.assertEqual(len(r5), 1)
        self.assertIs(r5[0].severity, Severity.WARN)
        joined = " ".join(r5[0].details)
        self.assertNotIn(OPENAI_KEY, joined)
        self.assertNotIn(AWS_KEY, joined)
        self.assertIn("[REDACTED:OPENAI_KEY]", joined)
        self.assertIn("[REDACTED:AWS_KEY]", joined)
        # scanner-style loose match falls back to the generic placeholder
        self.assertIn("[REDACTED:GENERIC_SECRET]", joined)
        self.assertNotEqual(card.verdict, Severity.FAIL)

    def test_rendered_reports_have_no_plaintext_secret(self):
        card = evaluate_trace(self._trace(), config=self._cfg())
        for fmt in ("console", "markdown", "json"):
            rendered = render_scorecard(card, fmt)
            self.assertNotIn(OPENAI_KEY, rendered, fmt)
            self.assertNotIn(AWS_KEY, rendered, fmt)

    def test_default_audit_unchanged(self):
        card = evaluate_trace(self._trace())
        r5 = [f for f in card.findings if f.rule_id == "R5"]
        self.assertEqual(len(r5), 1)
        self.assertIs(r5[0].severity, Severity.FAIL)

    def test_scanner_leaked_secrets_masked_in_audit(self):
        repo = self.root / "repo"
        repo.mkdir()
        _git(repo, "init")
        _git(repo, "config", "user.email", "t@t")
        _git(repo, "config", "user.name", "t")
        # Both files untracked: scan_git_repo secret-scans their content.
        (repo / "app.py").write_text(f"KEY = '{OPENAI_KEY}'\n", encoding="utf-8")
        (repo / "extra.py").write_text(f"AWS = '{AWS_KEY}'\n", encoding="utf-8")

        cfg = self._cfg()
        trace = scan_git_repo(repo, config=cfg)
        # the trace itself still carries the raw values (data source);
        # the *reported* findings must not.
        card = evaluate_trace(trace, config=cfg)
        r5 = [f for f in card.findings if f.rule_id == "R5"]
        self.assertTrue(r5)
        joined = " ".join(r5[0].details)
        self.assertNotIn(OPENAI_KEY, joined)
        self.assertNotIn(AWS_KEY, joined)
        self.assertIn("[REDACTED:OPENAI_KEY]", joined)
        self.assertIn("[REDACTED:AWS_KEY]", joined)


if __name__ == "__main__":
    unittest.main()
