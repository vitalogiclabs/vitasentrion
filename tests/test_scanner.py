"""Unit tests for vitasentrion.scanner (SPEC milestone M3).

Covers the pure parsing helpers (``_parse_porcelain``, ``_parse_diff``,
``_find_secrets``, ``_is_test_file``, ``detect_scratch_files``) with crafted
inputs, and the real entry points (``scan_git_repo``, ``audit_git_repo``)
against actual temporary git repositories built via ``subprocess``.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Optional

from vitasentrion.models import Finding, Scorecard, SessionTrace, Severity
from vitasentrion.scanner import (
    _clean_path,
    _find_secrets,
    _is_test_file,
    _parse_diff,
    _parse_porcelain,
    _scan_file_for_secrets,
    _strip_ab,
    audit_git_repo,
    detect_scratch_files,
    scan_git_repo,
)

# ---------------------------------------------------------------------------
# Synthetic, non-real secret fixtures (no genuine credential material).
# ---------------------------------------------------------------------------
FAKE_AWS = "AKIA0123456789ABCDEF"            # AKIA + 16 x [0-9A-Z]
FAKE_OPENAI = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"  # sk- + 24 x [A-Za-z0-9]
FAKE_GITHUB = "ghp_ABCDEFGHIJKLMNOPQRST"     # ghp_ + 20 x [A-Za-z0-9]
FAKE_ANTHROPIC = "sk-ant-" + "A1" * 12       # sk-ant- + 24 x [A-Za-z0-9_]
FAKE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"

MAIN = "def add(a, b):\n    return a + b\n"

TEST = (
    "import unittest\n"
    "from main import add\n"
    "\n"
    "class TestAdd(unittest.TestCase):\n"
    "    def test_add(self):\n"
    "        self.assertEqual(add(1, 2), 3)\n"
    "        assert add(2, 2) == 4\n"
)


# ---------------------------------------------------------------------------
# Git repository helpers (hermetic: isolate from any user/global git config).
# ---------------------------------------------------------------------------

def _git(args, cwd, check: bool = True) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["HOME"] = str(cwd)
    env["GIT_TERMINAL_PROMPT"] = "0"
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=env,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {args} failed: {proc.stderr}")
    return proc


def _make_repo(base_files: Dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp(prefix="vitascan_"))
    _git(["init"], d)
    _git(["config", "user.name", "VitaSentrion Test"], d)
    _git(["config", "user.email", "test@vitasentrion.local"], d)
    for rel, content in base_files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    _git(["add", "-A"], d)
    _git(["commit", "-m", "initial commit"], d)
    return d


# ---------------------------------------------------------------------------
# Pure helper: _parse_porcelain
# ---------------------------------------------------------------------------

class TestParsePorcelain(unittest.TestCase):
    def test_untracked_is_created_and_uncommitted(self):
        modified, created, uncommitted = _parse_porcelain("?? new.py")
        self.assertEqual(modified, set())
        self.assertEqual(created, {"new.py"})
        self.assertEqual(uncommitted, {"new.py"})

    def test_unstaged_modified(self):
        modified, created, uncommitted = _parse_porcelain(" M main.py")
        self.assertEqual(modified, {"main.py"})
        self.assertEqual(created, set())
        self.assertEqual(uncommitted, {"main.py"})

    def test_staged_add_is_created(self):
        modified, created, uncommitted = _parse_porcelain("A  new.py")
        self.assertEqual(modified, set())
        self.assertEqual(created, {"new.py"})
        self.assertEqual(uncommitted, {"new.py"})

    def test_staged_modified(self):
        modified, created, uncommitted = _parse_porcelain("M  main.py")
        self.assertEqual(modified, {"main.py"})
        self.assertEqual(created, set())
        self.assertEqual(uncommitted, {"main.py"})

    def test_staged_deletion_is_uncommitted_only(self):
        modified, created, uncommitted = _parse_porcelain("D  gone.py")
        self.assertEqual(created, set())
        self.assertEqual(uncommitted, {"gone.py"})

    def test_rename_uses_new_path(self):
        modified, created, uncommitted = _parse_porcelain(
            "R  old.py -> new.py"
        )
        self.assertEqual(uncommitted, {"new.py"})

    def test_quoted_path_is_unquoted(self):
        modified, created, uncommitted = _parse_porcelain('?? "my file.py"')
        self.assertEqual(created, {"my file.py"})

    def test_multiple_lines(self):
        modified, created, uncommitted = _parse_porcelain(
            " M a.py\n?? b.py\nA  c.py\n"
        )
        self.assertEqual(modified, {"a.py"})
        self.assertEqual(created, {"b.py", "c.py"})
        self.assertEqual(uncommitted, {"a.py", "b.py", "c.py"})

    def test_empty_output(self):
        modified, created, uncommitted = _parse_porcelain("")
        self.assertEqual(modified, set())
        self.assertEqual(created, set())
        self.assertEqual(uncommitted, set())


# ---------------------------------------------------------------------------
# Pure helper: _parse_diff
# ---------------------------------------------------------------------------

class TestParseDiff(unittest.TestCase):
    def test_weakened_assertion_in_test_file(self):
        diff = (
            "diff --git a/tests/test_main.py b/tests/test_main.py\n"
            "--- a/tests/test_main.py\n"
            "+++ b/tests/test_main.py\n"
            "@@ -4,4 +4,3 @@\n"
            "     def test_add(self):\n"
            "         self.assertEqual(add(1, 2), 3)\n"
            "-        assert add(2, 2) == 4\n"
        )
        weakened, secrets = _parse_diff(diff)
        self.assertEqual(weakened, 1)
        self.assertEqual(secrets, [])

    def test_deleted_assert_in_non_test_file_not_counted(self):
        diff = (
            "diff --git a/main.py b/main.py\n"
            "--- a/main.py\n"
            "+++ b/main.py\n"
            "@@ -1 +1 @@\n"
            "-assert something_happens()\n"
            "+pass\n"
        )
        weakened, secrets = _parse_diff(diff)
        self.assertEqual(weakened, 0)
        self.assertEqual(secrets, [])

    def test_deleted_non_assert_line_not_counted(self):
        diff = (
            "--- a/tests/test_x.py\n"
            "+++ b/tests/test_x.py\n"
            "@@ -1 +1 @@\n"
            "-    x = 5\n"
            "+    x = 6\n"
        )
        weakened, secrets = _parse_diff(diff)
        self.assertEqual(weakened, 0)

    def test_multiple_markers_each_counted(self):
        diff = (
            "--- a/tests/test_y.py\n"
            "+++ b/tests/test_y.py\n"
            "@@ -1,3 +1 @@\n"
            "-        self.assertGreater(a, 0)\n"
            "-        self.expect(value)\n"
            "-        expect(value).toBe(1)\n"
        )
        # self.assertGreater has "self.assert", "expect(" matches the expect
        # line, "toBe(" matches the last line -> 3 total.
        weakened, secrets = _parse_diff(diff)
        self.assertEqual(weakened, 3)

    def test_leaked_secrets_in_added_lines(self):
        diff = (
            "--- a/main.py\n"
            "+++ b/main.py\n"
            "@@ -1,0 +2,2 @@\n"
            f'+AWS_KEY = "{FAKE_AWS}"\n'
            f'+token = "{FAKE_OPENAI}"\n'
        )
        weakened, secrets = _parse_diff(diff)
        self.assertEqual(weakened, 0)
        self.assertIn(FAKE_AWS, secrets)
        self.assertIn(FAKE_OPENAI, secrets)
        self.assertEqual(len(secrets), 2)

    def test_secret_removed_line_not_counted(self):
        # A secret on a *deleted* line is not a leak in the new state.
        diff = (
            "--- a/main.py\n"
            "+++ b/main.py\n"
            "@@ -1,1 +1 @@\n"
            f'-AWS_KEY = "{FAKE_AWS}"\n'
            '+AWS_KEY = ""\n'
        )
        weakened, secrets = _parse_diff(diff)
        self.assertEqual(secrets, [])

    def test_diff_header_lines_never_counted(self):
        # The +++/--- headers themselves must not be parsed as content.
        diff = "+++ b/added.py\n--- a/added.py\n+content = 1\n"
        weakened, secrets = _parse_diff(diff)
        self.assertEqual(weakened, 0)
        self.assertEqual(secrets, [])

    def test_no_changes(self):
        self.assertEqual(_parse_diff(""), (0, []))


# ---------------------------------------------------------------------------
# Pure helper: _find_secrets
# ---------------------------------------------------------------------------

class TestFindSecrets(unittest.TestCase):
    def test_aws(self):
        self.assertIn(FAKE_AWS, _find_secrets(f'k = "{FAKE_AWS}"'))

    def test_openai(self):
        self.assertIn(FAKE_OPENAI, _find_secrets(f"k = '{FAKE_OPENAI}'"))

    def test_anthropic(self):
        self.assertIn(FAKE_ANTHROPIC, _find_secrets(f"k = {FAKE_ANTHROPIC}"))

    def test_github(self):
        self.assertIn(FAKE_GITHUB, _find_secrets(f"k = {FAKE_GITHUB}"))

    def test_private_key_header(self):
        self.assertIn(
            "BEGIN RSA PRIVATE KEY", _find_secrets(FAKE_KEY_HEADER)
        )

    def test_no_match(self):
        self.assertEqual(_find_secrets("nothing sensitive here"), [])

    def test_short_sk_not_matched(self):
        self.assertEqual(_find_secrets("sk-abc123"), [])

    def test_lowercase_akia_not_matched(self):
        self.assertEqual(_find_secrets("akia0123456789abcdef"), [])

    def test_ghp_too_short_not_matched(self):
        self.assertEqual(_find_secrets("ghp_short"), [])

    def test_dedup_does_not_double_count(self):
        # A single AWS key on a line must be reported exactly once.
        self.assertEqual(_find_secrets(FAKE_AWS), [FAKE_AWS])


# ---------------------------------------------------------------------------
# Pure helper: _scan_file_for_secrets
# ---------------------------------------------------------------------------

class TestScanFileForSecrets(unittest.TestCase):
    def test_scans_whole_file_content(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "new.py"
            p.write_text(
                f'AWS_KEY = "{FAKE_AWS}"\n'
                f"token = '{FAKE_OPENAI}'\n"
            )
            self.assertEqual(_scan_file_for_secrets(p), [FAKE_AWS, FAKE_OPENAI])

    def test_no_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "clean.py"
            p.write_text("x = 1\ny = 2\n")
            self.assertEqual(_scan_file_for_secrets(p), [])

    def test_dedup_within_file(self):
        # The same secret on multiple lines is reported once.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "dup.py"
            p.write_text(f'a = "{FAKE_GITHUB}"\nb = "{FAKE_GITHUB}"\n')
            self.assertEqual(_scan_file_for_secrets(p), [FAKE_GITHUB])

    def test_missing_file_yields_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(
                _scan_file_for_secrets(Path(d) / "nope.py"), []
            )


# ---------------------------------------------------------------------------
# Pure helper: _is_test_file / _strip_ab / _clean_path
# ---------------------------------------------------------------------------

class TestPathHelpers(unittest.TestCase):
    def test_is_test_file_true(self):
        for p in ("tests/test_main.py", "src/testutils.py", "TEST_CASE.md"):
            self.assertTrue(_is_test_file(p), p)

    def test_is_test_file_false(self):
        for p in ("main.py", "integrate.py", "util.py"):
            self.assertFalse(_is_test_file(p), p)

    def test_strip_ab(self):
        self.assertEqual(_strip_ab("a/tests/test_x.py"), "tests/test_x.py")
        self.assertEqual(_strip_ab("b/src/main.py"), "src/main.py")
        self.assertEqual(_strip_ab("src/main.py"), "src/main.py")

    def test_clean_path_unquotes(self):
        self.assertEqual(_clean_path('"my file.py"'), "my file.py")
        self.assertEqual(_clean_path("plain.py"), "plain.py")


# ---------------------------------------------------------------------------
# Pure helper: detect_scratch_files
# ---------------------------------------------------------------------------

class TestDetectScratchFiles(unittest.TestCase):
    def test_matches_all_four_patterns(self):
        created = {
            "debug_foo.py",
            "temp_x.py",
            "test_fixed.py",
            "final_verification.py",
            "main.py",
            "test_main.py",
        }
        self.assertEqual(
            detect_scratch_files(created),
            {
                "debug_foo.py",
                "temp_x.py",
                "test_fixed.py",
                "final_verification.py",
            },
        )

    def test_subdirectory_uses_basename(self):
        self.assertEqual(
            detect_scratch_files({"pkg/debug_run.py"}), {"pkg/debug_run.py"}
        )

    def test_non_python_and_close_names_not_matched(self):
        created = {
            "debug_foo.js",     # not .py
            "debugging.py",     # debug + no underscore run
            "temperature.py",   # temp + no underscore
            "test_foo.py",      # test file, not a scratch name
        }
        self.assertEqual(detect_scratch_files(created), set())

    def test_empty(self):
        self.assertEqual(detect_scratch_files(set()), set())


# ---------------------------------------------------------------------------
# Integration: scan_git_repo against real git repositories
# ---------------------------------------------------------------------------

class TestScanGitRepo(unittest.TestCase):
    def setUp(self) -> None:
        self._repo: Optional[Path] = None

    def tearDown(self) -> None:
        if self._repo is not None:
            shutil.rmtree(self._repo, ignore_errors=True)

    def _build_repo(self, base_files: Dict[str, str]) -> Path:
        self._repo = _make_repo(base_files)
        return self._repo

    def test_clean_repo(self):
        repo = self._build_repo({"main.py": MAIN, "tests/test_main.py": TEST})
        trace = scan_git_repo(repo)
        self.assertIsInstance(trace, SessionTrace)
        self.assertEqual(trace.files_modified, set())
        self.assertEqual(trace.files_created, set())
        self.assertEqual(trace.uncommitted_files, set())
        self.assertEqual(trace.weakened_assertions, 0)
        self.assertEqual(trace.leaked_secrets, [])
        self.assertEqual(str(repo), trace.session_id)
        self.assertEqual(str(repo), trace.workspace_root)

    def test_modified_non_test_file(self):
        repo = self._build_repo({"main.py": MAIN, "tests/test_main.py": TEST})
        (repo / "main.py").write_text(MAIN + "def sub(a, b):\n    return a - b\n")
        trace = scan_git_repo(repo)
        self.assertIn("main.py", trace.files_modified)
        self.assertIn("main.py", trace.uncommitted_files)
        self.assertNotIn("main.py", trace.files_created)
        self.assertEqual(trace.weakened_assertions, 0)
        self.assertEqual(trace.leaked_secrets, [])

    def test_weakened_assertion_in_test_file(self):
        repo = self._build_repo({"main.py": MAIN, "tests/test_main.py": TEST})
        # Drop the trailing `assert` line from the test file.
        (repo / "tests/test_main.py").write_text(
            "import unittest\n"
            "from main import add\n"
            "\n"
            "class TestAdd(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        self.assertEqual(add(1, 2), 3)\n"
        )
        trace = scan_git_repo(repo)
        self.assertIn("tests/test_main.py", trace.files_modified)
        self.assertGreaterEqual(trace.weakened_assertions, 1)

    def test_leaked_secret_in_added_line(self):
        repo = self._build_repo({"main.py": MAIN})
        (repo / "main.py").write_text(MAIN + f'AWS_KEY = "{FAKE_AWS}"\n')
        trace = scan_git_repo(repo)
        self.assertIn("main.py", trace.files_modified)
        self.assertEqual(len(trace.leaked_secrets), 1)
        self.assertEqual(trace.leaked_secrets[0], FAKE_AWS)

    def test_multiple_secrets_deduped(self):
        repo = self._build_repo({"main.py": MAIN})
        (repo / "main.py").write_text(
            MAIN + f'A = "{FAKE_AWS}"\nB = "{FAKE_OPENAI}"\n'
        )
        trace = scan_git_repo(repo)
        self.assertEqual(set(trace.leaked_secrets), {FAKE_AWS, FAKE_OPENAI})

    def test_untracked_scratch_files_are_created(self):
        repo = self._build_repo({"main.py": MAIN})
        (repo / "debug_foo.py").write_text("x = 1\n")
        (repo / "test_fixed.py").write_text("y = 2\n")
        (repo / "not_scratch.py").write_text("z = 3\n")
        trace = scan_git_repo(repo)
        self.assertEqual(
            trace.files_created,
            {"debug_foo.py", "test_fixed.py", "not_scratch.py"},
        )
        self.assertEqual(trace.uncommitted_files, trace.files_created)
        self.assertEqual(
            detect_scratch_files(trace.files_created),
            {"debug_foo.py", "test_fixed.py"},
        )

    def test_untracked_file_with_secrets_is_detected(self):
        # Untracked files never appear in ``git diff``, so their content
        # must be scanned directly.
        repo = self._build_repo({"main.py": MAIN})
        (repo / "config.py").write_text(
            f'AWS_KEY = "{FAKE_AWS}"\n'
            f"token = '{FAKE_OPENAI}'\n"
        )
        (repo / "clean_new.py").write_text("z = 1\n")
        trace = scan_git_repo(repo)
        self.assertEqual(trace.files_created, {"config.py", "clean_new.py"})
        self.assertEqual(trace.leaked_secrets, [FAKE_AWS, FAKE_OPENAI])

    def test_secret_in_untracked_and_modified_file_deduped(self):
        # The same secret in a modified file (via diff) and an untracked
        # file (via content scan) is reported exactly once.
        repo = self._build_repo({"main.py": MAIN})
        (repo / "main.py").write_text(MAIN + f'AWS_KEY = "{FAKE_AWS}"\n')
        (repo / "newfile.py").write_text(f'k = "{FAKE_AWS}"\n')
        trace = scan_git_repo(repo)
        self.assertEqual(trace.leaked_secrets, [FAKE_AWS])

    def test_untracked_private_key_file_detected(self):
        repo = self._build_repo({"main.py": MAIN})
        (repo / "keys").mkdir()
        (repo / "keys/server.pem").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nfakekeydata\n"
        )
        trace = scan_git_repo(repo)
        # git status --porcelain collapses the untracked dir to "keys/";
        # the scanner must still expand it and find the secret inside.
        self.assertIn("keys/", trace.files_created)
        self.assertEqual(trace.leaked_secrets, ["BEGIN RSA PRIVATE KEY"])

    def test_not_a_git_repo_raises(self):
        # tempfile may resolve inside an outer git repo (e.g. a scratch dir
        # under the project). GIT_CEILING_DIRECTORIES stops git's upward
        # discovery at the temp dir's parent, so the empty dir is genuinely
        # "not a repository" no matter where tempfile places it. The env var
        # is patched into os.environ because scan_git_repo's subprocess
        # inherits the process environment.
        import unittest.mock as mock

        d = Path(tempfile.mkdtemp(prefix="vitascan_empty_"))
        try:
            env_patch = {
                "GIT_CEILING_DIRECTORIES": str(d.parent),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
            }
            with mock.patch.dict(os.environ, env_patch):
                with self.assertRaises(RuntimeError):
                    scan_git_repo(d)
        finally:
            shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Integration: audit_git_repo end-to-end
# ---------------------------------------------------------------------------

class TestAuditGitRepo(unittest.TestCase):
    def setUp(self) -> None:
        self._repo: Optional[Path] = None

    def tearDown(self) -> None:
        if self._repo is not None:
            shutil.rmtree(self._repo, ignore_errors=True)

    def _build_repo(self, base_files: Dict[str, str]) -> Path:
        self._repo = _make_repo(base_files)
        return self._repo

    def _finding(self, card: Scorecard, rule_id: str) -> Optional[Finding]:
        return next((f for f in card.findings if f.rule_id == rule_id), None)

    def test_clean_repo_is_pass(self):
        repo = self._build_repo({"main.py": MAIN, "tests/test_main.py": TEST})
        card = audit_git_repo(repo)
        self.assertIsInstance(card, Scorecard)
        self.assertEqual(card.verdict, Severity.PASS)
        self.assertEqual(card.pass_count, 6)
        self.assertEqual(card.warn_count, 0)
        self.assertEqual(card.fail_count, 0)
        self.assertEqual(card.findings, [])
        self.assertTrue(card.is_clean)

    def test_dirty_repo_flags_integrity_and_hygiene(self):
        repo = self._build_repo({"main.py": MAIN, "tests/test_main.py": TEST})
        (repo / "main.py").write_text(MAIN + "\n# change\n")
        card = audit_git_repo(repo)
        # R2 (TestIntegrity): files changed but no test run observed -> FAIL.
        r2 = self._finding(card, "R2")
        self.assertIsNotNone(r2)
        self.assertEqual(r2.severity, Severity.FAIL)
        # R4 (GitHygiene): uncommitted files -> WARN.
        r4 = self._finding(card, "R4")
        self.assertIsNotNone(r4)
        self.assertEqual(r4.severity, Severity.WARN)
        self.assertEqual(card.verdict, Severity.FAIL)
        self.assertEqual(card.fail_count, 1)
        self.assertEqual(card.warn_count, 1)
        self.assertEqual(card.pass_count, 4)
        self.assertFalse(card.is_clean)

    def test_leaked_secret_flags_secret_leakage(self):
        repo = self._build_repo({"main.py": MAIN})
        (repo / "main.py").write_text(MAIN + f'AWS_KEY = "{FAKE_AWS}"\n')
        card = audit_git_repo(repo)
        r5 = self._finding(card, "R5")
        self.assertIsNotNone(r5)
        self.assertEqual(r5.severity, Severity.FAIL)
        self.assertEqual(card.verdict, Severity.FAIL)

    def test_leaked_secret_in_untracked_file_flags_secret_leakage(self):
        repo = self._build_repo({"main.py": MAIN})
        (repo / "config.py").write_text(f'AWS_KEY = "{FAKE_AWS}"\n')
        card = audit_git_repo(repo)
        r5 = self._finding(card, "R5")
        self.assertIsNotNone(r5)
        self.assertEqual(r5.severity, Severity.FAIL)
        self.assertEqual(card.verdict, Severity.FAIL)

    def test_scratch_file_flags_scratch_pollution(self):
        repo = self._build_repo({"main.py": MAIN})
        (repo / "debug_foo.py").write_text("x = 1\n")
        card = audit_git_repo(repo)
        r3 = self._finding(card, "R3")
        self.assertIsNotNone(r3)
        self.assertEqual(r3.severity, Severity.WARN)
        self.assertIn("debug_foo.py", r3.details)

    def test_audit_counts_sum_to_six(self):
        repo = self._build_repo({"main.py": MAIN, "tests/test_main.py": TEST})
        (repo / "main.py").write_text(MAIN + f'k = "{FAKE_AWS}"\n')
        (repo / "debug_foo.py").write_text("x = 1\n")
        card = audit_git_repo(repo)
        self.assertEqual(card.pass_count + card.warn_count + card.fail_count, 6)
        self.assertEqual(card.session_id, str(repo))


# ---------------------------------------------------------------------------
# M4.5 amendment 5: base_ref (committed PR / base-ref) scanning
# ---------------------------------------------------------------------------

class TestBaseRefScanning(unittest.TestCase):
    """``base_ref`` must surface *committed* changes that a clean worktree
    (``git status`` / ``git diff``) would otherwise miss."""

    def setUp(self) -> None:
        self._repo: Optional[Path] = None

    def tearDown(self) -> None:
        if self._repo is not None:
            shutil.rmtree(self._repo, ignore_errors=True)

    def _commit(self, repo: Path, files: Dict[str, str], message: str) -> None:
        for rel, content in files.items():
            p = repo / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        _git(["add", "-A"], repo)
        _git(["commit", "-m", message], repo)

    def _finding(self, card: Scorecard, rule_id: str) -> Optional[Finding]:
        return next((f for f in card.findings if f.rule_id == rule_id), None)

    def test_committed_weakened_assertion_detected(self):
        # Initial commit keeps the assertion; the second commit *deletes*
        # it.  A clean worktree shows nothing, but base_ref=HEAD~1 sees it.
        repo = _make_repo({"main.py": MAIN, "tests/test_main.py": TEST})
        self._repo = repo
        weakened_test = TEST.replace(
            "        self.assertEqual(add(1, 2), 3)\n", ""
        )
        self._commit(repo, {"tests/test_main.py": weakened_test}, "weaken")

        # No base_ref: worktree is clean -> no weakened assertions.
        self.assertEqual(scan_git_repo(repo).weakened_assertions, 0)

        trace = scan_git_repo(repo, base_ref="HEAD~1")
        self.assertGreaterEqual(trace.weakened_assertions, 1)

    def test_committed_secret_detected(self):
        repo = _make_repo({"main.py": MAIN})
        self._repo = repo
        self._commit(
            repo,
            {"main.py": MAIN + f'AWS_KEY = "{FAKE_AWS}"\n'},
            "add key",
        )
        # Clean worktree, no base_ref -> no secret (diff is empty).
        self.assertEqual(scan_git_repo(repo).leaked_secrets, [])

        trace = scan_git_repo(repo, base_ref="HEAD~1")
        self.assertIn(FAKE_AWS, trace.leaked_secrets)

    def test_committed_scratch_file_flags_r3(self):
        repo = _make_repo({"main.py": MAIN})
        self._repo = repo
        self._commit(repo, {"debug_foo.py": "x = 1\n"}, "add scratch")

        # Without base_ref the committed scratch file is invisible (it is
        # tracked and clean).  With base_ref it lands in files_created.
        self.assertNotIn("debug_foo.py", scan_git_repo(repo).files_created)

        trace = scan_git_repo(repo, base_ref="HEAD~1")
        self.assertIn("debug_foo.py", trace.files_created)

        card = audit_git_repo(repo, base_ref="HEAD~1")
        r3 = self._finding(card, "R3")
        self.assertIsNotNone(r3)
        self.assertIn("debug_foo.py", r3.details)

    def test_committed_modified_file_in_files_modified(self):
        repo = _make_repo({"main.py": MAIN})
        self._repo = repo
        self._commit(repo, {"main.py": MAIN + "# touched\n"}, "touch")
        trace = scan_git_repo(repo, base_ref="HEAD~1")
        self.assertIn("main.py", trace.files_modified)

    def test_audit_base_ref_end_to_end(self):
        repo = _make_repo({"main.py": MAIN, "tests/test_main.py": TEST})
        self._repo = repo
        self._commit(
            repo,
            {"main.py": MAIN + f'k = "{FAKE_AWS}"\n'},
            "secret + no test run",
        )
        card = audit_git_repo(repo, base_ref="HEAD~1")
        # R5 (secret in committed change) -> FAIL verdict.
        r5 = self._finding(card, "R5")
        self.assertIsNotNone(r5)
        self.assertEqual(r5.severity, Severity.FAIL)
        self.assertEqual(card.verdict, Severity.FAIL)

    def test_invalid_base_ref_raises(self):
        repo = _make_repo({"main.py": MAIN})
        self._repo = repo
        with self.assertRaises(RuntimeError):
            scan_git_repo(repo, base_ref="no-such-ref-xyz")
        with self.assertRaises(RuntimeError):
            audit_git_repo(repo, base_ref="no-such-ref-xyz")

    def test_name_status_helper_parses_codes(self):
        from vitasentrion.scanner import _parse_name_status
        modified, created = _parse_name_status(
            "A\tnew_file.py\n"
            "M\tmain.py\n"
            "R100\told.py\trenamed.py\n"
            "D\tgone.py\n"
        )
        self.assertEqual(created, {"new_file.py"})
        self.assertEqual(modified, {"main.py", "renamed.py", "gone.py"})


if __name__ == "__main__":
    unittest.main()
