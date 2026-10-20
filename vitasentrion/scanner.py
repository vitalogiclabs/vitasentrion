"""Git repository scanner for VitaSentrion (SPEC milestone M3).

Runs real ``git`` commands (standard library only) against a working
repository to build a :class:`~vitasentrion.models.SessionTrace`, and
exposes :func:`audit_git_repo` to turn that trace into a
:class:`~vitasentrion.models.Scorecard` through
:func:`~vitasentrion.rules.evaluate_trace`.

Design notes
------------
- ``scan_git_repo`` performs exactly two ``git`` invocations:
  ``git status --porcelain`` (to classify modified / created / uncommitted
  files) and ``git diff`` (to inspect line-level changes for weakened
  assertions and leaked secrets). In addition, every newly created file in
  ``files_created`` is read from disk and its content scanned with the same
  secret patterns, because untracked files never appear in ``git diff``.
- There is no dedicated "scratch files" field on :class:`SessionTrace`, so
  scratch files are surfaced the same way the rule engine expects: they are
  present in ``files_created`` (which is what R3 / ``ScratchPollution`` reads).
  :func:`detect_scratch_files` is the canonical detector for the M3 scratch
  patterns and can be applied to ``files_created`` directly.

Python 3.10+ standard library only (``subprocess``, ``re``, ``pathlib``).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

from .config import VitaConfig, path_matches_ignore, rule_action
from .models import Finding, Scorecard, SessionTrace, Severity
from .rules import evaluate_trace

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Secret patterns, per the M3 requirement. Ordered most-specific first so the
# overlap resolution in :func:`_find_secrets` prefers a more specific match
# (e.g. an Anthropic ``sk-ant-...`` token over the generic OpenAI ``sk-...``
# shape) when both could claim the same span.
#
# NOTE: this is deliberately a *separate* set from :data:`rules.SECRET_PATTERNS`.
# The four credential patterns are identical, but the private-key pattern is
# looser here (``BEGIN [A-Z ]*PRIVATE KEY``) so the repo scanner also catches
# key material without the exact ``-----`` framing that R5's live rule expects.
# Keep them in sync manually; do not import rules.SECRET_PATTERNS here.
SECRET_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("AWS", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("GitHub", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("PrivateKey", re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")),
)

# Substrings that mark an assertion line (M3 requirement). A *deleted* line in
# a test file containing any of these counts as a weakened assertion.
ASSERTION_MARKERS: Tuple[str, ...] = (
    "assert ",
    "self.assert",
    "expect(",
    "toBe(",
    "toEqual(",
)

# Scratch-file patterns (M3 requirement), matched against the basename.
# Note: deliberately narrower than R3's ``TEMP_FILE_RE`` (underscore-only for
# ``debug_`` / ``temp_``, and no ``tmp_`` / ``scratch-`` variants).
SCRATCH_PATTERNS: Tuple["re.Pattern[str]", ...] = (
    re.compile(r"^debug_.*\.py$"),
    re.compile(r"^temp_.*\.py$"),
    re.compile(r"^test_fixed\.py$"),
    re.compile(r"^final_verification\.py$"),
)


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

def _run_git(
    args: List[str], repo_path: Path
) -> "subprocess.CompletedProcess[str]":
    """Run ``git <args>`` inside *repo_path* and capture the output."""
    return subprocess.run(
        ["git", *args],
        cwd=str(repo_path),
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# ``git status --porcelain`` parsing
# ---------------------------------------------------------------------------

def _clean_path(raw: str) -> str:
    """Strip the quoting git adds around paths containing special characters."""
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        raw = raw[1:-1]
    return raw


def _parse_porcelain(output: str) -> Tuple[Set[str], Set[str], Set[str]]:
    """Parse ``git status --porcelain`` into ``(modified, created, uncommitted)``.

    Every line represents an uncommitted entry (it differs from HEAD or is
    untracked), so all paths land in ``uncommitted_files``. A path is counted
    as *created* when it is a new/staged-add file (``A``) or untracked (``??``)
    and as *modified* when either status column is ``M``.
    """
    modified: Set[str] = set()
    created: Set[str] = set()
    uncommitted: Set[str] = set()

    for line in output.splitlines():
        if not line or len(line) < 4:
            continue
        x, y = line[0], line[1]
        path_part = line[3:].strip()
        if not path_part:
            continue
        # Renames/copies are shown as "old -> new"; keep the new path.
        if " -> " in path_part:
            path_part = path_part.split(" -> ", 1)[1]
        path = _clean_path(path_part)
        if not path:
            continue

        uncommitted.add(path)

        is_untracked = x == "?" and y == "?"
        is_staged_add = x == "A"
        is_modified = "M" in (x, y)

        if is_untracked or is_staged_add:
            created.add(path)
        if is_modified:
            modified.add(path)

    return modified, created, uncommitted


# ---------------------------------------------------------------------------
# ``git diff --name-status`` parsing (M4.5 amendment 5)
# ---------------------------------------------------------------------------

def _parse_name_status(output: str) -> Tuple[Set[str], Set[str]]:
    """Parse ``git diff --name-status <base>...HEAD`` into
    ``(modified, created)`` path sets.

    Status codes: ``A`` -> created; ``M`` / ``R`` / ``C`` / ``D`` / ``T``
    -> modified (a rename keeps its *new* path; a deleted file is still a
    change relative to the base ref).  Renames/copies arrive as
    ``R<score>\told\tnew`` — the new path is kept.
    """
    modified: Set[str] = set()
    created: Set[str] = set()

    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        code = parts[0].strip()
        status = code[0] if code else ""
        if status == "A":
            path = _clean_path(parts[-1])
            if path:
                created.add(path)
            continue
        if status in ("M", "R", "C", "D", "T"):
            path = _clean_path(parts[-1])
            if path:
                modified.add(path)
        # U (unmerged) and anything else: not a committed change.

    return modified, created


# ---------------------------------------------------------------------------
# ``git diff`` parsing
# ---------------------------------------------------------------------------

def _strip_ab(path: str) -> str:
    """Strip the leading ``a/`` or ``b/`` prefix git adds to diff paths."""
    for prefix in ("a/", "b/"):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def _is_test_file(path: str) -> bool:
    """Heuristic per M3: a file is a test file when ``test`` appears in its
    name or path (case-insensitive substring)."""
    return "test" in path.lower()


def _has_assertion_marker(line: str) -> bool:
    return any(marker in line for marker in ASSERTION_MARKERS)


def _find_secrets(line: str) -> List[str]:
    """Return the secret values matched in *line*, deduplicated.

    Overlapping matches (e.g. an Anthropic token also matching the generic
    OpenAI ``sk-`` shape) collapse to the single most-specific span.
    """
    matches: List[Tuple[int, int, str]] = []
    for _label, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(line):
            matches.append((m.start(), m.end(), m.group(0)))
    if not matches:
        return []

    # Earliest start first; among matches at the same start, longest (most
    # specific) first.
    matches.sort(key=lambda t: (t[0], -(t[1] - t[0])))

    chosen: List[Tuple[int, int, str]] = []
    for start, end, text in matches:
        # Skip if it overlaps a span already chosen (that one is longer/equal
        # and came first).
        if any(start < c_end and c_start < end for c_start, c_end, _ in chosen):
            continue
        chosen.append((start, end, text))

    out: List[str] = []
    seen: Set[str] = set()
    for _start, _end, text in chosen:
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _scan_file_for_secrets(path: Path) -> List[str]:
    """Return the deduplicated secret values found in *path*'s content.

    Every line is scanned (a newly created file's whole content is, by
    definition, new) using the same :data:`SECRET_PATTERNS` as
    :func:`_parse_diff`. Missing or unreadable files yield an empty list.
    """
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    secrets: List[str] = []
    seen: Set[str] = set()
    for line in text.splitlines():
        for secret in _find_secrets(line):
            if secret not in seen:
                seen.add(secret)
                secrets.append(secret)
    return secrets


def _parse_diff(output: str) -> Tuple[int, List[str]]:
    """Parse ``git diff`` output into ``(weakened_assertions, leaked_secrets)``.

    - Weakened assertions: deleted lines (start with ``-`` but not ``---``)
      in a test file that contain an assertion marker.
    - Leaked secrets: added lines (start with ``+`` but not ``+++``) that match
      a secret pattern.
    """
    weakened = 0
    secrets: List[str] = []
    seen: Set[str] = set()
    current_file = ""

    for line in output.splitlines():
        # Any line starting with '+++'/'---' is a file header (or, in the
        # pathological case where a source line itself began with '--', a
        # deleted line the spec explicitly excludes). Either way it is not a
        # countable content line. Real headers always carry the a/ or b/
        # prefix in unified diff, so only those update ``current_file``.
        if line.startswith("+++") or line.startswith("---"):
            if line.startswith("+++ b/"):
                current_file = _strip_ab(_clean_path(line[4:]))
            elif line.startswith("--- a/"):
                # Provisional; overwritten by the +++ b/ header for normal
                # edits, kept as-is for deletions (whose +++ is /dev/null).
                current_file = _strip_ab(_clean_path(line[4:]))
            continue

        if line.startswith("+"):
            for secret in _find_secrets(line[1:]):
                if secret not in seen:
                    seen.add(secret)
                    secrets.append(secret)
            continue

        if line.startswith("-"):
            if _is_test_file(current_file) and _has_assertion_marker(line[1:]):
                weakened += 1
            continue

        # context / hunk-header / index lines: nothing to do

    return weakened, secrets


# ---------------------------------------------------------------------------
# R9: repo-borne prompt injection (M9, P1-b)
# ---------------------------------------------------------------------------

# Instruction / prompt files an agent may later read as instructions.
INSTRUCTION_BASENAMES = {
    "agents.md", "claude.md", "gemini.md", ".cursorrules",
}
INSTRUCTION_NAME_MARKERS = ("prompt", "instruction")
# Suffixes that mark instruction content on their own (.prompt, .rules);
# .md/.txt only match through the name rules below.
INSTRUCTION_OWN_SUFFIXES = (".prompt", ".rules")
INSTRUCTION_DOC_SUFFIXES = {".md", ".markdown"}

# Detector 1: prompt-injection / instruction-override signatures.
OVERRIDE_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("override-phrase", re.compile(
        r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?",
        re.IGNORECASE)),
    ("override-phrase", re.compile(
        r"disregard\s+(?:all\s+|any\s+|the\s+)?"
        r"(?:previous|prior|above|system)\s+"
        r"(?:instructions?|prompts?|rules?)",
        re.IGNORECASE)),
    ("override-phrase", re.compile(
        r"forget\s+(?:all\s+)?(?:previous|prior|your)\s+instructions?",
        re.IGNORECASE)),
    ("override-phrase", re.compile(
        r"override\s+(?:all\s+)?(?:previous|prior|the\s+system|system)\s+"
        r"(?:instructions?|prompts?|rules?)",
        re.IGNORECASE)),
    ("override-phrase", re.compile(
        r"new\s+instructions?\s*:", re.IGNORECASE)),
)

# Detector 2: hidden-Unicode tricks (zero-width chars, BOM, bidi
# override/clear) that hide text from a human reviewer but not a model.
HIDDEN_UNICODE_RE = re.compile("[\u200b\u200c\u200d\ufeff\u202e\u202c]")

# Detector 3: base64-shaped payload blobs (48+ chars) inside an
# instruction file — the classic smuggled-payload marker.
BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")

# Files larger than this are not read for R9 (instruction files are small;
# a huge match is almost certainly generated data).
_INSTRUCTION_MAX_BYTES = 512 * 1024


def is_instruction_file(path: str) -> bool:
    """True when *path* (repo-relative, '/' separators) is an instruction /
    prompt file that R9 scans (M9, P1-b).

    Matches well-known agent instruction basenames (AGENTS.md, CLAUDE.md,
    GEMINI.md, .cursorrules), ``*.prompt`` / ``*rules`` files, filenames
    containing "prompt" or "instruction" with a text suffix, and any
    Markdown under ``.github/`` (issue templates, Copilot instructions).
    """
    normalized = path.replace("\\", "/")
    parts = [seg for seg in normalized.split("/") if seg]
    if not parts:
        return False
    name = parts[-1]
    low = name.lower()
    if low in INSTRUCTION_BASENAMES or low.endswith(INSTRUCTION_OWN_SUFFIXES):
        return True
    if any(marker in low for marker in INSTRUCTION_NAME_MARKERS):
        # name marker + a text suffix; code files like prompt_loader.py
        # are not instruction files.
        return low.endswith((".md", ".markdown", ".txt", ".prompt"))
    if ".github" in parts[:-1] and low.endswith(
        tuple(INSTRUCTION_DOC_SUFFIXES)
    ):
        return True
    return False


def detect_repo_injections(
    repo_path, config: Optional[VitaConfig] = None
) -> List[Finding]:
    """Scan instruction files in *repo_path* for planted prompt-injection
    payloads (M9, R9). Returns zero or one R9 (RepoInjection) finding.

    Walks the working tree (skipping ``.git/``), keeps only
    :func:`is_instruction_file` matches, drops ``[guard].ignore_paths``
    (M8) before reading, and reports file + detector + line number per
    hit — never the line content, so the report cannot echo the payload.
    """
    root = Path(repo_path).resolve()
    hits: List[str] = []
    for candidate in sorted(root.rglob("*")):
        if not candidate.is_file():
            continue
        rel = candidate.relative_to(root).as_posix()
        if rel.startswith(".git/") or rel == ".git":
            continue
        if config is not None and config.ignore_paths and path_matches_ignore(
            rel, config.ignore_paths
        ):
            continue
        if not is_instruction_file(rel):
            continue
        try:
            if candidate.stat().st_size > _INSTRUCTION_MAX_BYTES:
                continue
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for label, pattern in OVERRIDE_PATTERNS:
                if pattern.search(line):
                    hits.append(
                        f"{rel}:{lineno}: instruction-override phrase "
                        f"({label})"
                    )
            if HIDDEN_UNICODE_RE.search(line):
                hits.append(
                    f"{rel}:{lineno}: hidden Unicode character "
                    "(zero-width / bidi)"
                )
            if BASE64_BLOB_RE.search(line):
                hits.append(
                    f"{rel}:{lineno}: base64-shaped payload blob"
                )
    if not hits:
        return []
    return [
        Finding(
            rule_id="R9",
            rule_name="RepoInjection",
            severity=Severity.WARN,
            message=(
                f"Instruction files contain prompt-injection markers "
                f"({len(hits)} hit(s))"
            ),
            details=hits[:20],
        )
    ]


# ---------------------------------------------------------------------------
# Scratch-file detection
# ---------------------------------------------------------------------------

def detect_scratch_files(created: Iterable[str]) -> Set[str]:
    """Return the paths in *created* whose basename matches a scratch pattern.

    This is the M3 scratch-file detector. Scratch files are also present in
    ``SessionTrace.files_created`` (from ``git status --porcelain``), which is
    what the R3 / ``ScratchPollution`` rule reads during an audit.
    """
    found: Set[str] = set()
    for path in created:
        name = Path(path).name
        if any(p.match(name) for p in SCRATCH_PATTERNS):
            found.add(path)
    return found


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def _drop_ignored(
    paths: Set[str], config: Optional[VitaConfig]
) -> Set[str]:
    """Remove paths matching ``[guard].ignore_paths`` (M8)."""
    if config is None or not config.ignore_paths:
        return paths
    return {
        path
        for path in paths
        if not path_matches_ignore(path, config.ignore_paths)
    }


def scan_git_repo(
    repo_path,
    base_ref: Optional[str] = None,
    config: Optional[VitaConfig] = None,
) -> SessionTrace:
    """Scan a git repository and build a :class:`SessionTrace`.

    Steps:
    1. ``git status --porcelain`` -> ``files_modified``, ``files_created``
       (which includes scratch files), ``uncommitted_files``.
    2. ``git diff`` -> ``weakened_assertions`` (deleted assertion lines in test
       files) and ``leaked_secrets`` (added lines matching a secret pattern).
    3. Newly created/untracked files (``files_created``) are scanned for
       leaked secrets as well: their content never appears in ``git diff``
       (untracked files are not diffed by default), so the whole file
       content is scanned with the same secret regexes and any hits are
       merged into ``leaked_secrets`` (deduplicated).

    When *base_ref* is provided (M4.5 amendment 5, e.g. ``"HEAD~1"`` or
    ``"main"``), the committed range ``git diff <base_ref>...HEAD`` is
    inspected as well: its unified diff is parsed for weakened assertions
    and leaked secrets (merged/deduped with the working-tree results), and
    ``git diff --name-status <base_ref>...HEAD`` contributes committed
    paths to ``files_modified`` / ``files_created`` so R3 sees committed
    scratch files.  This is how CI Pull Requests get their *committed*
    changes scanned, not just the dirty worktree.

    *config* (M8) optionally carries ``[guard].ignore_paths``: matching
    paths are dropped from every reported set (and never secret-scanned).

    Raises
    ------
    RuntimeError
        If ``git status`` fails (e.g. *repo_path* is not a valid git repo),
        or if *base_ref* is provided but git rejects it (unknown revision).
    """
    root = Path(repo_path).resolve()

    status = _run_git(["status", "--porcelain"], root)
    if status.returncode != 0:
        raise RuntimeError(
            f"git status failed for {root}: {status.stderr.strip()}"
        )
    modified, created, uncommitted = _parse_porcelain(status.stdout)
    modified, created, uncommitted = (
        _drop_ignored(modified, config),
        _drop_ignored(created, config),
        _drop_ignored(uncommitted, config),
    )

    diff = _run_git(["diff"], root)
    if diff.returncode == 0:
        weakened, secrets = _parse_diff(diff.stdout)
    else:
        # A non-zero diff return code is unusual (status already succeeded);
        # treat it as "no diffable changes" rather than failing the scan.
        weakened, secrets = 0, []

    # M4.5 amendment 5: committed changes relative to the base ref.
    if base_ref is not None:
        diff_base = _run_git(["diff", f"{base_ref}...HEAD"], root)
        if diff_base.returncode != 0:
            raise RuntimeError(
                f"git diff {base_ref}...HEAD failed for {root}: "
                f"{diff_base.stderr.strip()}"
            )
        base_weakened, base_secrets = _parse_diff(diff_base.stdout)
        weakened += base_weakened
        for secret in base_secrets:
            if secret not in secrets:
                secrets.append(secret)

        status_base = _run_git(
            ["diff", "--name-status", f"{base_ref}...HEAD"], root
        )
        if status_base.returncode != 0:
            raise RuntimeError(
                f"git diff --name-status {base_ref}...HEAD failed for "
                f"{root}: {status_base.stderr.strip()}"
            )
        base_modified, base_created = _parse_name_status(status_base.stdout)
        modified |= _drop_ignored(base_modified, config)
        created |= _drop_ignored(base_created, config)

    # ``git diff`` (without --cached) does not show the content of untracked
    # files, so scan every newly created path on disk and merge any secrets
    # found into ``leaked_secrets`` (deduplicated against the diff hits).
    # ``git status --porcelain`` reports an untracked *directory* as a single
    # collapsed entry (``?? keys/``), so directories are expanded to the
    # files inside them.
    for created_path in sorted(created):
        candidate = root / created_path
        if candidate.is_dir():
            candidates = sorted(p for p in candidate.rglob("*") if p.is_file())
        else:
            candidates = [candidate]
        for file_path in candidates:
            for secret in _scan_file_for_secrets(file_path):
                if secret not in secrets:
                    secrets.append(secret)

    return SessionTrace(
        session_id=str(root),
        workspace_root=str(root),
        files_modified=modified,
        files_created=created,
        uncommitted_files=uncommitted,
        weakened_assertions=weakened,
        leaked_secrets=secrets,
    )


def audit_git_repo(
    repo_path,
    base_ref: Optional[str] = None,
    config: Optional[VitaConfig] = None,
) -> Scorecard:
    """Scan *repo_path* and return the rule-engine :class:`Scorecard`.

    *base_ref* is forwarded to :func:`scan_git_repo` (M4.5 amendment 5):
    when provided, committed changes against the base ref are scanned too.
    *config* (M8) is forwarded for ignore-path filtering and rule actions.
    """
    trace = scan_git_repo(repo_path, base_ref=base_ref, config=config)
    card = evaluate_trace(trace, config=config)

    # M9 (P1-b): fold the repo-borne injection scan into the scorecard.
    # R9's DEFAULT action is "warn" (docs discussing prompts must not
    # hard-block); [rules] R9 = "block" escalates to FAIL, "ignore"
    # skips the check entirely.
    r9_action = rule_action(config, "R9", default="warn")
    if r9_action != "ignore":
        r9 = detect_repo_injections(repo_path, config=config)
        if r9 and r9_action == "block":
            r9 = [
                Finding(
                    rule_id=f.rule_id, rule_name=f.rule_name,
                    severity=Severity.FAIL, message=f.message,
                    details=f.details,
                )
                for f in r9
            ]
        card.findings.extend(r9)
        card.fail_count += sum(
            1 for f in r9 if f.severity is Severity.FAIL
        )
        card.warn_count += sum(
            1 for f in r9 if f.severity is Severity.WARN
        )
        if r9:
            if card.fail_count:
                card.verdict = Severity.FAIL
            elif card.verdict is Severity.PASS:
                card.verdict = Severity.WARN
    return card
