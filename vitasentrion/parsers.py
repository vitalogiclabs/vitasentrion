"""Trace parsers for VitaSentrion (SPEC milestone M2).

``parse_trace(source) -> SessionTrace`` accepts a filesystem path, a
file-like object (anything with ``.read()``), or a raw JSON / JSONL string,
and auto-detects the transcript format from the file extension and the
content:

1. Claude Code transcript -- ``.jsonl`` of event lines with
   ``"type": "assistant"`` / ``"type": "user"``; tool invocations appear as
   ``tool_use`` blocks inside ``message.content`` and results as
   ``tool_result`` blocks on the following user line.  (Top-level
   ``"type": "tool_use"`` / ``"type": "tool_result"`` lines are also
   understood.)
2. Cline / Roo Code task history -- JSON with ``"role": "assistant"``
   messages whose ``content`` is a list containing ``tool_use`` /
   ``tool_result`` blocks (single message object, message list, or an
   object wrapping the list under ``messages`` / ``history`` / ...).
3. OpenAI / Hermes format -- JSON or JSONL of a ``messages`` list where
   assistant messages carry ``tool_calls`` and tool outputs arrive as
   ``"role": "tool"`` messages keyed by ``tool_call_id``.

The parser populates ``session_id`` (metadata keys, then file name stem,
then a sha1 fingerprint of the content), ``workspace_root`` (metadata
``cwd`` / ``workspace_root`` keys, else the model default),
``tool_events`` (name, parsed arguments, output matched by tool id,
``is_error``), ``files_created`` / ``files_modified`` (from the file
editing tools ``patch``, ``write_file``, ``edit_file``, ``Edit``,
``Write``, ``MultiEdit`` and from ``apply_patch`` text),
``uncommitted_files`` (``git status`` output in command events or
metadata), ``test_runs_count`` / ``last_test_passed`` (command tools
executing ``pytest`` / ``unittest`` / ``npm test`` / ``cargo test`` /
``go test``), ``turns_count`` and ``duration_s`` (first-to-last
timestamp, or an explicit ``duration_s`` metadata key).

Python 3.10+ standard library only (json, pathlib, re, datetime, hashlib).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Optional, Union

from .models import SessionTrace, ToolEvent

__all__ = ["parse_trace"]

# ---------------------------------------------------------------------------
# Tool classification
# ---------------------------------------------------------------------------

# File editing tools: which create a new file versus modify an existing one.
CREATED_TOOLS = {"Write", "write_file"}
MODIFIED_TOOLS = {"patch", "edit_file", "Edit", "MultiEdit"}

# Command execution tools whose command argument is inspected for test runs
# and git status output.  Matched case-insensitively (Claude Code uses
# "Bash", Hermes uses "terminal").
COMMAND_TOOLS = {
    "bash",
    "terminal",
    "shell",
    "exec",
    "command",
    "run",
    "run_command",
    "run_in_terminal",
    "run_shell_command",
    "execute_command",
    "execute_bash",
    "shell_command",
}

# Argument keys that carry a shell command.
COMMAND_ARG_KEYS = ("command", "cmd", "code", "script", "shell_command")

# Argument keys that carry a file path (for edit tools).
PATH_ARG_KEYS = (
    "path",
    "file_path",
    "filepath",
    "file",
    "notebook_path",
    "target",
    "dest",
    "destination",
    "to",
)

# Argument keys that carry an apply_patch patch body.
APPLY_PATCH_ARG_KEYS = ("patch", "input", "text", "data")

# Substrings identifying a test-running command (mirrors rules.py).
TEST_COMMAND_MARKERS = ("pytest", "unittest", "npm test", "cargo test", "go test")

# Metadata keys, in priority order.
SESSION_ID_KEYS = (
    "session_id",
    "sessionId",
    "session-id",
    "conversation_id",
    "taskId",
    "task_id",
)
WORKSPACE_KEYS = (
    "workspace_root",
    "workspace",
    "cwd",
    "working_directory",
    "project_root",
)

# git status --porcelain line: "XY PATH" where X (index) and Y (worktree)
# are each one of ' ' M A D R C U or ? / !.
_PORCELAIN_LINE_RE = re.compile(r"^([ MARD?U!])([ MARD?U!]) (\S.*)$")
# Human-readable git status lines: "modified: x", "new file: x", ...
_STATUS_CHANGED_RE = re.compile(r"^(?:modified|new file|deleted|renamed):\s*(.+)$", re.I)

# apply_patch directives.
_APPLY_PATCH_ADD_RE = re.compile(r"^\*\*\* Add File: (.+)$", re.M)
_APPLY_PATCH_UPDATE_RE = re.compile(r"^\*\*\* (?:Update|Delete) File: (.+)$", re.M)


# ---------------------------------------------------------------------------
# Input coercion
# ---------------------------------------------------------------------------

def _coerce_text(source: Any) -> tuple[str, Optional[str]]:
    """Return ``(text, name)`` for a path, file-like, or raw-string source.

    Path probing is wrapped in ``try/except OSError``: on Python 3.10-3.13
    ``Path.exists()``/``is_file()`` raise ``OSError: [Errno 36] File name too
    long`` for names longer than 255 bytes (3.14 returns False instead), so a
    long raw-JSON string must never crash the probe.
    """
    if isinstance(source, Path):
        try:
            if source.is_file():
                return source.read_text(encoding="utf-8", errors="replace"), source.name
        except OSError:
            pass
        return str(source), None
    if isinstance(source, str):
        s_strip = source.strip()
        if s_strip.startswith("{") or s_strip.startswith("["):
            return source, None
        try:
            p = Path(source)
            if p.is_file():
                return p.read_text(encoding="utf-8", errors="replace"), p.name
        except OSError:
            pass
        return source, None
    read = getattr(source, "read", None)
    if callable(read):
        raw = read()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "replace")
        if not isinstance(raw, str):
            raise TypeError("file-like object did not return text or bytes")
        name = getattr(source, "name", None)
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        return raw, (str(name) if name is not None else None)
    raise TypeError(f"Unsupported trace source: {type(source).__name__}")


def _try_jsonl(text: str) -> Optional[list[Any]]:
    """Parse every non-blank line as JSON; return the objects or None."""
    objs: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            objs.append(json.loads(line))
        except (ValueError, TypeError):
            return None
    return objs if objs else None


# ---------------------------------------------------------------------------
# Small field extractors
# ---------------------------------------------------------------------------

def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 string or epoch seconds/ms into an aware datetime."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if value <= 0:
            return None
        seconds = value / 1000.0 if value > 1e12 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return None


def _content_to_text(content: Any) -> str:
    """Flatten a message/tool-result content value into plain text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
                else:
                    nested = item.get("content")
                    if isinstance(nested, (str, list)):
                        parts.append(_content_to_text(nested))
        return "\n".join(parts)
    return str(content)


def _normalize_args(args: Any) -> dict[str, Any]:
    """Coerce tool arguments (dict, JSON string, or other) into a dict."""
    if isinstance(args, dict):
        return args
    if isinstance(args, str):
        try:
            parsed = json.loads(args)
        except (ValueError, TypeError):
            return {"raw": args}
        if isinstance(parsed, dict):
            return parsed
        return {"raw": parsed}
    if args is None:
        return {}
    return {"raw": args}


def _extract_path(args: dict[str, Any]) -> Optional[str]:
    for key in PATH_ARG_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _lookup_session_id(*containers: Any) -> Optional[str]:
    for container in containers:
        if not isinstance(container, dict):
            continue
        # A plain "id" key is only a session id at top level, never on a
        # message-level dict (messages carry their own message ids).
        keys = SESSION_ID_KEYS + (() if "role" in container else ("id",))
        for key in keys:
            value = container.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _lookup_workspace(*containers: Any) -> Optional[str]:
    for container in containers:
        if not isinstance(container, dict):
            continue
        for key in WORKSPACE_KEYS:
            value = container.get(key)
            if isinstance(value, str) and value:
                return value
    return None


# ---------------------------------------------------------------------------
# Intermediate representation and per-format processors
# ---------------------------------------------------------------------------

class _Accumulator:
    """Collected pieces of a trace, format independent."""

    def __init__(self) -> None:
        self.uses: list[tuple[str, dict[str, Any], Optional[str]]] = []
        self.results: dict[str, tuple[str, bool]] = {}
        self.timestamps: list[datetime] = []
        self.turns: int = 0


def _record_use(acc: _Accumulator, name: Any, args: Any, tool_id: Any) -> None:
    acc.uses.append(
        (
            name if isinstance(name, str) and name else "unknown",
            _normalize_args(args),
            tool_id if isinstance(tool_id, str) and tool_id else None,
        )
    )


def _record_result(acc: _Accumulator, tool_id: Any, content: Any, is_error: Any) -> None:
    if isinstance(tool_id, str) and tool_id:
        acc.results[tool_id] = (_content_to_text(content), bool(is_error))


def _process_blocks(acc: _Accumulator, blocks: Any) -> None:
    """Claude-style content list: tool_use / tool_result blocks."""
    if not isinstance(blocks, list):
        return
    for block in blocks:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "tool_use":
            _record_use(
                acc,
                block.get("name") or block.get("tool_name"),
                block.get("input", block.get("arguments")),
                block.get("id"),
            )
        elif btype == "tool_result":
            _record_result(acc, block.get("tool_use_id"), block.get("content"), block.get("is_error"))


def _process_message_list(acc: _Accumulator, messages: Any) -> None:
    """OpenAI-style (tool_calls) and Claude-style (content blocks) messages."""
    if not isinstance(messages, list):
        return
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        ts = _parse_timestamp(
            message.get("timestamp") or message.get("created_at") or message.get("createdAt")
        )
        if ts is not None:
            acc.timestamps.append(ts)
        if role in ("user", "assistant"):
            acc.turns += 1
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list):
            for call in tool_calls:
                if not isinstance(call, dict):
                    continue
                func = call.get("function")
                if not isinstance(func, dict):
                    func = {}
                name = func.get("name") or call.get("name")
                args = func.get("arguments", call.get("arguments"))
                _record_use(acc, name, args, call.get("id"))
        content = message.get("content")
        if isinstance(content, list):
            _process_blocks(acc, content)
        if role == "tool":
            _record_result(acc, message.get("tool_call_id") or message.get("tool_use_id"), content, None)


def _process_claude_jsonl(acc: _Accumulator, lines: list[Any]) -> None:
    """Claude Code transcript: one event per line, session fields inline."""
    for line in lines:
        if not isinstance(line, dict):
            continue
        ltype = line.get("type")
        ts = _parse_timestamp(line.get("timestamp"))
        if ts is not None:
            acc.timestamps.append(ts)
        if ltype in ("user", "assistant"):
            acc.turns += 1
            message = line.get("message")
            if isinstance(message, dict):
                _process_blocks(acc, message.get("content"))
        elif ltype == "tool_use":
            _record_use(
                acc,
                line.get("name") or line.get("tool_name"),
                line.get("input", line.get("arguments")),
                line.get("id"),
            )
        elif ltype in ("tool_result", "tool"):
            _record_result(
                acc,
                line.get("tool_use_id") or line.get("id"),
                line.get("content", line.get("output")),
                line.get("is_error"),
            )


# ---------------------------------------------------------------------------
# Trace field derivation
# ---------------------------------------------------------------------------

def _apply_patch_paths(patch_text: str) -> tuple[set[str], set[str]]:
    created = {m.strip() for m in _APPLY_PATCH_ADD_RE.findall(patch_text) if m.strip()}
    modified = {m.strip() for m in _APPLY_PATCH_UPDATE_RE.findall(patch_text) if m.strip()}
    return created, modified


def _git_status_uncommitted(command: str, output: str) -> set[str]:
    """Files reported as uncommitted by a ``git status`` command output."""
    if "git status" not in command:
        return set()
    files: set[str] = set()
    if "porcelain" in command:
        for line in output.splitlines():
            match = _PORCELAIN_LINE_RE.match(line.rstrip())
            if match:
                path = match.group(3)
                if " -> " in path:  # rename: keep the destination
                    path = path.split(" -> ")[-1].strip()
                files.add(path)
    else:
        for line in output.splitlines():
            match = _STATUS_CHANGED_RE.match(line.strip())
            if match:
                files.add(match.group(1).strip())
    return files


def _command_of(args: dict[str, Any]) -> Optional[str]:
    for key in COMMAND_ARG_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _last_test_passed(output: str, is_error: bool = False) -> Optional[bool]:
    if not output:
        return False if is_error else None

    clean = output.strip()
    if clean.endswith("OK") or "OK (" in output or re.search(r"Ran \d+ tests? in [0-9.]+s.*?OK", output, re.I | re.DOTALL):
        return True

    # Non-zero failures or errors -> False
    if re.search(r"\b([1-9]\d*)\s+(?:failed|errors?|failures?)\b", output, re.I):
        return False
    # Case-sensitive FAILED check so lowercase "0 failed" is not caught
    if re.search(r"\bFAILED\b", output) or re.search(r"\bFAILURES?\b", output):
        return False
    if re.search(r"traceback \(most recent call last\)", output, re.I):
        return False

    # Pytest passed with 0 failed -> True
    if re.search(r"\b\d+\s+passed\b", output, re.I) and not re.search(r"\b[1-9]\d*\s+failed\b", output, re.I):
        return True

    if is_error:
        return False
    return None

def _duration(acc: _Accumulator, meta_containers: list[Any]) -> float:
    for container in meta_containers:
        if not isinstance(container, dict):
            continue
        for key in ("duration_s", "duration_seconds", "durationSeconds", "duration"):
            value = container.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
                return float(value)
    valid = [t for t in acc.timestamps if t is not None]
    if len(valid) >= 2:
        return (max(valid) - min(valid)).total_seconds()
    return 0.0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_trace(source: Union[str, os.PathLike[str], IO[Any]]) -> SessionTrace:
    """Parse a Claude Code / Cline / OpenAI(-Hermes) trace into a SessionTrace.

    *source* is a filesystem path (str or Path), a file-like object, or the
    raw JSON/JSONL content as a string.  The format is chosen from the file
    extension (``.jsonl`` prefers line-wise parsing) and from the content
    itself, so the formats work regardless of extension.
    """
    text, name = _coerce_text(source)
    text = text.strip()
    if not text:
        stem = Path(name).stem if name else None
        return SessionTrace(session_id=stem or "unknown")

    # Format choice: the extension is the first hint (a ".jsonl" file whose
    # every line is JSON is parsed line-wise), content is authoritative
    # otherwise.  Both candidates are computed; a multi-line JSONL file is
    # never a single valid JSON document, so JSON documents and JSONL never
    # conflict in practice.
    extension = Path(name).suffix.lower() if name else ""
    try:
        whole = json.loads(text)
    except (ValueError, TypeError):
        whole = None
    lines: Optional[list[Any]] = None
    if extension == ".jsonl":
        lines = _try_jsonl(text)
    elif whole is None:
        lines = _try_jsonl(text)
    if whole is None and lines is None:
        raise ValueError(
            "Unrecognized trace format: input is neither a JSON document nor JSONL"
        )

    acc = _Accumulator()
    meta: Any = {}
    meta_containers: list[Any] = []

    def _process_whole() -> None:
        nonlocal acc, meta, meta_containers
        if isinstance(whole, dict):
            meta = whole
            if isinstance(whole.get("messages"), list):
                _process_message_list(acc, whole["messages"])
            elif "role" in whole:
                _process_message_list(acc, [whole])
            else:
                for key in ("history", "records", "transcript", "events"):
                    if isinstance(whole.get(key), list):
                        _process_message_list(acc, whole[key])
                        break
            meta_containers = [meta]
        elif isinstance(whole, list):
            _process_message_list(acc, whole)
            meta_containers = []
        else:
            raise ValueError("Unrecognized trace format: JSON scalar has no session content")

    if lines is not None:
        # JSONL.  Claude Code transcripts carry per-line "type" + "message".
        is_claude = any(
            isinstance(line, dict)
            and line.get("type") in ("user", "assistant", "tool_use", "tool_result", "tool")
            and (
                isinstance(line.get("message"), dict)
                or line.get("type") in ("tool_use", "tool_result", "tool")
            )
            for line in lines
        )
        if is_claude:
            _process_claude_jsonl(acc, lines)
        else:
            messages = [line for line in lines if isinstance(line, dict) and "role" in line]
            _process_message_list(acc, messages)
        # A single-line JSON document inside a .jsonl-named file parses
        # line-wise but carries no message shape: fall back to the
        # whole-document interpretation.
        if not acc.uses and not acc.turns and whole is not None:
            acc = _Accumulator()
            _process_whole()
        else:
            meta_containers = [line for line in lines if isinstance(line, dict)]
    else:
        _process_whole()

    session_id = (
        _lookup_session_id(*meta_containers)
        or (Path(name).stem if name else None)
        or hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:12]
    )
    workspace_root = _lookup_workspace(*meta_containers) or "/workspace"

    trace = SessionTrace(session_id=session_id, workspace_root=workspace_root)

    for tool_name, arguments, tool_id in acc.uses:
        output, is_error = acc.results.get(tool_id, ("", False)) if tool_id else ("", False)
        trace.tool_events.append(
            ToolEvent(tool_name=tool_name, arguments=arguments, output=output, is_error=is_error)
        )

    uncommitted: set[str] = set()
    for tool_name, arguments, tool_id in acc.uses:
        if tool_name in CREATED_TOOLS:
            path = _extract_path(arguments)
            if path:
                trace.files_created.add(path)
        elif tool_name in MODIFIED_TOOLS:
            path = _extract_path(arguments)
            if path:
                trace.files_modified.add(path)
        elif tool_name == "apply_patch":
            patch_text = next(
                (v for key in APPLY_PATCH_ARG_KEYS if (v := arguments.get(key)) is not None
                 and isinstance(v, str)),
                "",
            )
            if patch_text:
                created, modified = _apply_patch_paths(patch_text)
                trace.files_created |= created
                trace.files_modified |= modified
        if tool_name.lower() in COMMAND_TOOLS:
            command = _command_of(arguments)
            if command:
                output, _ = acc.results.get(tool_id, ("", False)) if tool_id else ("", False)
                uncommitted |= _git_status_uncommitted(command, output)

    uncommitted |= {
        f
        for container in meta_containers
        for f in (container.get("uncommitted_files") if isinstance(container, dict) else None) or ()
        if isinstance(f, str) and f
    }
    trace.uncommitted_files = uncommitted

    test_count = 0
    last_output: Optional[str] = None
    last_error: Optional[bool] = None
    for tool_name, arguments, tool_id in acc.uses:
        if tool_name.lower() not in COMMAND_TOOLS:
            continue
        command = _command_of(arguments)
        if not command or not any(marker in command for marker in TEST_COMMAND_MARKERS):
            continue
        test_count += 1
        output, is_error = acc.results.get(tool_id, ("", False)) if tool_id else ("", False)
        last_output, last_error = output, is_error
    trace.test_runs_count = test_count
    if test_count:
        trace.last_test_passed = _last_test_passed(last_output or "", last_error or False)

    trace.turns_count = acc.turns
    trace.duration_s = _duration(acc, meta_containers)
    return trace
