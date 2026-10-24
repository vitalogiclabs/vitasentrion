"""Core data models for VitaSentrion.

Implements section 1 of SPEC.md. Python 3.10+ standard library only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class ToolEvent:
    """A single tool invocation recorded in a session trace."""

    tool_name: str
    arguments: dict[str, Any]
    output: str = ""
    is_error: bool = False


@dataclass
class SessionTrace:
    """Aggregated record of one agent session to be evaluated."""

    session_id: str
    # "" = not stated by the source; resolved by the parsers/guard/cli chain
    # ([guard].workspace_root setting, payload cwd, or process cwd).
    workspace_root: str = ""
    tool_events: list[ToolEvent] = field(default_factory=list)
    files_modified: set[str] = field(default_factory=set)
    files_created: set[str] = field(default_factory=set)
    uncommitted_files: set[str] = field(default_factory=set)
    test_runs_count: int = 0
    last_test_passed: Optional[bool] = None
    weakened_assertions: int = 0
    leaked_secrets: list[str] = field(default_factory=list)
    turns_count: int = 0
    duration_s: float = 0.0


@dataclass
class Finding:
    """Result of a single rule evaluation that detected a problem."""

    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    details: list[str] = field(default_factory=list)


@dataclass
class Scorecard:
    """Final evaluation result for a session trace.

    Counts are per-rule: pass_count is the number of rules that produced no
    finding, warn_count / fail_count the number of findings at that severity.
    With the six rules of SPEC.md, the three counts always sum to 6.
    """

    session_id: str
    verdict: Severity
    pass_count: int
    warn_count: int
    fail_count: int
    findings: list[Finding] = field(default_factory=list)
    total_turns: int = 0
    total_tool_calls: int = 0
    duration_s: float = 0.0

    @property
    def is_clean(self) -> bool:
        return self.fail_count == 0
