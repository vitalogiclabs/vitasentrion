"""Declarative configuration for VitaSentrion (SPEC milestone M8, P0-a).

A ``vitasentrion.toml`` file discovered in the target directory / repo
root (or passed explicitly with ``--config``) tunes the guard, the rule
engine and the scanner.  When no config file exists, every value falls
back to the historical hardcoded defaults — behaviour is unchanged.

Schema (all keys optional)::

    [guard]
    max_consecutive_edits = 3      # R1 threshold (loop breaker + rules)
    state_ttl_seconds = 3600       # loop-breaker state TTL
    ignore_paths = [".scratch/*"]  # paths skipped by guard / scan

    [rules]
    R3 = "warn"                    # per-rule action: block | warn | ignore

    [custom]
    blocked_commands = []          # extra regexes treated as destructive (R4)
    secret_patterns = []           # extra regexes treated as secrets (R5)

Loading uses stdlib ``tomllib`` (Python 3.11+); on 3.10 it falls back to
``tomli`` if installed, and to the defaults (with a one-line stderr
warning) when no TOML parser is available.

Python 3.10+ standard library only.
"""
from __future__ import annotations

import fnmatch
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .models import Severity

__all__ = [
    "VitaConfig",
    "ConfigError",
    "ConfigWarning",
    "default_config",
    "load_config",
    "find_config_file",
    "path_matches_ignore",
    "rule_action",
    "effective_rule_severity",
    "CONFIG_FILENAME",
    "RULE_IDS",
    "RULE_ACTIONS",
]

CONFIG_FILENAME = "vitasentrion.toml"

# Rules whose action can be configured (R1-R7 engine/guard rules, the
# R8 events-chain check wired into `audit`, and the R9 repo-injection
# scan wired into `scan`).
RULE_IDS = ("R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9")
RULE_ACTIONS = ("block", "warn", "ignore")

# Defaults are exactly the constants that were hardcoded before M8.
DEFAULT_MAX_CONSECUTIVE_EDITS = 3
DEFAULT_STATE_TTL_SECONDS = 3600


class ConfigError(Exception):
    """Raised for an explicitly requested config file that is missing,
    malformed, or contains invalid values."""


class ConfigWarning(UserWarning):
    """Non-fatal configuration notice (e.g. no TOML parser available)."""


@dataclass
class VitaConfig:
    """Resolved configuration: explicit values merged over defaults."""

    max_consecutive_edits: int = DEFAULT_MAX_CONSECUTIVE_EDITS
    state_ttl_seconds: int = DEFAULT_STATE_TTL_SECONDS
    ignore_paths: tuple[str, ...] = ()
    rule_actions: dict[str, str] = field(default_factory=dict)
    blocked_commands: tuple[str, ...] = ()
    secret_patterns: tuple[str, ...] = ()
    source: Optional[str] = None  # path of the loaded file, None = defaults

    @property
    def is_default(self) -> bool:
        return self.source is None


def default_config() -> VitaConfig:
    """The hardcoded pre-M8 behaviour, as a config object."""
    return VitaConfig()


# ---------------------------------------------------------------------------
# TOML parsing (stdlib 3.11+, tomli fallback, defaults as last resort)
# ---------------------------------------------------------------------------

def _import_toml() -> Optional[Any]:
    try:  # Python 3.11+
        import tomllib  # type: ignore[import-not-found]
        return tomllib
    except ImportError:
        pass
    try:  # Python 3.10 fallback
        import tomli  # type: ignore[import-not-found]
        return tomli
    except ImportError:
        return None


def _require_int(section: str, key: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigError(
            f"[{section}].{key} must be a positive integer, got {value!r}"
        )
    return value


def _require_str_list(section: str, key: str, value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(v, str) and v for v in value
    ):
        raise ConfigError(f"[{section}].{key} must be a list of strings")
    return tuple(value)


def _validate_regexes(section: str, key: str, values: tuple[str, ...]) -> None:
    for pattern in values:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(
                f"[{section}].{key} contains invalid regex {pattern!r}: {exc}"
            ) from exc


def parse_config_dict(data: dict, source: Optional[str]) -> VitaConfig:
    """Validate a parsed TOML mapping into a :class:`VitaConfig`.

    Unknown sections and keys are rejected (fail loud) so a typo in a
    rule name or threshold never silently does nothing.
    """
    known_sections = {"guard", "rules", "custom"}
    for section in data:
        if section not in known_sections:
            raise ConfigError(f"unknown config section [{section}]")

    cfg = VitaConfig(source=source)

    guard = data.get("guard", {})
    if not isinstance(guard, dict):
        raise ConfigError("[guard] must be a table")
    for key in guard:
        if key not in (
            "max_consecutive_edits", "state_ttl_seconds", "ignore_paths"
        ):
            raise ConfigError(f"unknown key [guard].{key}")
    if "max_consecutive_edits" in guard:
        cfg.max_consecutive_edits = _require_int(
            "guard", "max_consecutive_edits", guard["max_consecutive_edits"]
        )
    if "state_ttl_seconds" in guard:
        cfg.state_ttl_seconds = _require_int(
            "guard", "state_ttl_seconds", guard["state_ttl_seconds"]
        )
    if "ignore_paths" in guard:
        cfg.ignore_paths = _require_str_list(
            "guard", "ignore_paths", guard["ignore_paths"]
        )

    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError("[rules] must be a table")
    for rule_id, action in rules.items():
        if rule_id not in RULE_IDS:
            raise ConfigError(
                f"unknown rule {rule_id!r} in [rules] "
                f"(valid: {', '.join(RULE_IDS)})"
            )
        if not isinstance(action, str) or action not in RULE_ACTIONS:
            raise ConfigError(
                f"[rules].{rule_id} must be one of {RULE_ACTIONS}, "
                f"got {action!r}"
            )
        cfg.rule_actions[rule_id] = action

    custom = data.get("custom", {})
    if not isinstance(custom, dict):
        raise ConfigError("[custom] must be a table")
    for key in custom:
        if key not in ("blocked_commands", "secret_patterns"):
            raise ConfigError(f"unknown key [custom].{key}")
    if "blocked_commands" in custom:
        cfg.blocked_commands = _require_str_list(
            "custom", "blocked_commands", custom["blocked_commands"]
        )
        _validate_regexes("custom", "blocked_commands", cfg.blocked_commands)
    if "secret_patterns" in custom:
        cfg.secret_patterns = _require_str_list(
            "custom", "secret_patterns", custom["secret_patterns"]
        )
        _validate_regexes("custom", "secret_patterns", cfg.secret_patterns)

    return cfg


# ---------------------------------------------------------------------------
# Discovery + loading
# ---------------------------------------------------------------------------

def find_config_file(start_dir: Path) -> Optional[Path]:
    """Search *start_dir* and its parents for ``vitasentrion.toml``.

    The walk stops at the repository root (the directory containing
    ``.git``) or the filesystem root, so a config from an unrelated
    parent directory is never picked up.
    """
    current = Path(start_dir).resolve()
    while True:
        candidate = current / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if (current / ".git").exists():  # repo root: stop here
            return None
        parent = current.parent
        if parent == current:  # filesystem root
            return None
        current = parent


def load_config(
    path: Optional[Path] = None, start_dir: Optional[Path] = None
) -> VitaConfig:
    """Load configuration for a target directory.

    ``path`` (an explicit ``--config`` override): the file MUST exist —
    a missing or invalid explicit config is a :class:`ConfigError`.
    Without ``path``, the file is searched from ``start_dir`` (default:
    cwd) upward; no file found means the hardcoded defaults apply.
    """
    if path is not None:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"config file not found: {p}")
        return _read_config_file(p)

    start = Path(start_dir) if start_dir is not None else Path.cwd()
    found = find_config_file(start)
    if found is None:
        return default_config()
    return _read_config_file(found)


def _read_config_file(path: Path) -> VitaConfig:
    toml = _import_toml()
    if toml is None:
        print(
            f"VitaSentrion: no TOML parser available (need Python 3.11+ or "
            f"'tomli'); ignoring {path} and using default settings.",
            file=sys.stderr,
        )
        return default_config()
    try:
        with path.open("rb") as fh:
            data = toml.load(fh)
    except Exception as exc:  # tomllib.TOMLDecodeError, OSError, ...
        raise ConfigError(f"invalid config file {path}: {exc}") from exc
    return parse_config_dict(data, str(path))


# ---------------------------------------------------------------------------
# Helpers shared by guard / rules / scanner
# ---------------------------------------------------------------------------

def path_matches_ignore(path: str, patterns: tuple[str, ...]) -> bool:
    """True when *path* matches any ignore pattern.

    A pattern is matched against the path as given *and* against every
    trailing path segment, so ``.scratch/*`` also matches
    ``/workspace/foo/.scratch/x.py``.
    """
    if not patterns or not path:
        return False
    normalized = path.replace("\\", "/")
    segments = normalized.lstrip("/").split("/")
    candidates = [normalized] + [
        "/".join(segments[i:]) for i in range(1, len(segments))
    ]
    for pattern in patterns:
        for candidate in candidates:
            if fnmatch.fnmatch(candidate, pattern):
                return True
    return False


def rule_action(
    config: Optional[VitaConfig], rule_id: str, default: str = "block"
) -> str:
    """Configured action for *rule_id* (default: *default*, normally
    ``"block"`` = current behaviour; R9's default is ``"warn"``)."""
    if config is None:
        return default
    return config.rule_actions.get(rule_id, default)


def effective_rule_severity(
    config: Optional[VitaConfig], rule_id: str, default: Severity
) -> Optional[Severity]:
    """Severity a finding for *rule_id* should carry, or None to skip.

    ``block`` -> the rule's own severity (unchanged behaviour),
    ``warn`` -> downgraded to WARN, ``ignore`` -> the rule does not run.
    """
    action = rule_action(config, rule_id)
    if action == "ignore":
        return None
    if action == "warn":
        return Severity.WARN
    return default
