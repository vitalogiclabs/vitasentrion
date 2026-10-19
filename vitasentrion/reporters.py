"""Scorecard reporters: Console (ANSI), Markdown, and JSON."""

import json
from vitasentrion.models import Scorecard, Severity


def format_console(card: Scorecard) -> str:
    import os, sys
    use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if use_color:
        green, yellow, red, cyan, bold, dim, reset = (
            "\033[92m", "\033[93m", "\033[91m", "\033[96m", "\033[1m", "\033[2m", "\033[0m"
        )
    else:
        green = yellow = red = cyan = bold = dim = reset = ""
    w = 72
    lines = [
        "",
        bold + "━" * w + reset,
        f"{bold} 🛡️  VitaSentrion Scorecard — {cyan}{card.session_id}{reset}",
        f" {dim}A VitaLogic Labs Project (https://vitalogiclabs.com){reset}",
        bold + "━" * w + reset,
        "",
    ]
    v_color = green if card.verdict == Severity.PASS else (yellow if card.verdict == Severity.WARN else red)
    icon = "✅" if card.verdict == Severity.PASS else ("⚠️" if card.verdict == Severity.WARN else "❌")
    lines.append(f"  Verdict       : {icon} {v_color}{bold}{card.verdict.value}{reset}")
    lines.append(f"  Summary       : {green}{card.pass_count} passed{reset}, {yellow}{card.warn_count} warnings{reset}, {red}{card.fail_count} failed{reset}")
    lines.append(f"  Execution     : {card.total_turns} turns · {card.total_tool_calls} tool calls · {card.duration_s:.1f}s")
    lines.append("")
    lines.append(bold + "  Rule Findings:" + reset)
    lines.append("  " + "─" * (w - 4))

    if not card.findings:
        lines.append(f"  {green}✓ All guardrails passed cleanly. Findings: none.{reset}")
    else:
        for f in card.findings:
            badge = f"{red}FAIL{reset}" if f.severity == Severity.FAIL else f"{yellow}WARN{reset}"
            lines.append(f"  [{badge}] {bold}{f.rule_id} {f.rule_name}{reset}")
            lines.append(f"         {f.message}")
            for d in f.details:
                lines.append(f"         {dim}↳ {d}{reset}")
            lines.append("")
    lines.append(bold + "━" * w + reset)
    lines.append("")
    return "\n".join(lines)


def format_markdown(card: Scorecard) -> str:
    lines = [
        f"# VitaSentrion Scorecard — `{card.session_id}`",
        f"**Verdict:** `{card.verdict.value}` | **Passed:** {card.pass_count} | **Warnings:** {card.warn_count} | **Failed:** {card.fail_count}",
        f"*Audited by [VitaSentrion](https://github.com/vitalogiclabs/vitasentrion) by [VitaLogic Labs](https://vitalogiclabs.com)*",
        "",
    ]
    if not card.findings:
        lines.append("_No findings._")
    else:
        lines.extend([
            "| Rule | Name | Severity | Message | Details |",
            "| --- | --- | --- | --- | --- |",
        ])
        for f in card.findings:
            r_id = f.rule_id.replace("|", "\\|")
            r_name = f.rule_name.replace("|", "\\|")
            sev = f.severity.value
            msg = f.message.replace("|", "\\|").replace("\n", "<br>")
            if f.details:
                details_col = " <br> ".join([d.replace("|", "\\|").replace("\n", "<br>") for d in f.details])
            else:
                details_col = "none"
            lines.append(f"| {r_id} | {r_name} | {sev} | {msg} | {details_col} |")

    lines.extend([
        "",
        "### Execution Metrics",
        f"- **Model Turns:** {card.total_turns}",
        f"- **Tool Calls:** {card.total_tool_calls}",
        f"- **Duration:** {card.duration_s:.1f}s",
    ])
    return "\n".join(lines)


def format_json(card: Scorecard) -> str:
    data = {
        "session_id": card.session_id,
        "verdict": card.verdict.value,
        "is_clean": card.is_clean,
        "pass_count": card.pass_count,
        "warn_count": card.warn_count,
        "fail_count": card.fail_count,
        "total_turns": card.total_turns,
        "total_tool_calls": card.total_tool_calls,
        "duration_s": card.duration_s,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "message": f.message,
                "details": f.details,
            }
            for f in card.findings
        ],
    }
    return json.dumps(data, indent=2)


def render_scorecard(card: Scorecard, fmt: str = "console") -> str:
    fmt_lower = fmt.lower() if fmt else "console"
    if fmt_lower == "markdown":
        return format_markdown(card)
    elif fmt_lower == "json":
        return format_json(card)
    elif fmt_lower == "console":
        return format_console(card)
    raise ValueError(f"Unknown format: {fmt}")
