"""Grading and rendering."""

from __future__ import annotations

import json
from typing import List, Optional
from urllib.parse import quote

from . import __version__
from .check import FOLLOWED, NOT_APPLICABLE, VIOLATED, RuleResult
from .rules import Extraction

PENALTY = {"critical": 40, "high": 25, "medium": 15, "low": 5}
GRADES = (("A", 90), ("B", 80), ("C", 70), ("D", 60), ("F", 0))
GRADE_ORDER = "ABCDF"
_COLORS = {"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red"}


def grade_for(score: float) -> str:
    for g, floor in GRADES:
        if score >= floor:
            return g
    return "F"


def meets(grade: str, minimum: str) -> bool:
    return GRADE_ORDER.index(grade) <= GRADE_ORDER.index(minimum)


def build(results: List[RuleResult], extraction: Optional[Extraction], session_stats: dict,
          sources: List[str], session_path: str) -> dict:
    violated = [r for r in results if r.status == VIOLATED]
    followed = [r for r in results if r.status == FOLLOWED]
    na = [r for r in results if r.status == NOT_APPLICABLE]
    penalty = sum(PENALTY[r.severity] for r in violated)
    score = max(0.0, 100.0 - penalty)
    if any(r.severity == "critical" for r in violated):
        score = min(score, 69.0)
    applicable = len(followed) + len(violated)
    adherence = (len(followed) / applicable) if applicable else 1.0
    counts = {s: sum(1 for r in violated if r.severity == s) for s in PENALTY}
    report = {
        "tool": "agentsmd-adherence",
        "version": __version__,
        "agents_files": sources,
        "session": session_path,
        "session_events": session_stats,
        "score": round(score, 1),
        "grade": grade_for(score),
        "adherence_rate": round(adherence, 3),
        "rules": {
            "total": len(results),
            "followed": len(followed),
            "violated": len(violated),
            "not_applicable": len(na),
        },
        "violations_by_severity": counts,
        "results": [r.to_dict() for r in results],
    }
    if extraction is not None:
        report["directives"] = {
            "total": len(extraction.directives),
            "checkable": sum(1 for d in extraction.directives if d.checkable),
            "coverage": round(extraction.coverage, 3),
            "uncheckable": [
                {"text": d.text, "source": d.source, "line": d.line} for d in extraction.uncheckable
            ],
        }
    return report


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False)


_ICON = {FOLLOWED: "PASS", VIOLATED: "FAIL", NOT_APPLICABLE: "n/a "}


def render_console(report: dict, verbose: bool = False) -> str:
    lines = []
    lines.append("agentsmd-adherence %s" % report["version"])
    lines.append("  rules from : %s" % (", ".join(report["agents_files"]) or "(none)"))
    lines.append("  session    : %s  (%s)" % (
        report["session"],
        ", ".join("%d %s" % (v, k) for k, v in report["session_events"].items() if k != "total"),
    ))
    lines.append("")
    order = {VIOLATED: 0, FOLLOWED: 1, NOT_APPLICABLE: 2}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for r in sorted(report["results"], key=lambda x: (order[x["status"]], sev_order[x["severity"]])):
        if r["status"] == NOT_APPLICABLE and not verbose:
            continue
        rule = r["rule"]
        sev = ("[%s]" % r["severity"]) if r["status"] == VIOLATED else ""
        lines.append("  %s %-16s %-22s %s" % (_ICON[r["status"]], rule["kind"], _short(rule["pattern"], 22), sev))
        if r["status"] == VIOLATED:
            lines.append("       rule: %s  (%s:%s)" % (_short(rule["text"], 70), rule["source"], rule["line"]))
            for e in r["evidence"][:5]:
                loc = ("log line %d" % e["line"]) if e["line"] else "session"
                lines.append("       - %s  [%s]" % (e["detail"], loc))
            if len(r["evidence"]) > 5:
                lines.append("       - ... %d more" % (len(r["evidence"]) - 5))
        elif r["status"] == NOT_APPLICABLE:
            lines.append("       (%s)" % r["note"])
    rc = report["rules"]
    lines.append("")
    lines.append("  rules: %d followed, %d violated, %d not applicable" % (
        rc["followed"], rc["violated"], rc["not_applicable"]))
    if "directives" in report:
        d = report["directives"]
        lines.append("  coverage: %d of %d directives are machine-checkable (%.0f%%)" % (
            d["checkable"], d["total"], d["coverage"] * 100))
    lines.append("  adherence: %.0f%%   score: %.1f   grade: %s" % (
        report["adherence_rate"] * 100, report["score"], report["grade"]))
    return "\n".join(lines)


def render_markdown(report: dict) -> str:
    out = []
    out.append("## AGENTS.md adherence: grade %s (%.1f)" % (report["grade"], report["score"]))
    out.append("")
    rc = report["rules"]
    out.append("- **Adherence:** %.0f%% of applicable rules followed" % (report["adherence_rate"] * 100))
    out.append("- **Rules:** %d followed, %d violated, %d not applicable" % (
        rc["followed"], rc["violated"], rc["not_applicable"]))
    if "directives" in report:
        d = report["directives"]
        out.append("- **Coverage:** %d of %d directives machine-checkable" % (d["checkable"], d["total"]))
    out.append("- **Session:** `%s`" % report["session"])
    out.append("")
    out.append("| Status | Severity | Kind | Rule | Evidence |")
    out.append("|---|---|---|---|---|")
    for r in report["results"]:
        if r["status"] == NOT_APPLICABLE:
            continue
        ev = "<br>".join(_md(e["detail"]) for e in r["evidence"][:3]) or "-"
        out.append("| %s | %s | %s | %s | %s |" % (
            "violated" if r["status"] == VIOLATED else "followed",
            r["severity"] if r["status"] == VIOLATED else "-",
            r["rule"]["kind"], _md(_short(r["rule"]["text"], 80)), ev))
    if report.get("directives", {}).get("uncheckable"):
        out.append("")
        out.append("<details><summary>Directives not machine-checkable (%d)</summary>" % len(
            report["directives"]["uncheckable"]))
        out.append("")
        for d in report["directives"]["uncheckable"]:
            out.append("- %s" % _md(d["text"]))
        out.append("")
        out.append("</details>")
    return "\n".join(out)


def render_badge(report: dict) -> str:
    label = quote("AGENTS.md adherence")
    msg = quote("%s %d%%" % (report["grade"], round(report["adherence_rate"] * 100)))
    return "https://img.shields.io/badge/%s-%s-%s" % (label, msg, _COLORS[report["grade"]])


def render_badge_endpoint(report: dict) -> str:
    return json.dumps({
        "schemaVersion": 1,
        "label": "AGENTS.md adherence",
        "message": "%s %d%%" % (report["grade"], round(report["adherence_rate"] * 100)),
        "color": _COLORS[report["grade"]],
    })


def _short(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


def _md(s: str) -> str:
    return s.replace("|", "\\|")
