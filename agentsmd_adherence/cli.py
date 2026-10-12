"""Command-line interface.

Exit codes: 0 ok, 1 a CI gate failed, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from typing import List, Optional

from . import __version__
from . import report as rpt
from .check import VIOLATED, evaluate
from .demo import write_demo
from .rules import Extraction, extract_files, governance_chain, load_rules_json
from .session import SessionError, parse_file, summarize

FORMATS = ("console", "json", "markdown", "badge", "badge-endpoint")


def _agents_sources(args) -> List[str]:
    files: List[str] = list(args.agents or [])
    if args.repo:
        files = governance_chain(args.repo, args.path or ".") + files
    seen, out = set(), []
    for f in files:
        k = os.path.abspath(f)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _load_rules(args):
    sources = _agents_sources(args)
    for f in sources:
        if not os.path.isfile(f):
            raise FileNotFoundError("AGENTS.md not found: %s" % f)
    extraction: Optional[Extraction] = extract_files(sources) if sources else None
    rules = list(extraction.rules) if extraction else []
    for rj in args.rules_json or []:
        rules.extend(load_rules_json(rj))
        sources.append(rj)
    return sources, extraction, rules


def _emit(report: dict, fmt: str, verbose: bool) -> str:
    if fmt == "json":
        return rpt.render_json(report)
    if fmt == "markdown":
        return rpt.render_markdown(report)
    if fmt == "badge":
        return rpt.render_badge(report)
    if fmt == "badge-endpoint":
        return rpt.render_badge_endpoint(report)
    return rpt.render_console(report, verbose=verbose)


def _gate(report: dict, args) -> int:
    code = 0
    if args.min_grade and not rpt.meets(report["grade"], args.min_grade):
        print("gate: grade %s is below --min-grade %s" % (report["grade"], args.min_grade), file=sys.stderr)
        code = 1
    if args.fail_on_violation and report["rules"]["violated"]:
        print("gate: %d rule(s) violated (--fail-on-violation)" % report["rules"]["violated"], file=sys.stderr)
        code = 1
    if args.fail_on:
        sev = ("critical", "high", "medium", "low")
        threshold = sev.index(args.fail_on)
        bad = [r for r in report["results"] if r["status"] == VIOLATED and sev.index(r["severity"]) <= threshold]
        if bad:
            print("gate: %d violation(s) at %s or above (--fail-on)" % (len(bad), args.fail_on), file=sys.stderr)
            code = 1
    return code


def cmd_check(args) -> int:
    sources, extraction, rules = _load_rules(args)
    if not rules:
        print("error: no checkable rules found (give --agents, --repo or --rules-json)", file=sys.stderr)
        return 2
    events = parse_file(args.session)
    results = evaluate(rules, events, root=args.root)
    report = rpt.build(results, extraction, summarize(events), sources, args.session)
    text = _emit(report, args.format, args.verbose)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return _gate(report, args)


def cmd_rules(args) -> int:
    sources, extraction, rules = _load_rules(args)
    if args.format == "json":
        import json
        print(json.dumps({
            "sources": sources,
            "rules": [r.to_dict() for r in rules],
            "uncheckable": [d.__dict__ for d in (extraction.uncheckable if extraction else [])],
        }, indent=2))
        return 0
    print("Checkable rules (%d):" % len(rules))
    for r in rules:
        extra = (" before %s" % r.trigger) if r.trigger else ""
        pats = (" [%s]" % ", ".join(r.patterns)) if r.patterns and len(r.patterns) > 1 else ""
        print("  %-16s %s%s%s   (%s:%s)" % (r.kind, r.pattern, pats, extra, r.source, r.line))
    if extraction:
        un = extraction.uncheckable
        print("\nDirectives not machine-checkable (%d):" % len(un))
        for d in un:
            print("  - %s" % d.text)
        print("\ncoverage: %d of %d directives checkable" % (
            len(extraction.directives) - len(un), len(extraction.directives)))
    return 0


def cmd_demo(args) -> int:
    d = tempfile.mkdtemp(prefix="agentsmd-adherence-demo-")
    paths = write_demo(d)
    which = "bad" if args.bad else "good"
    print("demo files in %s\n" % d)
    ns = argparse.Namespace(
        agents=[paths["agents"]], repo=None, path=None, rules_json=None, session=paths[which],
        root="/work/shop", format=args.format, verbose=args.verbose, output=None,
        min_grade=None, fail_on_violation=False, fail_on=None)
    return cmd_check(ns)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentsmd-adherence",
        description="Check whether an agent session actually followed the rules in AGENTS.md.")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = p.add_subparsers(dest="cmd")

    def add_sources(sp):
        sp.add_argument("--agents", action="append", metavar="FILE",
                        help="AGENTS.md file (repeatable, root-first). agentsmd-resolve output works too.")
        sp.add_argument("--repo", metavar="DIR", help="repo root; collect the AGENTS.md chain down to --path")
        sp.add_argument("--path", metavar="SUBPATH", help="path inside --repo the agent worked in (default .)")
        sp.add_argument("--rules-json", action="append", metavar="FILE",
                        help="explicit rules in JSON (repeatable), added to extracted rules")

    c = sub.add_parser("check", help="check a session log against AGENTS.md")
    add_sources(c)
    c.add_argument("--session", required=True, metavar="JSONL", help="goose session JSONL or normalized JSONL")
    c.add_argument("--root", metavar="DIR", help="workspace root used in the log, to make paths repo-relative")
    c.add_argument("--format", choices=FORMATS, default="console")
    c.add_argument("--output", "-o", metavar="FILE")
    c.add_argument("--verbose", "-v", action="store_true", help="also list not-applicable rules")
    c.add_argument("--min-grade", choices=list("ABCDF"))
    c.add_argument("--fail-on-violation", action="store_true")
    c.add_argument("--fail-on", choices=("critical", "high", "medium", "low"),
                   help="fail when any violation is at this severity or above")
    c.set_defaults(func=cmd_check)

    r = sub.add_parser("rules", help="show the rules extracted from AGENTS.md")
    add_sources(r)
    r.add_argument("--format", choices=("console", "json"), default="console")
    r.set_defaults(func=cmd_rules)

    d = sub.add_parser("demo", help="run against the bundled sample (compliant by default)")
    d.add_argument("--bad", action="store_true", help="use the non-compliant session")
    d.add_argument("--format", choices=FORMATS, default="console")
    d.add_argument("--verbose", "-v", action="store_true")
    d.set_defaults(func=cmd_demo)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=lambda a: (print(__version__), 0)[1])
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except (FileNotFoundError, SessionError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
