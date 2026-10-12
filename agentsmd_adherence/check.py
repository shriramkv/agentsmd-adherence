"""Evaluate extracted rules against a parsed session."""

from __future__ import annotations

import fnmatch
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional

from .rules import (
    FORBID_COMMAND, NO_SECRET_LEAK, PROTECT_PATH, REQUIRE_COMMAND, RESTRICT_WRITES,
    TRIGGERS, Rule, is_protected,
)
from .session import COMMAND, OUTPUT, WRITE, Event

FOLLOWED = "followed"
VIOLATED = "violated"
NOT_APPLICABLE = "not-applicable"

SEVERITIES = ("critical", "high", "medium", "low")
_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai-style-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

# Shell verbs that write to (or destroy) the paths given as arguments.
_WRITE_VERBS = {"rm", "rmdir", "mv", "cp", "touch", "truncate", "tee", "chmod", "chown",
                "unlink", "shred", "ln", "install", "mkdir"}
_SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")


@dataclass
class Evidence:
    event_index: int
    line: int
    detail: str


@dataclass
class RuleResult:
    rule: Rule
    status: str
    severity: str
    evidence: List[Evidence] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule.to_dict(),
            "status": self.status,
            "severity": self.severity,
            "note": self.note,
            "evidence": [e.__dict__ for e in self.evidence],
        }


# ---------------------------------------------------------------- tokenizing

def _tokens(text: str) -> List[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def segments(command: str) -> List[str]:
    """Split a shell line into simple-command segments (&&, ||, ;, |)."""
    return [s for s in _SEGMENT_SPLIT.split(command.strip()) if s]


def _short_flags(tok: str) -> set:
    if tok.startswith("-") and not tok.startswith("--") and len(tok) > 1:
        return set(tok[1:])
    return set()


_LONG_TO_SHORT = {"--force": "f", "--recursive": "r", "--all": "a", "--hard": None}


def command_matches(pattern: str, command: str) -> bool:
    """True when ``pattern`` matches any simple-command segment of ``command``.

    Non-flag pattern tokens must appear in order (fnmatch globs allowed).
    Long flags match exactly or via their common short alias (``--force`` ~ ``-f``).
    Short flag clusters match as letter sets (``-rf`` ~ ``-fr`` ~ ``-r -f``).
    """
    ptoks = _tokens(pattern)
    if not ptoks:
        return False
    for seg in segments(command):
        ctoks = _tokens(seg)
        if _segment_matches(ptoks, ctoks):
            return True
        # `sudo X ...` also counts as running `X ...`
        if ctoks and ctoks[0] == "sudo" and _segment_matches(ptoks, ctoks[1:]):
            return True
    return False


def _segment_matches(ptoks: List[str], ctoks: List[str]) -> bool:
    plain_p = [t for t in ptoks if not t.startswith("-")]
    flags_p = [t for t in ptoks if t.startswith("-")]
    plain_c = [t for t in ctoks if not t.startswith("-")]
    if not plain_p:
        return False
    # The first plain token is the program; it must be the segment's program.
    if not plain_c or not fnmatch.fnmatchcase(os.path.basename(plain_c[0]), plain_p[0]):
        return False
    # Remaining plain tokens: ordered subsequence.
    it = iter(plain_c[1:])
    for want in plain_p[1:]:
        if not any(fnmatch.fnmatchcase(have, want) for have in it):
            return False
    c_short = set()
    for t in ctoks:
        c_short |= _short_flags(t)
    c_long = {t.split("=", 1)[0] for t in ctoks if t.startswith("--")}
    for f in flags_p:
        if f.startswith("--"):
            name = f.split("=", 1)[0]
            alias = _LONG_TO_SHORT.get(name)
            if name in c_long:
                continue
            if alias and alias in c_short:
                continue
            return False
        letters = _short_flags(f)
        for letter in letters:
            longs = [k for k, v in _LONG_TO_SHORT.items() if v == letter]
            if letter not in c_short and not any(l in c_long for l in longs):
                return False
    return True


# ---------------------------------------------------------------- paths

def normalize_path(path: str, root: Optional[str] = None) -> str:
    p = path.replace("\\", "/")
    if root and os.path.isabs(p):
        r = os.path.abspath(root).replace("\\", "/").rstrip("/") + "/"
        if p.startswith(r):
            p = p[len(r):]
    while p.startswith("./"):
        p = p[2:]
    return p


def path_matches(pattern: str, path: str) -> bool:
    """Match a protected/allowed pattern against a (normalized) file path.

    ``dir/`` or a bare name without glob or extension is a directory prefix.
    Globs are tried against the full path, the basename, and every suffix, so
    absolute paths from logs still match repo-relative patterns.
    """
    pat = pattern.replace("\\", "/").strip()
    while pat.startswith("./"):
        pat = pat[2:]
    p = path.replace("\\", "/")
    suffixes = []
    parts = p.split("/")
    for i in range(len(parts)):
        suffixes.append("/".join(parts[i:]))
    if any(ch in pat for ch in "*?["):
        pat_core = pat[:-3] if pat.endswith("/**") else None
        for s in suffixes:
            if fnmatch.fnmatchcase(s, pat):
                return True
            if pat_core and (s == pat_core or s.startswith(pat_core + "/")):
                return True
        return fnmatch.fnmatchcase(parts[-1], pat) if "/" not in pat else False
    is_dir = pat.endswith("/") or not re.search(r"\.[A-Za-z0-9]{1,6}$", pat) and not pat.startswith(".")
    core = pat.rstrip("/")
    for s in suffixes:
        if s == core:
            return True
        if is_dir and s.startswith(core + "/"):
            return True
    return False


def shell_write_targets(command: str) -> List[str]:
    """Best-effort list of paths a shell line writes, moves or deletes."""
    targets: List[str] = []
    for seg in segments(command):
        # redirections
        for m in re.finditer(r"(?:^|[^0-9&>])>>?\s*([^\s;&|]+)", seg):
            t = m.group(1)
            if t not in ("/dev/null", "&1", "&2"):
                targets.append(t)
        toks = _tokens(seg)
        if toks and toks[0] == "sudo":
            toks = toks[1:]
        if not toks:
            continue
        prog = os.path.basename(toks[0])
        args = [t for t in toks[1:] if not t.startswith("-") and ">" not in t]
        if prog in _WRITE_VERBS:
            if prog in ("cp", "install", "ln") and args:
                targets.append(args[-1])
            else:
                targets.extend(args)
        elif prog == "sed" and any(t == "-i" or t.startswith("-i") for t in toks[1:]):
            targets.extend(args[1:] if args else [])
        elif prog == "git" and len(toks) > 1 and toks[1] in ("rm", "mv"):
            targets.extend([a for a in args[1:]])
        elif prog in ("perl",) and any(t.startswith("-i") or t == "-pi" for t in toks[1:]):
            targets.extend(args[1:])
    return targets


def find_secrets(text: str) -> List[str]:
    hits = []
    for name, rx in SECRET_PATTERNS:
        if rx.search(text or ""):
            hits.append(name)
    return hits


# ---------------------------------------------------------------- evaluation

def _base_severity(rule: Rule) -> str:
    if rule.severity in SEVERITIES:
        return rule.severity
    if rule.kind == NO_SECRET_LEAK:
        sev = "critical"
    elif rule.kind == REQUIRE_COMMAND and not rule.trigger:
        sev = "medium"
    else:
        sev = "high"
    if rule.strength == "should":
        sev = _DOWNGRADE[sev]
    if is_protected(rule) and rule.strength == "must":
        sev = "critical"
    return sev


def _write_events(events: List[Event], root: Optional[str]):
    """Yield (event, normalized_path, how) for every write, incl. shell writes."""
    for e in events:
        if e.kind == WRITE:
            yield e, normalize_path(e.value, root), "file write"
        elif e.kind == COMMAND:
            for t in shell_write_targets(e.value):
                yield e, normalize_path(t, root), "shell: " + e.snippet(60)


def evaluate_rule(rule: Rule, events: List[Event], root: Optional[str] = None) -> RuleResult:
    sev = _base_severity(rule)
    ev: List[Evidence] = []

    if rule.kind == FORBID_COMMAND:
        for e in events:
            if e.kind == COMMAND and command_matches(rule.pattern, e.value):
                ev.append(Evidence(e.index, e.line, "ran: " + e.snippet()))
        if not any(e.kind == COMMAND for e in events):
            return RuleResult(rule, NOT_APPLICABLE, sev, note="session ran no commands")
        return RuleResult(rule, VIOLATED if ev else FOLLOWED, sev, ev)

    if rule.kind == REQUIRE_COMMAND:
        if rule.trigger:
            trig = re.compile(TRIGGERS[rule.trigger])
            last = -1
            triggers = [e for e in events if e.kind == COMMAND and trig.search(e.value)]
            if not triggers:
                return RuleResult(rule, NOT_APPLICABLE, sev, note="no %s in session" % rule.trigger)
            for t in triggers:
                ok = any(
                    e.kind == COMMAND and last < e.index < t.index and command_matches(rule.pattern, e.value)
                    for e in events
                )
                # The required command chained on the same line before the trigger also counts.
                if not ok:
                    segs = segments(t.value)
                    for i, s in enumerate(segs):
                        if trig.search(s):
                            ok = any(command_matches(rule.pattern, x) for x in segs[:i])
                            break
                if not ok:
                    ev.append(Evidence(t.index, t.line, "%s without prior `%s`: %s" % (
                        rule.trigger, rule.pattern, t.snippet(70))))
                last = t.index
            return RuleResult(rule, VIOLATED if ev else FOLLOWED, sev, ev)
        if not any(e.kind == WRITE for e in events) and not any(
                shell_write_targets(e.value) for e in events if e.kind == COMMAND):
            return RuleResult(rule, NOT_APPLICABLE, sev, note="session changed no files")
        if any(e.kind == COMMAND and command_matches(rule.pattern, e.value) for e in events):
            return RuleResult(rule, FOLLOWED, sev)
        return RuleResult(rule, VIOLATED, sev,
                          [Evidence(-1, 0, "`%s` never ran although files changed" % rule.pattern)])

    if rule.kind == PROTECT_PATH:
        any_write = False
        for e, p, how in _write_events(events, root):
            any_write = True
            if path_matches(rule.pattern, p):
                ev.append(Evidence(e.index, e.line, "%s -> %s" % (how, p)))
        if not any_write:
            return RuleResult(rule, NOT_APPLICABLE, sev, note="session changed no files")
        return RuleResult(rule, VIOLATED if ev else FOLLOWED, sev, ev)

    if rule.kind == RESTRICT_WRITES:
        any_write = False
        allowed = rule.patterns or [rule.pattern]
        for e, p, how in _write_events(events, root):
            any_write = True
            if os.path.isabs(p):
                # Cannot tell without --root; fall back to suffix matching.
                pass
            if not any(path_matches(a, p) for a in allowed):
                ev.append(Evidence(e.index, e.line, "%s -> %s (outside %s)" % (how, p, ", ".join(allowed))))
        if not any_write:
            return RuleResult(rule, NOT_APPLICABLE, sev, note="session changed no files")
        return RuleResult(rule, VIOLATED if ev else FOLLOWED, sev, ev)

    if rule.kind == NO_SECRET_LEAK:
        for e in events:
            texts = []
            if e.kind in (OUTPUT, COMMAND):
                texts.append(e.value)
            if e.kind == WRITE:
                texts.append(e.content)
            for t in texts:
                hits = find_secrets(t)
                if hits:
                    where = {"output": "agent message", "command": "command", "write": "written to " + e.value}[e.kind]
                    ev.append(Evidence(e.index, e.line, "%s in %s (value redacted)" % (", ".join(hits), where)))
        return RuleResult(rule, VIOLATED if ev else FOLLOWED, sev, ev)

    raise ValueError("unknown rule kind %r" % rule.kind)


def evaluate(rules: List[Rule], events: List[Event], root: Optional[str] = None) -> List[RuleResult]:
    return [evaluate_rule(r, events, root) for r in rules]
