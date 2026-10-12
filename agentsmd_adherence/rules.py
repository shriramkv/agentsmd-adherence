"""Extract checkable rules from AGENTS.md text.

AGENTS.md is free-form Markdown, so extraction is heuristic and deliberately
conservative. A line is a *directive* when it carries an RFC 2119-style modal
("must", "never", "do not", "always", "should", "avoid", "only"). A directive
becomes a *checkable rule* only when it also names something concrete in a
backtick code span (a command or a path), or when it is about secrets. Every
other directive is kept and reported as "uncheckable" so the coverage figure
stays honest.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# Rule kinds
FORBID_COMMAND = "forbid-command"
REQUIRE_COMMAND = "require-command"
PROTECT_PATH = "protect-path"
RESTRICT_WRITES = "restrict-writes"
NO_SECRET_LEAK = "no-secret-leak"

KINDS = (FORBID_COMMAND, REQUIRE_COMMAND, PROTECT_PATH, RESTRICT_WRITES, NO_SECRET_LEAK)

_NEG = r"must\s+not|must\s+never|mustn't|never|do\s+not|don't|should\s+not|shouldn't|avoid|not\s+allowed\s+to|forbidden"
_POS = r"must|always|required\s+to|need\s+to|should|ensure|make\s+sure"
_ONLY = r"only"

_NEG_RE = re.compile(r"\b(" + _NEG + r")\b", re.I)
_POS_RE = re.compile(r"\b(" + _POS + r")\b", re.I)
_ONLY_RE = re.compile(r"\b(" + _ONLY + r")\b", re.I)
_SHOULD_RE = re.compile(r"\b(should|shouldn't|avoid|prefer)\b", re.I)
# Imperative sentences ("Run `make test` ...") are directives too.
_IMPERATIVE_RE = re.compile(
    r"^(run|execute|use|install|keep|prefer|write|add|update|format|lint|test|follow|document|"
    r"commit|create|ensure|avoid|check|verify|place|put|name|open)\b", re.I)
_RUN_RE = re.compile(r"\b(run|runs|running|execute|invoke|call)\b", re.I)

_CODE_RE = re.compile(r"`([^`]+)`")

_CMD_VERB_RE = re.compile(r"\b(run|runs|running|execute|exec|invoke|call|use|using|type|launch)\b", re.I)
_PATH_VERB_RE = re.compile(
    r"\b(modify|modifying|edit|editing|change|changing|touch|touching|write|writing|"
    r"overwrite|delete|deleting|remove|removing|rename|commit\s+changes\s+to|update|updating|create\s+files)\b",
    re.I,
)
_SECRET_RE = re.compile(r"\b(secret|secrets|credential|credentials|api[\s_-]?keys?|tokens?|passwords?|private\s+keys?)\b", re.I)

# "before committing" style triggers for required commands
TRIGGERS: Dict[str, str] = {
    # allow global options such as `git -C dir commit` or `git --no-pager push`
    "commit": r"\bgit\s+(?:-[cC]\s+\S+\s+|--?[\w-]+(?:=\S+)?\s+)*commit\b",
    "push": r"\bgit\s+(?:-[cC]\s+\S+\s+|--?[\w-]+(?:=\S+)?\s+)*push\b",
    "pr": r"\bgh\s+pr\s+create\b",
}
_TRIGGER_RE = re.compile(
    r"\bbefore\s+(?:every\s+|each\s+|any\s+)?"
    r"(committing|commit|commits|pushing|push|pushes|opening\s+a\s+(?:pr|pull\s+request)|"
    r"creating\s+a\s+(?:pr|pull\s+request)|raising\s+a\s+(?:pr|pull\s+request))\b",
    re.I,
)

# Topics that escalate any violation to critical.
PROTECTED_TOPICS = (
    "force", "--force", "production", "prod", "secret", "credential", "token",
    "drop", "rm -rf", "delete", "main branch", "history", "sudo", "customer",
)

_KNOWN_BINARIES = {
    "git", "npm", "npx", "pnpm", "yarn", "pip", "pip3", "python", "python3", "pytest",
    "make", "cargo", "go", "docker", "kubectl", "terraform", "rm", "curl", "wget",
    "sudo", "ruff", "black", "mypy", "eslint", "prettier", "tox", "uv", "uvx", "gh",
    "bash", "sh", "chmod", "chown", "mvn", "gradle", "dotnet", "helm", "node", "deno",
}


@dataclass
class Rule:
    kind: str
    pattern: str
    text: str
    source: str = "<inline>"
    line: int = 0
    strength: str = "must"          # must | should
    trigger: Optional[str] = None   # commit | push | pr (require-command only)
    patterns: List[str] = field(default_factory=list)  # restrict-writes: allowed prefixes
    severity: Optional[str] = None  # explicit override (rules JSON)

    @property
    def id(self) -> str:
        base = self.pattern if self.kind != RESTRICT_WRITES else ",".join(self.patterns)
        tail = ("@" + self.trigger) if self.trigger else ""
        return "%s:%s%s" % (self.kind, base, tail)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        return d


@dataclass
class Directive:
    text: str
    source: str
    line: int
    checkable: bool


@dataclass
class Extraction:
    rules: List[Rule]
    directives: List[Directive]

    @property
    def uncheckable(self) -> List[Directive]:
        return [d for d in self.directives if not d.checkable]

    @property
    def coverage(self) -> float:
        if not self.directives:
            return 0.0
        return sum(1 for d in self.directives if d.checkable) / len(self.directives)


def _looks_like_path(span: str) -> bool:
    s = span.strip()
    if " " in s:
        return False
    if s.startswith("-"):
        return False
    if "/" in s or "*" in s:
        return True
    if s.startswith("."):
        return True
    return bool(re.search(r"\.[A-Za-z0-9]{1,6}$", s))


def _looks_like_command(span: str) -> bool:
    s = span.strip()
    first = s.split()[0] if s.split() else ""
    if first in _KNOWN_BINARIES:
        return True
    return " " in s and not _looks_like_path(s.split()[0])


def _strip_markdown(line: str) -> str:
    s = line.strip()
    s = re.sub(r"^(?:[-*+]|\d+[.)])\s+", "", s)  # list markers
    s = re.sub(r"^>\s*", "", s)
    return s


def _iter_lines(markdown: str):
    in_fence = False
    for i, raw in enumerate(markdown.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence or not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("<!--"):
            continue
        yield i, _strip_markdown(raw)


_PROTECTED_RE = re.compile(
    r"(?:^|[\s`'\"(])(" + "|".join(re.escape(t) for t in PROTECTED_TOPICS) + r")(?=$|[\s`'\".,;:)])",
    re.I,
)


def _is_protected(text: str) -> bool:
    return bool(_PROTECTED_RE.search(text))


def extract(markdown: str, source: str = "<inline>") -> Extraction:
    """Extract rules and directives from one AGENTS.md document."""
    rules: List[Rule] = []
    directives: List[Directive] = []
    for lineno, text in _iter_lines(markdown):
        neg = _NEG_RE.search(text)
        pos = _POS_RE.search(text) or _IMPERATIVE_RE.search(text)
        only = _ONLY_RE.search(text)
        if not (neg or pos or only):
            continue
        strength = "should" if _SHOULD_RE.search(text) else "must"
        spans = [s.strip() for s in _CODE_RE.findall(text) if s.strip()]
        found: List[Rule] = []

        cmd_verb = _CMD_VERB_RE.search(text)
        path_verb = _PATH_VERB_RE.search(text)

        if neg:
            for span in spans:
                as_path = _looks_like_path(span)
                as_cmd = _looks_like_command(span)
                # Verb nearest before the span decides when both readings are possible.
                pos_span = text.find("`" + span)
                cmd_before = [m.start() for m in _CMD_VERB_RE.finditer(text) if m.start() < pos_span]
                path_before = [m.start() for m in _PATH_VERB_RE.finditer(text) if m.start() < pos_span]
                last_cmd = max(cmd_before) if cmd_before else -1
                last_path = max(path_before) if path_before else -1
                if as_path and (last_path > last_cmd or (not as_cmd and last_cmd < 0)):
                    found.append(Rule(PROTECT_PATH, span, text, source, lineno, strength))
                elif as_cmd or last_cmd >= 0:
                    found.append(Rule(FORBID_COMMAND, span, text, source, lineno, strength))
                elif as_path or last_path >= 0:
                    # e.g. "Do not modify `LICENSE`": no slash or extension, but a path verb.
                    found.append(Rule(PROTECT_PATH, span, text, source, lineno, strength))
            if _SECRET_RE.search(text) and not found:
                found.append(Rule(NO_SECRET_LEAK, "secrets", text, source, lineno, strength))
        elif only and path_verb and spans:
            prefixes = [s for s in spans if _looks_like_path(s)]
            if prefixes:
                found.append(Rule(RESTRICT_WRITES, prefixes[0], text, source, lineno, strength,
                                  patterns=prefixes))
        elif pos and spans and _RUN_RE.search(text):
            tm = _TRIGGER_RE.search(text)
            trigger = None
            if tm:
                word = tm.group(1).lower()
                if word.startswith("commit"):
                    trigger = "commit"
                elif word.startswith("push"):
                    trigger = "push"
                else:
                    trigger = "pr"
            for span in spans:
                if _looks_like_command(span) or not _looks_like_path(span):
                    found.append(Rule(REQUIRE_COMMAND, span, text, source, lineno, strength,
                                      trigger=trigger))

        directives.append(Directive(text, source, lineno, bool(found)))
        rules.extend(found)
    return Extraction(rules=_dedupe(rules), directives=directives)


def _dedupe(rules: List[Rule]) -> List[Rule]:
    seen = {}
    for r in rules:
        if r.id not in seen:
            seen[r.id] = r
    return list(seen.values())


def extract_files(paths: List[str]) -> Extraction:
    """Extract from several AGENTS.md files (root-first order). Union of rules."""
    rules: List[Rule] = []
    directives: List[Directive] = []
    for p in paths:
        with open(p, "r", encoding="utf-8") as fh:
            ex = extract(fh.read(), source=p)
        rules.extend(ex.rules)
        directives.extend(ex.directives)
    return Extraction(rules=_dedupe(rules), directives=directives)


def governance_chain(repo: str, subpath: str = ".") -> List[str]:
    """Return AGENTS.md files from repo root down to repo/subpath (root-first)."""
    repo = os.path.abspath(repo)
    target = os.path.abspath(os.path.join(repo, subpath))
    if os.path.isfile(target):
        target = os.path.dirname(target)
    if os.path.commonpath([repo, target]) != repo:
        raise ValueError("path %r is outside repo %r" % (subpath, repo))
    rel = os.path.relpath(target, repo)
    parts = [] if rel == "." else rel.split(os.sep)
    chain = []
    cur = repo
    for i in range(len(parts) + 1):
        cand = os.path.join(cur, "AGENTS.md")
        if os.path.isfile(cand):
            chain.append(cand)
        if i < len(parts):
            cur = os.path.join(cur, parts[i])
    return chain


def load_rules_json(path: str) -> List[Rule]:
    """Load explicit rules: [{"kind": ..., "pattern": ..., "trigger": ..., ...}]."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("rules", [])
    out = []
    for i, item in enumerate(data):
        kind = item.get("kind")
        if kind not in KINDS:
            raise ValueError("rule %d: unknown kind %r (expected one of %s)" % (i, kind, ", ".join(KINDS)))
        trigger = item.get("trigger")
        if trigger is not None and trigger not in TRIGGERS:
            raise ValueError("rule %d: unknown trigger %r" % (i, trigger))
        patterns = item.get("patterns") or ([item["pattern"]] if kind == RESTRICT_WRITES and item.get("pattern") else [])
        out.append(Rule(
            kind=kind,
            pattern=item.get("pattern", patterns[0] if patterns else "secrets"),
            text=item.get("text", "(explicit rule from %s)" % os.path.basename(path)),
            source=path,
            line=0,
            strength=item.get("strength", "must"),
            trigger=trigger,
            patterns=patterns,
            severity=item.get("severity"),
        ))
    return out


def is_protected(rule: Rule) -> bool:
    return _is_protected(rule.text) or _is_protected(rule.pattern)
