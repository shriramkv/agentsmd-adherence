"""Parse agent session logs into a flat, ordered list of events.

Two input formats are accepted, line by line, and may even be mixed:

1. goose session JSONL. Each message line has ``role`` and a ``content`` list.
   Assistant ``toolRequest`` items carry ``toolCall.value.name`` and
   ``toolCall.value.arguments``. Shell tools (name ending in ``shell``) become
   ``command`` events; text-editor tools become ``write`` / ``read`` events;
   assistant ``text`` items become ``output`` events. Tool responses are not
   treated as agent output (reading a secret is not leaking it).

2. Normalized JSONL, so any agent can be checked after a small conversion::

       {"type": "command", "command": "pytest -q"}
       {"type": "write", "path": "src/app.py", "content": "..."}
       {"type": "read", "path": "README.md"}
       {"type": "output", "text": "Done."}

Lines that are neither (for example the goose metadata header) are skipped.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, List, Optional

COMMAND = "command"
WRITE = "write"
READ = "read"
OUTPUT = "output"

_EDIT_WRITE_CMDS = {"write", "str_replace", "insert", "undo_edit", "create", "edit", "append"}


@dataclass
class Event:
    kind: str
    value: str                 # command text, path, or output text
    index: int                 # position in the ordered event stream
    line: int                  # 1-based line in the source log
    content: str = ""          # written content (write events)
    tool: str = ""

    def snippet(self, width: int = 100) -> str:
        v = self.value.replace("\n", " ")
        return v if len(v) <= width else v[: width - 3] + "..."


class SessionError(ValueError):
    pass


def _from_tool_call(name: str, args: dict) -> List[tuple]:
    out = []
    lname = (name or "").lower()
    if not isinstance(args, dict):
        return out
    if lname.endswith("shell") or lname.endswith("__bash") or lname in ("bash", "shell", "run_command"):
        cmd = args.get("command") or args.get("cmd")
        if isinstance(cmd, str):
            out.append((COMMAND, cmd, ""))
        return out
    if "text_editor" in lname or "edit" in lname or "write" in lname or "file" in lname:
        path = args.get("path") or args.get("file_path") or args.get("filename")
        sub = (args.get("command") or "").lower()
        if isinstance(path, str):
            if sub == "view" or sub == "read":
                out.append((READ, path, ""))
            elif sub in _EDIT_WRITE_CMDS or not sub:
                content = args.get("file_text") or args.get("new_str") or args.get("content") or ""
                out.append((WRITE, path, content if isinstance(content, str) else ""))
        return out
    # Unknown tool: accept a bare "command" argument as a command.
    if isinstance(args.get("command"), str) and " " in args["command"]:
        out.append((COMMAND, args["command"], ""))
    return out


def _parse_obj(obj: dict) -> List[tuple]:
    """Return a list of (kind, value, content, tool) from one JSON object."""
    out: List[tuple] = []
    t = obj.get("type")
    if t in (COMMAND, WRITE, READ, OUTPUT) and "role" not in obj:
        if t == COMMAND and isinstance(obj.get("command"), str):
            out.append((COMMAND, obj["command"], "", obj.get("tool", "")))
        elif t in (WRITE, READ) and isinstance(obj.get("path"), str):
            out.append((t, obj["path"], obj.get("content", "") or "", obj.get("tool", "")))
        elif t == OUTPUT and isinstance(obj.get("text"), str):
            out.append((OUTPUT, obj["text"], "", ""))
        return out

    role = obj.get("role")
    content = obj.get("content")
    if role is None or not isinstance(content, list):
        return out
    for item in content:
        if not isinstance(item, dict):
            continue
        itype = item.get("type")
        if role == "assistant" and itype == "text" and isinstance(item.get("text"), str):
            out.append((OUTPUT, item["text"], "", ""))
        elif role == "assistant" and itype == "toolRequest":
            call = item.get("toolCall") or {}
            value = call.get("value") if isinstance(call, dict) else None
            if not isinstance(value, dict):
                continue
            name = value.get("name", "")
            for kind, val, cont in _from_tool_call(name, value.get("arguments") or {}):
                out.append((kind, val, cont, name))
    return out


def parse_lines(lines: Iterable[str]) -> List[Event]:
    events: List[Event] = []
    for lineno, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SessionError("line %d: invalid JSON (%s)" % (lineno, exc.msg))
        if not isinstance(obj, dict):
            continue
        for kind, val, cont, tool in _parse_obj(obj):
            events.append(Event(kind, val, len(events), lineno, cont, tool))
    return events


def parse_file(path: str) -> List[Event]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_lines(fh)


def summarize(events: List[Event]) -> dict:
    counts = {COMMAND: 0, WRITE: 0, READ: 0, OUTPUT: 0}
    for e in events:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    counts["total"] = len(events)
    return counts


def first(events: List[Event], kind: str) -> Optional[Event]:
    for e in events:
        if e.kind == kind:
            return e
    return None
