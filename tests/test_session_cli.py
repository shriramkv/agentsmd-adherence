import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from agentsmd_adherence.cli import main
from agentsmd_adherence.demo import AGENTS_MD, BAD_SESSION, GOOD_SESSION, write_demo
from agentsmd_adherence.session import COMMAND, OUTPUT, READ, WRITE, SessionError, parse_lines


def _put(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class SessionParseTests(unittest.TestCase):
    def test_goose_format(self):
        ev = parse_lines(GOOD_SESSION.splitlines())
        kinds = [e.kind for e in ev]
        self.assertEqual(kinds.count(COMMAND), 4)
        self.assertEqual(kinds.count(WRITE), 2)
        self.assertEqual(kinds.count(OUTPUT), 2)
        self.assertEqual(ev[0].kind, OUTPUT)
        self.assertEqual([e.index for e in ev], list(range(len(ev))))

    def test_tool_responses_are_not_output(self):
        ev = parse_lines(BAD_SESSION.splitlines())
        outs = [e.value for e in ev if e.kind == OUTPUT]
        self.assertFalse(any(o.startswith("AWS_ACCESS_KEY_ID") for o in outs))

    def test_text_editor_view_is_read(self):
        line = json.dumps({"role": "assistant", "content": [{"type": "toolRequest", "toolCall": {
            "value": {"name": "developer__text_editor", "arguments": {"command": "view", "path": "a.py"}}}}]})
        self.assertEqual(parse_lines([line])[0].kind, READ)

    def test_normalized_format(self):
        lines = [json.dumps({"type": "command", "command": "ls"}), json.dumps({"type": "write", "path": "x"})]
        self.assertEqual([e.kind for e in parse_lines(lines)], [COMMAND, WRITE])

    def test_invalid_json(self):
        with self.assertRaises(SessionError):
            parse_lines(["{not json"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = write_demo(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_good_session_grades_a(self):
        code, out, _ = run(["check", "--agents", self.paths["agents"], "--session", self.paths["good"],
                            "--format", "json", "--min-grade", "A", "--fail-on-violation"])
        self.assertEqual(code, 0)
        rep = json.loads(out)
        self.assertEqual(rep["grade"], "A")
        self.assertEqual(rep["rules"]["violated"], 0)
        self.assertEqual(rep["adherence_rate"], 1.0)

    def test_bad_session_fails_gate(self):
        code, out, err = run(["check", "--agents", self.paths["agents"], "--session", self.paths["bad"],
                              "--root", "/work/shop", "--format", "json", "--min-grade", "C"])
        self.assertEqual(code, 1)
        rep = json.loads(out)
        self.assertEqual(rep["grade"], "F")
        self.assertEqual(rep["violations_by_severity"]["critical"], 3)  # force-push, secret, sudo
        violated = {r["rule"]["kind"] + ":" + r["rule"]["pattern"] for r in rep["results"] if r["status"] == "violated"}
        self.assertIn("forbid-command:sudo", violated)
        self.assertIn("protect-path:migrations/", violated)
        self.assertIn("below --min-grade C", err)

    def test_fail_on_threshold(self):
        code, _, _ = run(["check", "--agents", self.paths["agents"], "--session", self.paths["bad"],
                          "--format", "json", "--fail-on", "critical"])
        self.assertEqual(code, 1)

    def test_markdown_and_badge(self):
        _, md, _ = run(["check", "--agents", self.paths["agents"], "--session", self.paths["bad"],
                        "--format", "markdown"])
        self.assertIn("## AGENTS.md adherence: grade F", md)
        self.assertIn("not machine-checkable", md)
        _, badge, _ = run(["check", "--agents", self.paths["agents"], "--session", self.paths["good"],
                           "--format", "badge"])
        self.assertTrue(badge.strip().startswith("https://img.shields.io/badge/"))
        _, ep, _ = run(["check", "--agents", self.paths["agents"], "--session", self.paths["good"],
                        "--format", "badge-endpoint"])
        self.assertEqual(json.loads(ep)["schemaVersion"], 1)

    def test_repo_chain(self):
        repo = os.path.join(self.tmp.name, "repo")
        os.makedirs(os.path.join(repo, "svc"))
        _put(os.path.join(repo, "AGENTS.md"), "- Never run `git push --force`.\n")
        _put(os.path.join(repo, "svc", "AGENTS.md"), "- Do not use `sudo`.\n")
        code, out, _ = run(["rules", "--repo", repo, "--path", "svc", "--format", "json"])
        self.assertEqual(code, 0)
        pats = [r["pattern"] for r in json.loads(out)["rules"]]
        self.assertEqual(pats, ["git push --force", "sudo"])

    def test_no_rules_is_usage_error(self):
        empty = os.path.join(self.tmp.name, "EMPTY.md")
        _put(empty, "# nothing here\n")
        code, _, err = run(["check", "--agents", empty, "--session", self.paths["good"]])
        self.assertEqual(code, 2)
        self.assertIn("no checkable rules", err)

    def test_missing_file(self):
        code, _, err = run(["check", "--agents", "/nope/AGENTS.md", "--session", self.paths["good"]])
        self.assertEqual(code, 2)

    def test_demo_runs(self):
        code, out, _ = run(["demo", "--bad"])
        self.assertEqual(code, 0)
        self.assertIn("grade: F", out)

    def test_agents_md_sample_is_sane(self):
        self.assertIn("Never run `git push --force`", AGENTS_MD)


if __name__ == "__main__":
    unittest.main()
