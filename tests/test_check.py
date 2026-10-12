import json
import unittest

from agentsmd_adherence.check import (
    FOLLOWED, NOT_APPLICABLE, VIOLATED, command_matches, evaluate_rule, path_matches,
    shell_write_targets,
)
from agentsmd_adherence.rules import Rule, extract
from agentsmd_adherence.session import parse_lines


def norm(*items):
    return parse_lines(json.dumps(i) for i in items)


def cmd(c):
    return {"type": "command", "command": c}


def write(p, content=""):
    return {"type": "write", "path": p, "content": content}


def rule(md):
    return extract(md).rules[0]


class CommandMatchTests(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(command_matches("git push --force", "git push --force origin main"))

    def test_short_alias(self):
        self.assertTrue(command_matches("git push --force", "git push -f origin main"))

    def test_flag_cluster_order(self):
        self.assertTrue(command_matches("rm -rf", "rm -fr build/"))
        self.assertTrue(command_matches("rm -rf", "rm -r -f build/"))

    def test_chained_segment(self):
        self.assertTrue(command_matches("git push --force", "cd repo && git push --force"))

    def test_no_false_positive(self):
        self.assertFalse(command_matches("git push --force", "git push origin main"))
        self.assertFalse(command_matches("pytest", "echo pytest"))

    def test_sudo_prefix(self):
        self.assertTrue(command_matches("pip install", "sudo pip install x"))
        self.assertTrue(command_matches("sudo", "sudo pip install x"))

    def test_glob_token(self):
        self.assertTrue(command_matches("kubectl delete *", "kubectl delete pod web-1"))


class PathTests(unittest.TestCase):
    def test_dir_prefix(self):
        self.assertTrue(path_matches("migrations/", "migrations/0001.py"))
        self.assertTrue(path_matches("migrations", "app/migrations/0001.py"))
        self.assertFalse(path_matches("migrations/", "src/migrationsx.py"))

    def test_file(self):
        self.assertTrue(path_matches(".env", ".env"))
        self.assertTrue(path_matches(".env", "/work/app/.env"))
        self.assertFalse(path_matches(".env", ".env.example"))

    def test_glob(self):
        self.assertTrue(path_matches("*.lock", "poetry.lock"))
        self.assertTrue(path_matches("vendor/**", "vendor/lib/a.go"))

    def test_shell_targets(self):
        t = shell_write_targets("rm -rf migrations/old && echo hi > notes.txt; sed -i 's/a/b/' cfg.ini")
        self.assertIn("migrations/old", t)
        self.assertIn("notes.txt", t)
        self.assertIn("cfg.ini", t)
        self.assertEqual(shell_write_targets("ls -la > /dev/null"), [])


class EvaluateTests(unittest.TestCase):
    def test_forbid_violated(self):
        r = evaluate_rule(rule("Never run `git push --force`."), norm(cmd("git push -f")))
        self.assertEqual(r.status, VIOLATED)
        self.assertEqual(r.severity, "critical")

    def test_forbid_na_without_commands(self):
        r = evaluate_rule(rule("Never run `git push --force`."), norm(write("a.py")))
        self.assertEqual(r.status, NOT_APPLICABLE)

    def test_require_before_commit_followed(self):
        ev = norm(cmd("pytest -q"), cmd("git commit -m x"))
        self.assertEqual(evaluate_rule(rule("Always run `pytest -q` before committing."), ev).status, FOLLOWED)

    def test_require_before_commit_same_line(self):
        ev = norm(cmd("pytest -q && git commit -m x"))
        self.assertEqual(evaluate_rule(rule("Always run `pytest -q` before committing."), ev).status, FOLLOWED)

    def test_require_each_commit(self):
        ev = norm(cmd("pytest -q"), cmd("git commit -m one"), write("a.py"), cmd("git commit -m two"))
        r = evaluate_rule(rule("Always run `pytest -q` before committing."), ev)
        self.assertEqual(r.status, VIOLATED)
        self.assertEqual(len(r.evidence), 1)
        self.assertIn("two", r.evidence[0].detail)

    def test_require_after_commit_does_not_count(self):
        ev = norm(cmd("git commit -m x"), cmd("pytest -q"))
        self.assertEqual(evaluate_rule(rule("Always run `pytest -q` before committing."), ev).status, VIOLATED)

    def test_require_no_trigger_na(self):
        ev = norm(cmd("pytest -q"))
        self.assertEqual(evaluate_rule(rule("Always run `pytest -q` before committing."), ev).status,
                         NOT_APPLICABLE)

    def test_git_global_option_trigger(self):
        ev = norm(cmd("git -C repo commit -m x"))
        self.assertEqual(evaluate_rule(rule("Always run `make test` before committing."), ev).status, VIOLATED)

    def test_standalone_required(self):
        r = rule("Run `ruff check .` after edits.")
        self.assertEqual(evaluate_rule(r, norm(write("a.py"))).status, VIOLATED)
        self.assertEqual(evaluate_rule(r, norm(write("a.py"), cmd("ruff check ."))).status, FOLLOWED)
        self.assertEqual(evaluate_rule(r, norm(cmd("ls"))).status, NOT_APPLICABLE)
        self.assertEqual(evaluate_rule(r, norm(write("a.py"))).severity, "medium")

    def test_protect_path_via_shell(self):
        r = evaluate_rule(rule("Never edit files under `migrations/`."), norm(cmd("rm migrations/0003.py")))
        self.assertEqual(r.status, VIOLATED)

    def test_protect_path_with_root(self):
        r = evaluate_rule(rule("Never edit files under `migrations/`."),
                          norm(write("/w/app/migrations/1.py")), root="/w/app")
        self.assertEqual(r.status, VIOLATED)
        self.assertIn("migrations/1.py", r.evidence[0].detail)

    def test_restrict_writes(self):
        r = rule("Only modify files in `src/` and `tests/`.")
        self.assertEqual(evaluate_rule(r, norm(write("src/a.py"), write("tests/t.py"))).status, FOLLOWED)
        bad = evaluate_rule(r, norm(write("src/a.py"), write("setup.cfg")))
        self.assertEqual(bad.status, VIOLATED)
        self.assertIn("setup.cfg", bad.evidence[0].detail)

    def test_secret_in_output_redacted(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"
        r = evaluate_rule(rule("Never print secrets."), norm({"type": "output", "text": "key " + key}))
        self.assertEqual(r.status, VIOLATED)
        self.assertNotIn(key, r.evidence[0].detail)

    def test_secret_written_to_file(self):
        tok = "ghp_" + "a" * 36
        r = evaluate_rule(rule("Never commit tokens."), norm(write("cfg.py", "T='%s'" % tok)))
        self.assertEqual(r.status, VIOLATED)
        self.assertIn("cfg.py", r.evidence[0].detail)

    def test_should_downgrades(self):
        r = evaluate_rule(rule("You should not run `npm audit fix`."), norm(cmd("npm audit fix")))
        self.assertEqual(r.severity, "medium")

    def test_explicit_severity_wins(self):
        r = Rule("forbid-command", "terraform apply", "explicit", severity="low")
        self.assertEqual(evaluate_rule(r, norm(cmd("terraform apply"))).severity, "low")


if __name__ == "__main__":
    unittest.main()
