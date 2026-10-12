import json
import os
import tempfile
import unittest

from agentsmd_adherence.rules import (
    FORBID_COMMAND, NO_SECRET_LEAK, PROTECT_PATH, REQUIRE_COMMAND, RESTRICT_WRITES,
    extract, governance_chain, is_protected, load_rules_json,
)


def kinds(md):
    return {(r.kind, r.pattern, r.trigger) for r in extract(md).rules}


class ExtractTests(unittest.TestCase):
    def test_forbid_command(self):
        self.assertIn((FORBID_COMMAND, "git push --force", None), kinds("- Never run `git push --force`."))

    def test_forbid_use_binary(self):
        self.assertIn((FORBID_COMMAND, "sudo", None), kinds("- Do not use `sudo`."))

    def test_protect_path_dir(self):
        self.assertIn((PROTECT_PATH, "migrations/", None), kinds("- Never edit files under `migrations/`."))

    def test_protect_dotfile(self):
        self.assertIn((PROTECT_PATH, ".env", None), kinds("Do not modify `.env`."))

    def test_bare_filename_with_path_verb(self):
        self.assertIn((PROTECT_PATH, "LICENSE", None), kinds("Do not modify `LICENSE`."))

    def test_require_before_commit(self):
        self.assertIn((REQUIRE_COMMAND, "make test", "commit"), kinds("Always run `make test` before committing."))

    def test_require_before_pr(self):
        self.assertIn((REQUIRE_COMMAND, "npm run lint", "pr"),
                      kinds("You must run `npm run lint` before opening a pull request."))

    def test_imperative_run_is_required(self):
        self.assertIn((REQUIRE_COMMAND, "ruff check .", None), kinds("Run `ruff check .` after edits."))

    def test_install_is_not_a_required_command(self):
        self.assertEqual(kinds("Install dependencies with `pip install -e .`."), set())

    def test_secret_rule(self):
        self.assertIn((NO_SECRET_LEAK, "secrets", None), kinds("Never print secrets or API keys."))

    def test_restrict_writes(self):
        rules = extract("Only modify files in `src/` and `tests/`.").rules
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].kind, RESTRICT_WRITES)
        self.assertEqual(rules[0].patterns, ["src/", "tests/"])

    def test_fenced_code_ignored(self):
        md = "```\nnever run `rm -rf /`\n```\n"
        self.assertEqual(extract(md).rules, [])

    def test_uncheckable_directives_counted(self):
        ex = extract("- Prefer small commits.\n- Never run `git push --force`.\n")
        self.assertEqual(len(ex.directives), 2)
        self.assertEqual(len(ex.uncheckable), 1)
        self.assertAlmostEqual(ex.coverage, 0.5)

    def test_should_lowers_strength(self):
        r = extract("You should not run `npm audit fix --force`.").rules[0]
        self.assertEqual(r.strength, "should")

    def test_protected_topic(self):
        r = extract("Never run `git push --force`.").rules[0]
        self.assertTrue(is_protected(r))
        r2 = extract("Do not use `yarn`.").rules[0]
        self.assertFalse(is_protected(r2))

    def test_product_is_not_production(self):
        r = extract("Do not use `yarn` for product builds.").rules[0]
        self.assertFalse(is_protected(r))

    def test_source_and_line(self):
        r = extract("# Title\n\n- Never run `rm -rf build`.\n", source="AGENTS.md").rules[0]
        self.assertEqual((r.source, r.line), ("AGENTS.md", 3))


class ChainAndJsonTests(unittest.TestCase):
    def test_governance_chain_root_first(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "pkg", "sub"))
            for p in ("AGENTS.md", os.path.join("pkg", "sub", "AGENTS.md")):
                open(os.path.join(d, p), "w").close()
            chain = governance_chain(d, "pkg/sub/mod.py")
            self.assertEqual([os.path.relpath(c, d) for c in chain],
                             ["AGENTS.md", os.path.join("pkg", "sub", "AGENTS.md")])

    def test_chain_outside_repo_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                governance_chain(d, "../elsewhere")

    def test_rules_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rules.json")
            with open(p, "w") as fh:
                json.dump({"rules": [
                    {"kind": "forbid-command", "pattern": "terraform apply", "severity": "critical"},
                    {"kind": "require-command", "pattern": "make test", "trigger": "push"},
                ]}, fh)
            rules = load_rules_json(p)
            self.assertEqual([r.kind for r in rules], ["forbid-command", "require-command"])
            self.assertEqual(rules[0].severity, "critical")
            self.assertEqual(rules[1].trigger, "push")

    def test_rules_json_bad_kind(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rules.json")
            with open(p, "w") as fh:
                json.dump([{"kind": "nope", "pattern": "x"}], fh)
            with self.assertRaises(ValueError):
                load_rules_json(p)


if __name__ == "__main__":
    unittest.main()
