#!/usr/bin/env python3
import ast
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
EMAIL = "66705347+timsonner@users.noreply.github.com"


def load_house():
    path = os.environ.get("HOUSE_RULES_PATH") or str(ROOT / "scripts" / "house-rules.py")
    spec = importlib.util.spec_from_file_location("house_rules_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def apply_mutations(data):
    mutated = copy.deepcopy(data)
    for name in mutated.get("mutations") or []:
        if name == "emdash-title":
            mutated["title"] = mutated.get("title", "") + "\u2014"
        elif name == "emdash-body":
            mutated["body"] = mutated.get("body", "") + "\n" + "\u2014"
        elif name == "emdash-commit":
            mutated["commits"][0]["message"] += "\n" + "\u2014"
        elif name == "emdash-md":
            mutated.setdefault("added", []).append({"path": "notes.md", "line_no": 1, "text": "see " + "\u2014"})
            mutated.setdefault("files", []).append("notes.md")
        elif name == "token-line":
            token = "gh" + "p_" + ("A" * 36)
            mutated.setdefault("added", []).append({"path": "a.py", "line_no": 2, "text": "token = " + json.dumps(token)})
        elif name == "email-line":
            address = "person" + "@" + "example.com"
            mutated.setdefault("added", []).append({"path": "a.py", "line_no": 3, "text": "email = " + json.dumps(address)})
        elif name == "non-tim-committer":
            mutated["commits"][0]["committer_name"] = "GitHub"
            mutated["commits"][0]["committer_email"] = "noreply@" + "github.com"
    return mutated


def evaluate(data):
    module = load_house()
    manifest = module.load_manifest()
    ready = apply_mutations(data)
    ctx = module.Ctx(
        manifest,
        ready.get("title", ""),
        ready.get("body", ""),
        ready.get("commits", []),
        ready.get("files", []),
        ready.get("added", []),
        ready.get("head_sha", ""),
        ready.get("scope_mode", ""),
        ready.get("comments_mode", ""),
        ready.get("allowed_authors", ""),
    )
    return module, module.run_checks(ctx)


class FixtureCase(unittest.TestCase):
    def check(self, name, check_id):
        data = load_fixture(name)
        module, findings = evaluate(data)
        expected = data["expect"][str(check_id)]
        got = module.worst(findings, check_id)
        self.assertEqual(got, expected, [item.reason for item in findings if item.check == check_id])


class TestC2(FixtureCase):
    def test_c2_good(self):
        self.check("good_pr.json", 2)

    def test_c2_author(self):
        self.check("check2_author.json", 2)

    def test_c2_committer(self):
        self.check("check2_committer.json", 2)

    def test_c2_allowed_author(self):
        module = load_house()
        data = load_fixture("check2_author.json")
        data["allowed_authors"] = "Pat Example <pat@users.noreply.github.com>"
        _, findings = evaluate(data)
        self.assertEqual(module.worst(findings, 2), "PASS")


class TestC3(FixtureCase):
    def test_c3_good(self):
        self.check("good_pr.json", 3)

    def test_c3_title(self):
        self.check("check3_title.json", 3)

    def test_c3_body(self):
        self.check("check3_body.json", 3)

    def test_c3_commit(self):
        self.check("check3_commit.json", 3)

    def test_c3_md(self):
        self.check("check3_md.json", 3)


class TestC4(FixtureCase):
    def test_c4_good(self):
        self.check("good_pr.json", 4)

    def test_c4_template(self):
        self.check("check4_template.json", 4)

    def test_c4_missing_plan(self):
        self.check("check4_missing_plan.json", 4)

    def test_c4_risk_placeholder(self):
        self.check("check4_risk_placeholder.json", 4)

    def test_c4_scope_warn(self):
        self.check("check4_scope_warn.json", 4)

    def test_c4_scope_fail(self):
        self.check("check4_scope_fail.json", 4)

    def test_c4_evidence_empty(self):
        self.check("check4_evidence_empty.json", 4)

    def test_c4_medium_no_rollback(self):
        self.check("check4_medium_no_rollback.json", 4)

    def test_c4_unticked(self):
        self.check("check4_unticked.json", 4)

    def test_c4_directory_prefix(self):
        module = load_house()
        self.assertTrue(module.path_in_scope(".github/workflows/ci.yml", [".github"]))
        self.assertTrue(module.path_in_scope("README.md", ["*.md"]))
        self.assertTrue(module.path_in_scope("README.md", ["README.md"]))
        self.assertFalse(module.path_in_scope("hidden/README.md", ["README.md"]))
        self.assertFalse(module.path_in_scope("src/app.py", ["README.md"]))

    def test_c4_basename_scope(self):
        self.check("check4_basename_scope.json", 4)


class TestC5(FixtureCase):
    def test_c5_good(self):
        self.check("good_pr.json", 5)

    def test_c5_head_mismatch(self):
        self.check("check5_head_mismatch.json", 5)


class TestC6(FixtureCase):
    def test_c6_good(self):
        self.check("good_pr.json", 6)

    def test_c6_workflow_low(self):
        self.check("check6_workflow_low.json", 6)

    def test_c6_workflow_high(self):
        self.check("check6_workflow_high.json", 6)


class TestC7(FixtureCase):
    def test_c7_good(self):
        self.check("good_pr.json", 7)

    def test_c7_py_comment(self):
        self.check("check7_py_comment.json", 7)

    def test_c7_shebang(self):
        self.check("check7_shebang.json", 7)

    def test_c7_safety(self):
        self.check("check7_safety.json", 7)

    def test_c7_inline_py(self):
        self.check("check7_inline_py.json", 7)

    def test_c7_string_hash(self):
        self.check("check7_string_hash.json", 7)

    def test_c7_inline_js(self):
        self.check("check7_inline_js.json", 7)

    def test_c7_inline_safety(self):
        module = load_house()
        data = load_fixture("good_pr.json")
        data["added"] = [{"path": "a.rs", "line_no": 8, "text": "let value = 1; // SAFETY: checked bounds"}]
        data["files"] = ["a.rs"]
        data["comments_mode"] = "fail"
        _, findings = evaluate(data)
        self.assertEqual(module.worst(findings, 7), "PASS")

    def test_c7_inline_after_string(self):
        module = load_house()
        data = load_fixture("good_pr.json")
        marker = chr(35)
        data["added"] = [{"path": "a.py", "line_no": 4, "text": "value = " + json.dumps(marker + " x") + "  " + marker + " note"}]
        data["files"] = ["a.py"]
        data["comments_mode"] = "warn"
        _, findings = evaluate(data)
        self.assertEqual(module.worst(findings, 7), "WARN")

    def shell_level(self, text):
        module = load_house()
        data = load_fixture("good_pr.json")
        data["added"] = [{"path": "run.sh", "line_no": 3, "text": text}]
        data["files"] = ["run.sh"]
        data["comments_mode"] = "warn"
        _, findings = evaluate(data)
        return module.worst(findings, 7)

    def test_c7_shell_shortest_prefix(self):
        marker = chr(35)
        self.assertEqual(self.shell_level("base=${name" + marker + "prefix}"), "PASS")

    def test_c7_shell_longest_prefix(self):
        marker = chr(35)
        self.assertEqual(self.shell_level("base=${name" + marker + marker + "*/}"), "PASS")

    def test_c7_shell_argc(self):
        marker = chr(35)
        self.assertEqual(self.shell_level("count=$" + marker), "PASS")

    def test_c7_shell_nonspace(self):
        marker = chr(35)
        self.assertEqual(self.shell_level("echo hello" + marker + "world"), "PASS")

    def test_c7_shell_trailing_comment(self):
        marker = chr(35)
        self.assertEqual(self.shell_level("echo done " + marker + " note"), "WARN")
        self.assertEqual(self.shell_level("base=${name" + marker + "prefix} " + marker + " note"), "WARN")

    def test_c7_shell_line_comment(self):
        marker = chr(35)
        self.assertEqual(self.shell_level(marker + " note"), "WARN")


class TestC9(FixtureCase):
    def test_c9_good(self):
        self.check("good_pr.json", 9)

    def test_c9_token(self):
        self.check("check9_token.json", 9)

    def test_c9_email(self):
        self.check("check9_email.json", 9)


class TestManifestAndCli(unittest.TestCase):
    def test_manifest_entries_drive_checks(self):
        module = load_house()
        manifest = module.load_manifest()
        ids = [item["id"] for item in manifest["checks"]]
        self.assertEqual(set(ids), set(module.DISPATCH))
        self.assertNotIn(8, module.DISPATCH)
        self.assertNotIn("check_8", module.__dict__)
        self.assertNotIn("model_pins", module.__dict__)
        data = load_fixture("good_pr.json")
        for shape in manifest["token_shapes"]:
            sample = copy.deepcopy(data)
            sample["added"] = [{"path": "a.py", "line_no": 2, "text": "value = " + json.dumps(module.shape_sample(shape))}]
            sample["files"] = ["a.py"]
            _, findings = evaluate(sample)
            self.assertEqual(module.worst(findings, 9), "WARN", shape)
        for entry in manifest["comment_allow"]:
            sample = copy.deepcopy(data)
            if entry.startswith("/") or entry == "#!":
                path = "a.rs" if entry.startswith("/") else "a.py"
                line_no = 1 if entry == "#!" else 3
                text = entry + " kept"
            else:
                path = "a.py"
                line_no = 3
                text = chr(35) + " " + entry + " kept"
            sample["added"] = [{"path": path, "line_no": line_no, "text": text}]
            sample["comments_mode"] = "fail"
            _, findings = evaluate(sample)
            self.assertEqual(module.worst(findings, 7), "PASS", entry)
        plain = copy.deepcopy(data)
        plain["added"] = [{"path": "a.py", "line_no": 2, "text": chr(35) + " note"}]
        plain["comments_mode"] = "warn"
        _, findings = evaluate(plain)
        self.assertEqual(module.worst(findings, 7), "WARN")
        short = copy.deepcopy(manifest)
        short["limits"] = dict(manifest["limits"])
        short["limits"]["min_self_check_boxes"] = 5
        last = manifest["self_check_labels"][-1]
        unticked_body = load_fixture("good_pr.json")["body"].replace("- [x] " + last, "- [ ] " + last, 1)
        unticked = load_fixture("good_pr.json")
        real_ctx = module.Ctx(manifest, unticked["title"], unticked_body, unticked["commits"], unticked["files"], unticked["added"], unticked["head_sha"], "fail", "warn", "")
        short_ctx = module.Ctx(short, unticked["title"], unticked_body, unticked["commits"], unticked["files"], unticked["added"], unticked["head_sha"], "fail", "warn", "")
        self.assertEqual(module.worst(module.run_checks(real_ctx), 4), "FAIL")
        self.assertEqual(module.worst(module.run_checks(short_ctx), 4), "PASS")
        loose = copy.deepcopy(manifest)
        loose["limits"] = dict(manifest["limits"])
        loose["limits"]["max_risk_rank_without_rollback"] = 3
        medium = load_fixture("check4_medium_no_rollback.json")
        real_medium = module.Ctx(manifest, medium["title"], medium["body"], medium["commits"], medium["files"], medium["added"], medium["head_sha"], "fail", "warn", "")
        loose_medium = module.Ctx(loose, medium["title"], medium["body"], medium["commits"], medium["files"], medium["added"], medium["head_sha"], "fail", "warn", "")
        self.assertIn("Rollback", " ".join(item.reason for item in module.run_checks(real_medium)))
        self.assertNotIn("Rollback", " ".join(item.reason for item in module.run_checks(loose_medium)))

    def test_disable_refused(self):
        data = load_fixture("disable_refused.json")
        env = os.environ.copy()
        env.pop("HOUSE_RULES_TEST", None)
        env.pop("GITHUB_STEP_SUMMARY", None)
        for key, value in data["env"].items():
            env[key] = value
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "house-rules.py")], env=env, text=True, capture_output=True)
        self.assertEqual(proc.returncode, data["expect_exit"])

    def test_cli_reads_git(self):
        module = load_house()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.check_call(["git", "init"], cwd=repo, stdout=subprocess.DEVNULL)
            subprocess.check_call(["git", "config", "user.name", "Tim Sonner"], cwd=repo)
            subprocess.check_call(["git", "config", "user.email", EMAIL], cwd=repo)
            subprocess.check_call(["git", "config", "commit.gpgsign", "false"], cwd=repo)
            (repo / "README.md").write_text("hello\n", encoding="utf-8")
            subprocess.check_call(["git", "add", "README.md"], cwd=repo)
            subprocess.check_call(["git", "commit", "-m", "init"], cwd=repo, stdout=subprocess.DEVNULL)
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            (repo / "README.md").write_text("hello\nworld\n", encoding="utf-8")
            subprocess.check_call(["git", "add", "README.md"], cwd=repo)
            subprocess.check_call(["git", "commit", "-m", "edit readme"], cwd=repo, stdout=subprocess.DEVNULL)
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            good = load_fixture("good_pr.json")
            body = good["body"].replace("a" * 40, head)
            env = os.environ.copy()
            env.pop("GITHUB_STEP_SUMMARY", None)
            env.pop("HOUSE_RULES_DISABLE", None)
            env.pop("HOUSE_RULES_TEST", None)
            env.update({"PR_TITLE": "Edit readme", "PR_BODY": body, "BASE_SHA": base, "HEAD_SHA": head, "SCOPE_MODE": "fail", "COMMENTS_MODE": "fail"})
            proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "house-rules.py")], cwd=repo, env=env, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("| 1 |", proc.stdout)
            self.assertIn("| 2 | PASS |", proc.stdout)
            self.assertNotIn("| 8 |", proc.stdout)
            self.assertIn("Risk tier: low", proc.stdout)
        self.assertTrue(callable(module.run_checks))

    def test_sources_stay_clean(self):
        em = "\u2014"
        header = "-----BEGIN " + "PRIVATE KEY-----"
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.suffix not in {".py", ".yml", ".yaml", ".json", ".md"}:
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(em, text, str(path))
            for index, line in enumerate(text.splitlines(), 1):
                self.assertNotIn(header, line, str(path) + ":" + str(index))
                if path.suffix in {".py", ".yml", ".yaml"}:
                    stripped = line.lstrip()
                    if path.suffix == ".py" and index == 1 and stripped.startswith("#!"):
                        continue
                    self.assertFalse(stripped.startswith(chr(35)), str(path) + ":" + str(index))
        house = (ROOT / "scripts" / "house-rules.py").read_text(encoding="utf-8")
        tree = ast.parse(house)
        banned = {"urllib", "socket", "http", "requests"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name.split(".")[0], banned)
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotIn(node.module.split(".")[0], banned)


if __name__ == "__main__":
    unittest.main()
