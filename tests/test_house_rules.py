#!/usr/bin/env python3
import ast
import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
EMAIL = "66705347+timsonner@users.noreply.github.com"
PAT = "Pat Example <pat@users.noreply.github.com>"
RETIRED_SELF_CHECK = "No trailers, author and committer are Tim"


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


def align_self_check(body, manifest):
    labels = list(manifest.get("self_check_labels") or [])
    if RETIRED_SELF_CHECK in labels or not labels:
        return body
    return body.replace(RETIRED_SELF_CHECK, labels[-1])


def evaluate(data):
    module = load_house()
    manifest = module.load_manifest()
    ready = apply_mutations(data)
    if "repo_config_text" in ready:
        config = module.parse_repo_config(ready.get("repo_config_text"))
    else:
        config = None
    ctx = module.Ctx(
        manifest,
        ready.get("title", ""),
        align_self_check(ready.get("body", ""), manifest),
        ready.get("commits", []),
        ready.get("files", []),
        ready.get("added", []),
        ready.get("head_sha", ""),
        ready.get("scope_mode", ""),
        ready.get("comments_mode", ""),
        ready.get("allowed_authors", ""),
        config,
    )
    return module, module.run_checks(ctx)


def reasons(findings, check_id):
    return [item.reason for item in findings if item.check == check_id]


def with_config(name, text, authors=""):
    data = load_fixture(name)
    data["repo_config_text"] = text
    if authors:
        data["allowed_authors"] = authors
    return evaluate(data)


def step_run(text, step_name):
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == "- name: " + step_name:
            start = index
            break
    if start is None:
        raise AssertionError("missing step " + step_name)
    buf = []
    seen = False
    for line in lines[start + 1:]:
        if seen and (re.match(r"\s+- name:", line) or re.match(r"\S", line)):
            break
        if re.match(r"\s+run:\s*\|\s*$", line):
            seen = True
            continue
        if seen:
            buf.append(line)
    if not buf:
        raise AssertionError("missing run for " + step_name)
    indent = len(buf[0]) - len(buf[0].lstrip())
    return "\n".join((line[indent:] if len(line) >= indent else line) for line in buf) + "\n"


def init_repo(tmp):
    repo = Path(tmp)
    subprocess.check_call(["git", "init", "-b", "main"], cwd=repo, stdout=subprocess.DEVNULL)
    subprocess.check_call(["git", "config", "user.name", "Tim Sonner"], cwd=repo)
    subprocess.check_call(["git", "config", "user.email", EMAIL], cwd=repo)
    subprocess.check_call(["git", "config", "commit.gpgsign", "false"], cwd=repo)
    return repo


def commit_as(repo, name, email, message):
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = name
    env["GIT_AUTHOR_EMAIL"] = email
    env["GIT_COMMITTER_NAME"] = name
    env["GIT_COMMITTER_EMAIL"] = email
    subprocess.check_call(["git", "add", "-A"], cwd=repo)
    subprocess.check_call(["git", "commit", "-m", message], cwd=repo, env=env, stdout=subprocess.DEVNULL)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


def read_base_config(repo, base):
    house = step_run((ROOT / ".github" / "workflows" / "house-rules.yml").read_text(encoding="utf-8"), "read base repo-gates config")
    trusted = step_run((ROOT / ".github" / "workflows" / "trusted-gate.yml").read_text(encoding="utf-8"), "read base repo-gates config")
    if house != trusted:
        raise AssertionError("config read scripts differ")
    if 'git show "$BASE_SHA:.github/repo-gates.json"' not in house:
        raise AssertionError("base config read is missing")
    if "HEAD_SHA:.github/repo-gates.json" in house:
        raise AssertionError("config read uses head")
    out = Path(repo) / "github-output.txt"
    if out.exists():
        out.unlink()
    temp = Path(repo) / "runner-temp"
    temp.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["BASE_SHA"] = base
    env["RUNNER_TEMP"] = str(temp)
    env["GITHUB_OUTPUT"] = str(out)
    proc = subprocess.run(["bash", "-c", house], cwd=repo, env=env, text=True, capture_output=True)
    if proc.returncode != 0:
        raise AssertionError(proc.stdout + proc.stderr)
    path = ""
    for line in out.read_text(encoding="utf-8").splitlines():
        if line.startswith("path="):
            path = line[5:]
    return path


def pr_body(module, head):
    body = align_self_check(load_fixture("good_pr.json")["body"], module.load_manifest())
    body = body.replace("a" * 40, head)
    return body.replace("- Scope (paths): README.md", "- Scope (paths): README.md, .github")


def run_checker(repo, base, head, config_path):
    module = load_house()
    env = os.environ.copy()
    for key in ("GITHUB_STEP_SUMMARY", "HOUSE_RULES_DISABLE", "HOUSE_RULES_TEST", "REPO_GATES_CONFIG"):
        env.pop(key, None)
    env.update(
        {
            "PR_TITLE": "Edit readme",
            "PR_BODY": pr_body(module, head),
            "BASE_SHA": base,
            "HEAD_SHA": head,
            "SCOPE_MODE": "fail",
            "COMMENTS_MODE": "fail",
        }
    )
    if config_path:
        env["REPO_GATES_CONFIG"] = config_path
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "house-rules.py")], cwd=repo, env=env, text=True, capture_output=True)


def filled_template(raw, head):
    body = raw.replace("- Goal:", "- Goal: Ship the contributor config.", 1)
    body = body.replace("- Scope (paths):", "- Scope (paths): README.md", 1)
    body = body.replace("- Steps:", "- Steps: Fill the template and tick every box.", 1)
    body = body.replace("- Success criteria:", "- Success criteria: Check 4 passes on this filled template.", 1)
    body = body.replace("- Risk: low | medium | high", "- Risk: low", 1)
    body = body.replace('- Plan file: (box spec path or "n/a")', "- Plan file: n/a", 1)
    body = body.replace("Head: <full SHA>", "Head: " + head, 1)
    marker = "- Commands and exit codes (fmt, lint -D warnings, tests, proof scripts):"
    body = body.replace(marker, marker + "\npython3 -m unittest discover -s tests -v exit 0", 1)
    body = body.replace("- Rollback:", "- Rollback: Revert the pull request.", 1)
    return body.replace("- [ ] ", "- [x] ")


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
        data["allowed_authors"] = PAT
        _, findings = evaluate(data)
        self.assertEqual(module.worst(findings, 2), "PASS")

    def test_c2_owner_ignores_listed_author(self):
        module, findings = with_config("check2_author.json", json.dumps({"authors_mode": "owner", "allowed_authors": [PAT]}))
        self.assertEqual(module.worst(findings, 2), "FAIL")

    def test_c2_omitted_mode_stays_owner(self):
        module, findings = with_config("check2_author.json", json.dumps({"allowed_authors": [PAT]}))
        self.assertEqual(module.worst(findings, 2), "FAIL")

    def test_c2_list_allows_listed_author(self):
        module, findings = with_config("check2_author.json", json.dumps({"authors_mode": "list", "allowed_authors": [PAT]}))
        self.assertEqual(module.worst(findings, 2), "PASS")
        self.assertEqual(reasons(findings, 2), [])

    def test_c2_list_rejects_unlisted_author(self):
        module, findings = with_config(
            "check2_author.json",
            json.dumps({"authors_mode": "list", "allowed_authors": ["Ada Lovelace <1+ada@users.noreply.github.com>"]}),
        )
        self.assertEqual(module.worst(findings, 2), "FAIL")

    def test_c2_list_keeps_owner(self):
        module, findings = with_config("good_pr.json", json.dumps({"authors_mode": "list", "allowed_authors": [PAT]}))
        self.assertEqual(module.worst(findings, 2), "PASS")

    def test_c2_list_merges_workflow_authors(self):
        module, findings = with_config("check2_author.json", json.dumps({"authors_mode": "list", "allowed_authors": []}), PAT)
        self.assertEqual(module.worst(findings, 2), "PASS")

    def test_c2_any_skips_identity(self):
        module, findings = with_config("check2_author.json", json.dumps({"authors_mode": "any"}))
        self.assertEqual(module.worst(findings, 2), "PASS")
        self.assertEqual(reasons(findings, 2), [])

    def test_c2_any_skips_github_committer(self):
        module, findings = with_config("check2_committer.json", json.dumps({"authors_mode": "any"}))
        self.assertEqual(module.worst(findings, 2), "PASS")
        self.assertEqual(reasons(findings, 2), [])

    def test_c2_github_committer_still_fails(self):
        module, findings = with_config(
            "check2_committer.json",
            json.dumps({"authors_mode": "list", "allowed_authors": [PAT]}),
        )
        self.assertEqual(module.worst(findings, 2), "FAIL")
        self.assertTrue(any("GitHub <" + "noreply@" + "github.com>" in item for item in reasons(findings, 2)))

    def test_c2_unknown_key_fails_closed(self):
        module, findings = with_config("check2_author.json", json.dumps({"authors_mode": "any", "extra": True}))
        self.assertEqual(module.worst(findings, 2), "FAIL")
        text = " ".join(reasons(findings, 2))
        self.assertIn("unknown repo-gates config key: extra", text)
        self.assertIn("author Pat Example <pat@users.noreply.github.com>", text)

    def test_c2_bad_config_values(self):
        samples = [
            ("{", "repo-gates config is not valid JSON"),
            ("[]", "repo-gates config must be a JSON object"),
            ("null", "repo-gates config must be a JSON object"),
            (json.dumps({"authors_mode": "everyone"}), "bad authors_mode: everyone"),
            (json.dumps({"authors_mode": "ANY"}), "bad authors_mode: ANY"),
            (json.dumps({"allowed_authors": PAT}), "bad allowed_authors"),
            (json.dumps({"authors_mode": "list", "allowed_authors": [""]}), "bad allowed_authors"),
            (json.dumps({"authors_mode": "list", "allowed_authors": [1]}), "bad allowed_authors"),
            (json.dumps({"authors_mode": True}), "bad authors_mode: invalid"),
        ]
        for text, message in samples:
            module, findings = with_config("good_pr.json", text)
            self.assertEqual(module.worst(findings, 2), "FAIL", text)
            self.assertIn(message, " ".join(reasons(findings, 2)), text)

    def test_c2_config_changed_warns(self):
        data = load_fixture("good_pr.json")
        data["files"] = ["README.md", ".github/repo-gates.json"]
        data["repo_config_text"] = json.dumps({"authors_mode": "owner"})
        module, findings = evaluate(data)
        self.assertEqual(module.worst(findings, 2), "WARN")
        self.assertEqual(reasons(findings, 2), ["repo-gates config changed"])

    def test_c2_config_changed_normalizes_path(self):
        data = load_fixture("good_pr.json")
        data["files"] = [".github\\repo-gates.json"]
        module, findings = evaluate(data)
        self.assertEqual(reasons(findings, 2), ["repo-gates config changed"])
        data["files"] = ["./.github/repo-gates.json"]
        module, findings = evaluate(data)
        self.assertEqual(reasons(findings, 2), ["repo-gates config changed"])

    def test_c2_unrelated_file_does_not_warn(self):
        data = load_fixture("good_pr.json")
        data["files"] = [".github/repo-gates.json.bak", "README.md"]
        module, findings = evaluate(data)
        self.assertEqual(reasons(findings, 2), [])

    def test_c2_bad_author_and_config_change_fails(self):
        data = load_fixture("check2_author.json")
        data["files"] = [".github/repo-gates.json"]
        module, findings = evaluate(data)
        self.assertEqual(module.worst(findings, 2), "FAIL")
        self.assertIn("repo-gates config changed", " ".join(reasons(findings, 2)))

    def test_c2_any_with_config_change_warns(self):
        data = load_fixture("check2_author.json")
        data["files"] = [".github/repo-gates.json"]
        data["repo_config_text"] = json.dumps({"authors_mode": "any"})
        module, findings = evaluate(data)
        self.assertEqual(module.worst(findings, 2), "WARN")
        self.assertEqual(reasons(findings, 2), ["repo-gates config changed"])

    def test_c2_missing_path_is_owner(self):
        module = load_house()
        self.assertEqual(module.load_repo_config_path(""), module.empty_repo_config())
        parsed = module.parse_repo_config(None)
        self.assertEqual(parsed["authors_mode"], "owner")
        self.assertEqual(parsed["error"], "")

    def test_c2_config_path_list(self):
        module = load_house()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "repo-gates.json"
            path.write_text(json.dumps({"authors_mode": "list", "allowed_authors": [PAT]}), encoding="utf-8")
            loaded = module.load_repo_config_path(str(path))
            self.assertEqual(loaded["error"], "")
            self.assertEqual(loaded["authors_mode"], "list")
            module, findings = with_config("check2_author.json", path.read_text(encoding="utf-8"))
            self.assertEqual(module.worst(findings, 2), "PASS")

    def test_c2_malformed_config_does_not_crash(self):
        module = load_house()
        body = align_self_check(load_fixture("good_pr.json")["body"], module.load_manifest())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{", encoding="utf-8")
            env = os.environ.copy()
            for key in ("GITHUB_STEP_SUMMARY", "HOUSE_RULES_DISABLE", "HOUSE_RULES_TEST"):
                env.pop(key, None)
            env.update({"REPO_GATES_CONFIG": str(path), "PR_TITLE": "Edit readme", "PR_BODY": body})
            proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "house-rules.py")], env=env, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("| 2 | FAIL | repo-gates config is not valid JSON |", proc.stdout)
            self.assertNotIn("Traceback", proc.stderr)
            env["REPO_GATES_CONFIG"] = str(Path(tmp) / "missing.json")
            proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "house-rules.py")], env=env, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("repo-gates config could not be read", proc.stdout)
            self.assertNotIn("Traceback", proc.stderr)

    def test_c2_head_only_config_does_not_widen(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(tmp)
            (repo / "README.md").write_text("hello\n", encoding="utf-8")
            base = commit_as(repo, "Tim Sonner", EMAIL, "init")
            config_dir = repo / ".github"
            config_dir.mkdir()
            (config_dir / "repo-gates.json").write_text(json.dumps({"authors_mode": "any"}) + "\n", encoding="utf-8")
            (repo / "README.md").write_text("hello\nworld\n", encoding="utf-8")
            head = commit_as(repo, "Pat Example", "pat@users.noreply.github.com", "widen")
            self.assertTrue((repo / ".github" / "repo-gates.json").is_file())
            base_path = read_base_config(repo, base)
            self.assertEqual(base_path, "")
            base_run = run_checker(repo, base, head, base_path)
            self.assertIn("| 2 | FAIL |", base_run.stdout, base_run.stdout + base_run.stderr)
            self.assertIn("author Pat Example <pat@users.noreply.github.com>", base_run.stdout)
            head_path = read_base_config(repo, head)
            self.assertTrue(head_path)
            head_run = run_checker(repo, base, head, head_path)
            self.assertNotIn("author Pat Example <pat@users.noreply.github.com>", head_run.stdout)
            self.assertIn("| 2 | WARN |", head_run.stdout, head_run.stdout + head_run.stderr)
            self.assertIn("repo-gates config changed", head_run.stdout)

    def test_c2_base_list_beats_head_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(tmp)
            config_dir = repo / ".github"
            config_dir.mkdir()
            listed = json.dumps({"authors_mode": "list", "allowed_authors": [PAT]}) + "\n"
            (config_dir / "repo-gates.json").write_text(listed, encoding="utf-8")
            (repo / "README.md").write_text("hello\n", encoding="utf-8")
            base = commit_as(repo, "Tim Sonner", EMAIL, "init")
            (config_dir / "repo-gates.json").write_text(json.dumps({"authors_mode": "owner"}) + "\n", encoding="utf-8")
            (repo / "README.md").write_text("hello\nworld\n", encoding="utf-8")
            head = commit_as(repo, "Pat Example", "pat@users.noreply.github.com", "tighten")
            base_path = read_base_config(repo, base)
            self.assertTrue(base_path)
            self.assertIn('"list"', Path(base_path).read_text(encoding="utf-8"))
            base_run = run_checker(repo, base, head, base_path)
            self.assertEqual(base_run.returncode, 0, base_run.stdout + base_run.stderr)
            self.assertIn("| 2 | WARN |", base_run.stdout)
            self.assertNotIn("author Pat Example", base_run.stdout)
            self.assertNotIn("committer Pat Example", base_run.stdout)
            self.assertIn("repo-gates config changed", base_run.stdout)
            head_path = read_base_config(repo, head)
            head_run = run_checker(repo, base, head, head_path)
            self.assertIn("| 2 | FAIL |", head_run.stdout, head_run.stdout + head_run.stderr)
            self.assertIn("author Pat Example <pat@users.noreply.github.com>", head_run.stdout)


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

    def test_c4_retired_label_does_not_count(self):
        module = load_house()
        manifest = module.load_manifest()
        data = load_fixture("good_pr.json")
        ctx = module.Ctx(
            manifest,
            data["title"],
            data["body"],
            data["commits"],
            data["files"],
            data["added"],
            data["head_sha"],
            "fail",
            "warn",
            "",
        )
        findings = module.run_checks(ctx)
        self.assertEqual(module.worst(findings, 4), "FAIL")
        self.assertTrue(any("Author and committer allowed by repo-gates config" in item.reason for item in findings if item.check == 4))

    def test_c4_shipped_templates(self):
        module = load_house()
        manifest = module.load_manifest()
        label = "Author and committer allowed by repo-gates config"
        head = "a" * 40
        self.assertEqual(manifest["limits"]["min_self_check_boxes"], 6)
        self.assertEqual(len(manifest["self_check_labels"]), 6)
        self.assertEqual(manifest["self_check_labels"][-1], label)
        for rel in ("templates/pull_request_template.md", ".github/pull_request_template.md"):
            raw = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIn("- [ ] " + label, raw)
            data = load_fixture("good_pr.json")
            data["body"] = filled_template(raw, head)
            data["head_sha"] = head
            data["files"] = ["README.md"]
            _, findings = evaluate(data)
            self.assertEqual(module.worst(findings, 4), "PASS", rel + " " + " ".join(reasons(findings, 4)))


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
        body = align_self_check(load_fixture("good_pr.json")["body"], manifest)
        unticked_body = body.replace("- [x] " + last, "- [ ] " + last, 1)
        self.assertNotEqual(body, unticked_body)
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
            body = align_self_check(good["body"], module.load_manifest()).replace("a" * 40, head)
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
