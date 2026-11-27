#!/usr/bin/env python3
import contextlib
import copy
import importlib.util
import io
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN_V1 = '{"tag": "v1.0.0", "sha": "481ac8dcacf93ba86742a4ec79a82ccffd1b983d"}\n'
PIN_BOOT = '{"tag": "bootstrap", "sha": "bootstrap"}\n'
PIN_OTHER = '{"tag": "v9.9.9", "sha": "' + ("ab" * 20) + '"}\n'
HOUSE_WITH_GUARDS = (
    "#!/usr/bin/env python3\n"
    "import os\n"
    "import sys\n"
    "def main():\n"
    "    if os.environ.get(\"HOUSE_RULES_TEST\") == \"1\":\n"
    "        return 0\n"
    "    if os.environ.get(\"GITHUB_ACTIONS\") == \"true\" and os.environ.get(\"HOUSE_RULES_DISABLE\"):\n"
    "        return 2\n"
    "    return 0\n"
    "if __name__ == \"__main__\":\n"
    "    sys.exit(main())\n"
)
HOUSE_STUB = "#!/usr/bin/env python3\nimport sys\nsys.exit(0)\nkept = \"HOUSE_RULES_TEST GITHUB_ACTIONS HOUSE_RULES_DISABLE\"\n"


def load_integrity():
    override = os.environ.get("RULES_INTEGRITY_SCRIPT", "")
    path = Path(override) if override else ROOT / "scripts" / "rules-integrity.py"
    spec = importlib.util.spec_from_file_location("rules_integrity_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def workspace_snapshot(module):
    return module.snapshot_from_map(module.list_dir_files(ROOT))


def write_tree(root, files):
    for rel, text in files.items():
        path = Path(root) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def git_init(repo):
    subprocess.check_call(["git", "init", "-b", "main"], cwd=repo, stdout=subprocess.DEVNULL)
    subprocess.check_call(["git", "config", "user.name", "Tim Sonner"], cwd=repo)
    subprocess.check_call(["git", "config", "user.email", "66705347+timsonner@users.noreply.github.com"], cwd=repo)
    subprocess.check_call(["git", "config", "commit.gpgsign", "false"], cwd=repo)


def git_commit(repo, files, message):
    write_tree(repo, files)
    subprocess.check_call(["git", "add", "-A"], cwd=repo)
    subprocess.check_call(["git", "commit", "-m", message], cwd=repo, stdout=subprocess.DEVNULL)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


def run_main(module, repo, env):
    previous = os.getcwd()
    keys = ("TRUSTED_DIR", "BASE_SHA", "HEAD_SHA", "PR_BODY", "PR_TITLE", "GITHUB_STEP_SUMMARY", "GITHUB_TOKEN", "GH_TOKEN", "MAIN_REF")
    saved = {key: os.environ.get(key) for key in keys}
    try:
        os.chdir(repo)
        for key in keys:
            os.environ.pop(key, None)
        for key, value in env.items():
            os.environ[key] = value
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = module.main()
        return code, stdout.getvalue()
    finally:
        os.chdir(previous)
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class TestRulesIntegrity(unittest.TestCase):
    def test_empty_base_passes(self):
        module = load_integrity()
        new = workspace_snapshot(module)
        new["pin"] = {"tag": "bootstrap", "sha": "bootstrap"}
        findings = module.compare_snapshots(module.empty_snapshot(), new, "Risk: high\n", None)
        self.assertEqual(findings, [])

    def test_empty_base_real_pin_needs_checker(self):
        module = load_integrity()
        new = workspace_snapshot(module)
        new["pin"] = {"tag": "v1.0.0", "sha": "481ac8dcacf93ba86742a4ec79a82ccffd1b983d"}
        findings = module.compare_snapshots(module.empty_snapshot(), new, "Risk: high\n", None)
        self.assertIn("pin change has no checker", findings)

    def test_removed_check_fails(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        new["manifest"]["checks"] = [item for item in new["manifest"]["checks"] if item["id"] != 2]
        findings = module.compare_snapshots(old, new, "Risk: high\n", None)
        self.assertTrue(any("removed check id 2" in item for item in findings))

    def test_added_check_passes(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        new["manifest"]["checks"] = list(new["manifest"]["checks"]) + [{"id": 10, "name": "extra", "severity": "FAIL"}]
        self.assertEqual(module.compare_snapshots(old, new, "Risk: high\n", None), [])

    def test_lowered_severity_fails(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        for item in new["manifest"]["checks"]:
            if item["id"] == 2:
                item["severity"] = "WARN"
        findings = module.compare_snapshots(old, new, "Risk: high\n", None)
        self.assertTrue(any("lowered severity" in item for item in findings))

    def test_stricter_severity_passes(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        for item in new["manifest"]["checks"]:
            if item["id"] == 9:
                item["severity"] = "FAIL"
        self.assertEqual(module.compare_snapshots(old, new, "Risk: high\n", None), [])

    def test_loosened_default_fails(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        old["manifest"]["defaults"]["scope_mode"] = "fail"
        new["manifest"]["defaults"]["scope_mode"] = "warn"
        findings = module.compare_snapshots(old, new, "Risk: high\n", None)
        self.assertTrue(any("loosened default scope_mode" in item for item in findings))

    def test_removed_pattern_fails(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        new["manifest"]["self_check_labels"] = list(new["manifest"]["self_check_labels"][:-1])
        findings = module.compare_snapshots(old, new, "Risk: high\n", None)
        self.assertTrue(any("removed self_check_labels" in item for item in findings))

    def test_added_allow_fails(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        new["manifest"]["comment_allow"] = list(new["manifest"]["comment_allow"]) + ["//"]
        findings = module.compare_snapshots(old, new, "Risk: high\n", None)
        self.assertTrue(any("added comment allow" in item for item in findings))

    def test_removed_allow_passes(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        new["manifest"]["comment_allow"] = list(new["manifest"]["comment_allow"][:-1])
        self.assertEqual(module.compare_snapshots(old, new, "Risk: high\n", None), [])

    def test_limits(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        raised = copy.deepcopy(old)
        raised["manifest"]["limits"]["max_risk_rank_without_rollback"] = 2
        findings = module.compare_snapshots(old, raised, "Risk: high\n", None)
        self.assertTrue(any("raised limit" in item for item in findings))
        lowered = copy.deepcopy(old)
        lowered["manifest"]["limits"]["min_head_sha_hex_length"] = 7
        findings = module.compare_snapshots(old, lowered, "Risk: high\n", None)
        self.assertTrue(any("lowered limit" in item for item in findings))

    def test_fixture_delete_and_loosen_and_edit(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        deleted = copy.deepcopy(old)
        path = next(iter(deleted["fixtures"]))
        del deleted["fixtures"][path]
        self.assertTrue(any("deleted fixture" in item for item in module.compare_snapshots(old, deleted, "Risk: high\n", None)))
        loosened = copy.deepcopy(old)
        target = loosened["fixtures"]["tests/fixtures/check2_author.json"]
        target["expect"]["2"] = "PASS"
        self.assertTrue(any("toward passing" in item for item in module.compare_snapshots(old, loosened, "Risk: high\n", None)))
        edited = copy.deepcopy(old)
        edited["fixtures"]["tests/fixtures/good_pr.json"]["title"] = "changed"
        self.assertTrue(any("edited fixture input" in item for item in module.compare_snapshots(old, edited, "Risk: high\n", None)))

    def test_deleted_test_and_skip(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        path = "tests/test_house_rules.py"
        deleted = copy.deepcopy(old)
        deleted["tests"][path] = old["tests"][path].replace("def test_c2_good", "def kept_c2_good", 1)
        self.assertTrue(any("deleted func test_c2_good" in item for item in module.compare_snapshots(old, deleted, "Risk: high\n", None)))
        skipped = copy.deepcopy(old)
        skipped["tests"][path] = old["tests"][path].replace("    def test_c2_good", "    @unittest.skip('x')\n    def test_c2_good", 1)
        findings = module.compare_snapshots(old, skipped, "Risk: high\n", None)
        self.assertTrue(any("added skip" in item for item in findings))
        called = copy.deepcopy(old)
        old_chunk = "    def test_c2_good(self):\n        self.check(\"good_pr.json\", 2)\n"
        new_chunk = "    def test_c2_good(self):\n        self.skipTest('x')\n        self.check(\"good_pr.json\", 2)\n"
        self.assertIn(old_chunk, called["tests"][path])
        called["tests"][path] = old["tests"][path].replace(old_chunk, new_chunk, 1)
        findings = module.compare_snapshots(old, called, "Risk: high\n", None)
        self.assertTrue(any("added skip on test_c2_good" in item for item in findings))

    def test_fail_on_old_id_and_guard(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        trimmed = copy.deepcopy(old)
        trimmed["fail_on_old"] = old["fail_on_old"].replace("{2, 3, 4, 5, 6, 7, 9}", "{2, 3, 4, 5, 6, 7}", 1)
        self.assertTrue(any("removed fail-on-old id 9" in item for item in module.compare_snapshots(old, trimmed, "Risk: high\n", None)))
        unguarded = copy.deepcopy(old)
        unguarded["house"] = old["house"].replace("HOUSE_RULES_TEST", "HOUSE_RULES_OFF")
        self.assertTrue(any("HOUSE_RULES_TEST" in item for item in module.compare_snapshots(old, unguarded, "Risk: high\n", None)))

    def test_manifest_identity_extensions_and_signoff(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        dropped = copy.deepcopy(old)
        dropped["manifest"]["comment_extensions"] = [item for item in dropped["manifest"]["comment_extensions"] if item != ".py"]
        findings = module.compare_snapshots(old, dropped, "Risk: high\n", None)
        self.assertTrue(any("comment_extensions" in item for item in findings))
        added = copy.deepcopy(old)
        added["manifest"]["comment_extensions"] = list(added["manifest"]["comment_extensions"]) + [".css"]
        self.assertEqual(module.compare_snapshots(old, added, "Risk: high\n", None), [])
        changed = copy.deepcopy(old)
        changed["manifest"]["identity"] = dict(changed["manifest"]["identity"])
        changed["manifest"]["identity"]["email"] = "other@users.noreply.github.com"
        findings = module.compare_snapshots(old, changed, "Risk: high\n", None)
        self.assertTrue(any("changed identity email" in item for item in findings))
        loose = copy.deepcopy(old)
        loose["manifest"]["placeholders"] = [item for item in loose["manifest"]["placeholders"] if item != "TBD"]
        findings = module.compare_snapshots(old, loose, "Risk: high\n", None)
        self.assertTrue(any("placeholders" in item for item in findings))
        signed = copy.deepcopy(old)
        signed["manifest"]["signed_off_allow_exact"] = "Other Person <other@users.noreply.github.com>"
        findings = module.compare_snapshots(old, signed, "Risk: high\n", None)
        self.assertEqual(findings, [])

    def test_pin_move_to_tagged_release(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.check_call(["git", "init", "-b", "main"], cwd=repo, stdout=subprocess.DEVNULL)
            subprocess.check_call(["git", "config", "user.name", "Tim Sonner"], cwd=repo)
            subprocess.check_call(["git", "config", "user.email", "66705347+timsonner@users.noreply.github.com"], cwd=repo)
            subprocess.check_call(["git", "config", "commit.gpgsign", "false"], cwd=repo)
            (repo / "README.md").write_text("hello\n", encoding="utf-8")
            subprocess.check_call(["git", "add", "README.md"], cwd=repo)
            subprocess.check_call(["git", "commit", "-m", "init"], cwd=repo, stdout=subprocess.DEVNULL)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            subprocess.check_call(["git", "tag", "v1"], cwd=repo)
            new["pin"] = {"tag": "v1", "sha": sha}
            previous = os.getcwd()
            saved = os.environ.get("MAIN_REF")
            os.chdir(repo)
            os.environ["MAIN_REF"] = "main"
            original = module.release_status_ok
            module.release_status_ok = lambda value: value == sha
            try:
                ok, reason = module.live_pin_checker(new["pin"], {"tag": "bootstrap", "sha": "bootstrap"})
                self.assertTrue(ok, reason)
                findings = module.compare_snapshots(old, new, "Risk: high\n", module.live_pin_checker)
                self.assertEqual(findings, [])
                missing_ok, missing_reason = module.live_pin_checker({"tag": "v9", "sha": sha}, {"tag": "bootstrap", "sha": "bootstrap"})
                self.assertFalse(missing_ok)
                self.assertTrue(missing_reason)
            finally:
                module.release_status_ok = original
                if saved is None:
                    os.environ.pop("MAIN_REF", None)
                else:
                    os.environ["MAIN_REF"] = saved
                os.chdir(previous)

    def test_pin_and_workflows(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        back = copy.deepcopy(old)
        back["pin"] = {"tag": "bootstrap", "sha": "bootstrap"}
        old_real = copy.deepcopy(old)
        old_real["pin"] = {"tag": "v1", "sha": "b" * 40}
        self.assertTrue(any("bootstrap" in item for item in module.compare_snapshots(old_real, back, "Risk: high\n", None)))
        evil = copy.deepcopy(old)
        evil["workflows"]["evil.yml"] = "on:\n  pull_request_target:\n"
        self.assertTrue(any("evil.yml" in item for item in module.compare_snapshots(old, evil, "Risk: high\n", None)))
        edited = copy.deepcopy(old)
        edited["workflows"]["trusted-gate.yml"] = old["workflows"]["trusted-gate.yml"] + "\n"
        self.assertTrue(any("Risk high" in item for item in module.compare_snapshots(old, edited, "Risk: low\n", None)))
        self.assertEqual(module.compare_snapshots(old, edited, "Risk: high\n", None), [])

    def test_base_grade_pin_bootstrap(self):
        module = load_integrity()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trusted = root / "trusted"
            repo = root / "repo"
            repo.mkdir()
            write_tree(trusted, {".github/trusted-gates.json": PIN_BOOT})
            git_init(repo)
            base = git_commit(repo, {".github/trusted-gates.json": PIN_V1}, "base")
            head = git_commit(repo, {".github/trusted-gates.json": PIN_BOOT}, "head")
            code, text = run_main(module, repo, {"TRUSTED_DIR": str(trusted), "BASE_SHA": base, "HEAD_SHA": head, "PR_BODY": "Risk: high\n"})
        self.assertEqual(code, 1)
        self.assertIn("pin moved back to bootstrap", text)

    def test_base_grade_pin_other(self):
        module = load_integrity()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trusted = root / "trusted"
            repo = root / "repo"
            repo.mkdir()
            write_tree(trusted, {".github/trusted-gates.json": PIN_OTHER})
            git_init(repo)
            base = git_commit(repo, {".github/trusted-gates.json": PIN_V1}, "base")
            head = git_commit(repo, {".github/trusted-gates.json": PIN_OTHER}, "head")
            previous = os.getcwd()
            saved = os.environ.get("BASE_SHA")
            try:
                os.chdir(repo)
                os.environ["BASE_SHA"] = base
                old = module.snapshot_from_map(module.list_dir_files(trusted))
                new = module.snapshot_from_git(head)
                findings = module.grade_against_base(old, new, "Risk: high\n", None)
            finally:
                os.chdir(previous)
                if saved is None:
                    os.environ.pop("BASE_SHA", None)
                else:
                    os.environ["BASE_SHA"] = saved
        self.assertIn("pin change has no checker", findings)

    def test_base_grade_house(self):
        module = load_integrity()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trusted = root / "trusted"
            repo = root / "repo"
            repo.mkdir()
            write_tree(trusted, {".github/trusted-gates.json": PIN_BOOT, "scripts/house-rules.py": HOUSE_WITH_GUARDS})
            git_init(repo)
            base = git_commit(repo, {".github/trusted-gates.json": PIN_V1, "scripts/house-rules.py": HOUSE_WITH_GUARDS}, "base")
            head = git_commit(repo, {"scripts/house-rules.py": HOUSE_STUB}, "head")
            low_code, low_text = run_main(module, repo, {"TRUSTED_DIR": str(trusted), "BASE_SHA": base, "HEAD_SHA": head, "PR_BODY": "Risk: low\n"})
            high_code, high_text = run_main(module, repo, {"TRUSTED_DIR": str(trusted), "BASE_SHA": base, "HEAD_SHA": head, "PR_BODY": "Risk: high\n"})
        self.assertEqual(low_code, 1)
        self.assertIn("scripts/house-rules.py changed without Risk high", low_text)
        self.assertNotIn("removed HOUSE_RULES_TEST guard", low_text)
        self.assertNotIn("removed GITHUB_ACTIONS guard", low_text)
        self.assertNotIn("removed HOUSE_RULES_DISABLE guard", low_text)
        self.assertEqual(high_code, 0, high_text)
        self.assertNotIn("scripts/house-rules.py changed without Risk high", high_text)

    def test_base_grade_unreadable(self):
        module = load_integrity()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trusted = root / "trusted"
            repo = root / "repo"
            repo.mkdir()
            write_tree(trusted, {".github/trusted-gates.json": PIN_BOOT})
            git_init(repo)
            head = git_commit(repo, {".github/trusted-gates.json": PIN_BOOT}, "head")
            code, text = run_main(module, repo, {"TRUSTED_DIR": str(trusted), "BASE_SHA": "b" * 40, "HEAD_SHA": head, "PR_BODY": "Risk: high\n"})
        self.assertEqual(code, 1)
        self.assertIn("BASE_SHA is unreadable", text)

    def test_trusted_gate_workflow(self):
        text = (ROOT / ".github" / "workflows" / "trusted-gate.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request_target", text)
        self.assertNotIn("pip install", text)
        self.assertNotIn("ref: head", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn(".trusted/scripts/house-rules.py", text)
        self.assertIn(".trusted/scripts/rules-integrity.py", text)
        self.assertIn("trusted/house-rules", text)
        self.assertIn("trusted/rules-integrity", text)
        self.assertIn("fetch-tags: true", text)
        self.assertIn("refs/tags/", text)
        self.assertIn("GITHUB_TOKEN:", text)
        script = (ROOT / "scripts" / "read-base-config.sh").read_text(encoding="utf-8")
        self.assertIn("bash .trusted/scripts/read-base-config.sh", text)
        rules = text.split("  rules-integrity:\n", 1)[1]
        self.assertIn("BASE_SHA:", rules.split("python3 .trusted/scripts/rules-integrity.py", 1)[0])
        self.assertIn('git show "$BASE_SHA:.github/repo-gates.json"', script)
        self.assertLess(script.index("\nrequire_base_sha\n"), script.index('git show "$BASE_SHA:.github/repo-gates.json"'))
        self.assertIn("REPO_GATES_CONFIG:", text)
        self.assertNotIn("HEAD_SHA:.github/repo-gates.json", text)
        self.assertNotIn("HEAD_SHA:.github/repo-gates.json", script)
        blocks = checkout_blocks(text)
        self.assertGreaterEqual(len(blocks), 2)
        for block in blocks:
            self.assertIn("persist-credentials: false", block)
            self.assertNotIn("pull_request.head", block)
            self.assertNotIn("ref: head", block)
        for block in run_blocks(text):
            self.assertNotIn("github.event.pull_request.title", block)
            self.assertNotIn("github.event.pull_request.body", block)
        self.assertNotIn("secrets.", text)
        pinned_actions(self, text)

    def test_house_rules_workflow(self):
        text = (ROOT / ".github" / "workflows" / "house-rules.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_call", text)
        for name in ("scope_mode", "comments_mode", "allowed_authors", "gates_ref"):
            self.assertIn(name, text)
        self.assertIn("\n  check:\n", text)
        self.assertIn("contents: read", text)
        self.assertIn("pull-requests: read", text)
        self.assertNotIn("write", text)
        self.assertNotIn("pull_request_target", text)
        self.assertIn("python3 .repo-gates/scripts/house-rules.py", text)
        script = (ROOT / "scripts" / "read-base-config.sh").read_text(encoding="utf-8")
        self.assertIn("bash .repo-gates/scripts/read-base-config.sh", text)
        self.assertNotIn("bash scripts/read-base-config.sh", text)
        self.assertIn('git show "$BASE_SHA:.github/repo-gates.json"', script)
        self.assertLess(script.index("\nrequire_base_sha\n"), script.index('git show "$BASE_SHA:.github/repo-gates.json"'))
        self.assertIn("REPO_GATES_CONFIG:", text)
        self.assertNotIn("HEAD_SHA:.github/repo-gates.json", text)
        self.assertNotIn("HEAD_SHA:.github/repo-gates.json", script)
        for block in run_blocks(text):
            self.assertNotIn("github.event.pull_request.title", block)
            self.assertNotIn("github.event.pull_request.body", block)
        pinned_actions(self, text)

    def test_release_and_ci_and_no_self_check(self):
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch", release)
        self.assertNotIn("pull_request", release)
        self.assertIn("needs: verify", release)
        self.assertIn("HOUSE_RULES_PATH", release)
        self.assertIn("release/verify", release)
        self.assertIn("contents: write", release)
        self.assertIn("statuses: write", release)
        self.assertIn("python3 -m unittest discover -s tests -v", ci)
        self.assertIn("python3 tests/fail_on_old.py", ci)
        self.assertNotIn("pull_request_target", ci)
        self.assertFalse((ROOT / ".github" / "workflows" / "self-check.yml").exists())
        pinned_actions(self, release)
        pinned_actions(self, ci)
        for path in (ROOT / ".github" / "workflows").glob("*.yml"):
            if path.name != "trusted-gate.yml":
                self.assertNotIn("pull_request_target", path.read_text(encoding="utf-8"))


def checkout_blocks(text):
    blocks = []
    parts = text.split("uses: actions/checkout@")
    for part in parts[1:]:
        stop = part.find("\n      - name:")
        blocks.append(part if stop == -1 else part[:stop])
    return blocks


def run_blocks(text):
    lines = text.splitlines()
    blocks = []
    capture = False
    buf = []
    for line in lines:
        if re.match(r"\s+run:\s*", line):
            if capture:
                blocks.append("\n".join(buf))
            capture = True
            buf = [line]
            continue
        if capture and (re.match(r"\s+- name:", line) or re.match(r"\S", line)):
            blocks.append("\n".join(buf))
            capture = False
            buf = []
            continue
        if capture:
            buf.append(line)
    if capture:
        blocks.append("\n".join(buf))
    return blocks


def pinned_actions(test, text):
    for match in re.findall(r"uses:\s+actions/[A-Za-z0-9_.-]+@([0-9a-f]+)", text):
        test.assertEqual(len(match), 40)


if __name__ == "__main__":
    unittest.main()
