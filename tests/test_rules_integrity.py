#!/usr/bin/env python3
import copy
import importlib.util
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_integrity():
    path = ROOT / "scripts" / "rules-integrity.py"
    spec = importlib.util.spec_from_file_location("rules_integrity_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def workspace_snapshot(module):
    return module.snapshot_from_map(module.list_dir_files(ROOT))


class TestRulesIntegrity(unittest.TestCase):
    def test_empty_base_passes(self):
        module = load_integrity()
        findings = module.compare_snapshots(module.empty_snapshot(), workspace_snapshot(module), "Risk: high\n", None)
        self.assertEqual(findings, [])

    def test_removed_check_fails(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        new = copy.deepcopy(old)
        new["manifest"]["checks"] = [item for item in new["manifest"]["checks"] if item["id"] != 1]
        findings = module.compare_snapshots(old, new, "Risk: high\n", None)
        self.assertTrue(any("removed check id 1" in item for item in findings))

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
            if item["id"] == 1:
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
        new["manifest"]["trailer_patterns"] = list(new["manifest"]["trailer_patterns"][:-1])
        findings = module.compare_snapshots(old, new, "Risk: high\n", None)
        self.assertTrue(any("removed trailer_patterns" in item for item in findings))

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
        target = loosened["fixtures"]["tests/fixtures/check1_coauthored_commit.json"]
        target["expect"]["1"] = "PASS"
        self.assertTrue(any("toward passing" in item for item in module.compare_snapshots(old, loosened, "Risk: high\n", None)))
        edited = copy.deepcopy(old)
        edited["fixtures"]["tests/fixtures/good_pr.json"]["title"] = "changed"
        self.assertTrue(any("edited fixture input" in item for item in module.compare_snapshots(old, edited, "Risk: high\n", None)))

    def test_deleted_test_and_skip(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        path = "tests/test_house_rules.py"
        deleted = copy.deepcopy(old)
        deleted["tests"][path] = old["tests"][path].replace("def test_c1_good", "def kept_c1_good", 1)
        self.assertTrue(any("deleted func test_c1_good" in item for item in module.compare_snapshots(old, deleted, "Risk: high\n", None)))
        skipped = copy.deepcopy(old)
        skipped["tests"][path] = old["tests"][path].replace("    def test_c1_good", "    @unittest.skip('x')\n    def test_c1_good", 1)
        findings = module.compare_snapshots(old, skipped, "Risk: high\n", None)
        self.assertTrue(any("added skip" in item for item in findings))
        called = copy.deepcopy(old)
        old_chunk = "    def test_c1_good(self):\n        self.check(\"good_pr.json\", 1)\n"
        new_chunk = "    def test_c1_good(self):\n        self.skipTest('x')\n        self.check(\"good_pr.json\", 1)\n"
        self.assertIn(old_chunk, called["tests"][path])
        called["tests"][path] = old["tests"][path].replace(old_chunk, new_chunk, 1)
        findings = module.compare_snapshots(old, called, "Risk: high\n", None)
        self.assertTrue(any("added skip on test_c1_good" in item for item in findings))

    def test_fail_on_old_id_and_guard(self):
        module = load_integrity()
        old = workspace_snapshot(module)
        trimmed = copy.deepcopy(old)
        trimmed["fail_on_old"] = old["fail_on_old"].replace("{1, 2, 3, 4, 5, 6, 7, 9}", "{1, 2, 3, 4, 5, 6, 7}", 1)
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
        self.assertTrue(any("signed_off_allow_exact" in item for item in findings))

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
