#!/usr/bin/env python3
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANY = '{"authors_mode":"any"}\n'
OWNER = '{"authors_mode":"owner"}\n'


def script_path():
    override = os.environ.get("READ_BASE_CONFIG_SCRIPT", "")
    if override:
        return Path(override)
    return ROOT / "scripts" / "read-base-config.sh"


def git(repo, *args):
    subprocess.check_call(["git", *args], cwd=repo, stdout=subprocess.DEVNULL)


def init_repo(tmp):
    repo = Path(tmp)
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Tim Sonner")
    git(repo, "config", "user.email", "66705347+timsonner@users.noreply.github.com")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "config", "tag.gpgsign", "false")
    git(repo, "config", "advice.nestedTag", "false")
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "init")
    return repo


def head(repo):
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


def stage_config(repo, text):
    github = repo / ".github"
    github.mkdir(exist_ok=True)
    (github / "repo-gates.json").write_text(text, encoding="utf-8")
    git(repo, "add", ".github/repo-gates.json")


def run_script(repo, base, args=None):
    out = Path(repo) / "github-output.txt"
    if out.exists():
        out.unlink()
    temp = Path(repo) / "runner-temp"
    if temp.exists():
        for child in temp.iterdir():
            if child.is_file():
                child.unlink()
    else:
        temp.mkdir()
    env = os.environ.copy()
    env.pop("GITHUB_STEP_SUMMARY", None)
    if base is None:
        env.pop("BASE_SHA", None)
    else:
        env["BASE_SHA"] = base
    env["RUNNER_TEMP"] = str(temp)
    env["GITHUB_OUTPUT"] = str(out)
    cmd = ["bash", str(script_path())]
    if args:
        cmd.extend(args)
    proc = subprocess.run(cmd, cwd=repo, env=env, text=True, capture_output=True)
    return proc, out, temp


def output_path(out):
    if not out.exists():
        return ""
    found = ""
    for line in out.read_text(encoding="utf-8").splitlines():
        if line.startswith("path="):
            found = line[5:]
    return found


def annotated_tag(repo, name, target):
    git(repo, "tag", "-a", "-m", name, name, target)
    return subprocess.check_output(["git", "rev-parse", "refs/tags/" + name], cwd=repo, text=True).strip()


def assert_rejected(test, repo, sha):
    proc, out, temp = run_script(repo, sha)
    test.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
    test.assertIn("commit", proc.stderr)
    test.assertEqual(output_path(out), "")
    test.assertFalse(blobs_contain(temp, "any"))
    checked, _, checked_temp = run_script(repo, sha, ["--check"])
    test.assertNotEqual(checked.returncode, 0, checked.stderr)
    test.assertFalse(blobs_contain(checked_temp, "any"))


def blobs_contain(temp, needle):
    for path in temp.glob("*"):
        if path.is_file() and needle in path.read_text(encoding="utf-8"):
            return True
    return False


def named_steps(text):
    return re.split(r"\n      - name: ", text)[1:]


class TestBaseSha(unittest.TestCase):
    def test_base_sha_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(tmp)
            stage_config(repo, ANY)
            proc, out, temp = run_script(repo, "")
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("BASE_SHA", proc.stderr)
            self.assertEqual(output_path(out), "")
            self.assertFalse(blobs_contain(temp, "any"))
            checked, _, _ = run_script(repo, "", ["--check"])
            self.assertNotEqual(checked.returncode, 0, checked.stderr)
            missing, _, _ = run_script(repo, None)
            self.assertNotEqual(missing.returncode, 0, missing.stderr)

    def test_base_sha_non_hex(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(tmp)
            for bad in ("not-a-sha", "g" * 40, "zzzz", "A" * 40):
                proc, out, temp = run_script(repo, bad)
                self.assertNotEqual(proc.returncode, 0, bad + proc.stderr)
                self.assertIn("BASE_SHA", proc.stderr)
                self.assertEqual(output_path(out), "")
                self.assertFalse(blobs_contain(temp, "any"))

    def test_base_sha_short(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(tmp)
            stage_config(repo, OWNER)
            git(repo, "commit", "-m", "config")
            good = head(repo)
            for short in (good[:7], good[:39]):
                proc, out, _ = run_script(repo, short)
                self.assertNotEqual(proc.returncode, 0, short + proc.stderr)
                self.assertIn("BASE_SHA", proc.stderr)
                self.assertEqual(output_path(out), "")

    def test_base_sha_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(tmp)
            proc, out, _ = run_script(repo, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
            self.assertNotEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("commit", proc.stderr)
            self.assertEqual(output_path(out), "")

    def test_base_sha_valid_with_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(tmp)
            stage_config(repo, OWNER)
            git(repo, "commit", "-m", "config")
            good = head(repo)
            stage_config(repo, ANY)
            proc, out, _ = run_script(repo, good)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            path = output_path(out)
            self.assertTrue(path)
            body = Path(path).read_text(encoding="utf-8")
            self.assertIn("owner", body)
            self.assertNotIn("any", body)
            checked, _, temp = run_script(repo, good, ["--check"])
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertFalse(blobs_contain(temp, "any"))

    def test_base_sha_valid_without_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(tmp)
            good = head(repo)
            stage_config(repo, ANY)
            proc, out, temp = run_script(repo, good)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(output_path(out), "")
            self.assertFalse(blobs_contain(temp, "any"))

    def test_base_sha_index_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(tmp)
            good = head(repo)
            stage_config(repo, ANY)
            proc, out, temp = run_script(repo, "")
            self.assertNotEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(output_path(out), "")
            self.assertFalse(blobs_contain(temp, "any"))
            kept, kept_out, kept_temp = run_script(repo, good)
            self.assertEqual(kept.returncode, 0, kept.stderr)
            self.assertEqual(output_path(kept_out), "")
            self.assertFalse(blobs_contain(kept_temp, "any"))

    def repo_with_any(self, tmp):
        repo = init_repo(tmp)
        stage_config(repo, ANY)
        git(repo, "commit", "-m", "config")
        return repo

    def test_base_sha_annotated_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.repo_with_any(tmp)
            tag = annotated_tag(repo, "mark", head(repo))
            self.assertEqual(subprocess.check_output(["git", "cat-file", "-t", tag], cwd=repo, text=True).strip(), "tag")
            assert_rejected(self, repo, tag)

    def test_base_sha_nested_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.repo_with_any(tmp)
            inner = annotated_tag(repo, "inner", head(repo))
            outer = annotated_tag(repo, "outer", inner)
            self.assertEqual(subprocess.check_output(["git", "cat-file", "-t", outer], cwd=repo, text=True).strip(), "tag")
            self.assertNotEqual(outer, inner)
            assert_rejected(self, repo, outer)

    def test_base_sha_tag_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.repo_with_any(tmp)
            tree = subprocess.check_output(["git", "rev-parse", head(repo) + "^{tree}"], cwd=repo, text=True).strip()
            tag = annotated_tag(repo, "ontree", tree)
            assert_rejected(self, repo, tag)

    def test_base_sha_tag_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.repo_with_any(tmp)
            blob = subprocess.check_output(["git", "rev-parse", head(repo) + ":README.md"], cwd=repo, text=True).strip()
            tag = annotated_tag(repo, "onblob", blob)
            assert_rejected(self, repo, tag)

    def test_base_sha_guard_runs_before_show(self):
        text = script_path().read_text(encoding="utf-8")
        call = text.index("\nrequire_base_sha\n")
        show = text.index('git show "$BASE_SHA:.github/repo-gates.json"')
        self.assertLess(call, show)
        self.assertIn('[ "$(git cat-file -t "$base" 2>/dev/null)" = "commit" ]', text)
        self.assertNotIn("^{", text)
        self.assertIn("^[0-9a-f]{40}$", text)

    def test_base_sha_steps_call_guard(self):
        trusted = (ROOT / ".github" / "workflows" / "trusted-gate.yml").read_text(encoding="utf-8")
        house = (ROOT / ".github" / "workflows" / "house-rules.yml").read_text(encoding="utf-8")
        script = (ROOT / "scripts" / "read-base-config.sh").read_text(encoding="utf-8")
        self.assertNotIn('git show "$BASE_SHA:.github/repo-gates.json"', trusted)
        self.assertNotIn('git show "$BASE_SHA:.github/repo-gates.json"', house)
        self.assertIn('git show "$BASE_SHA:.github/repo-gates.json"', script)
        self.assertNotIn("HEAD_SHA:.github/repo-gates.json", trusted + house + script)
        trusted_steps = [part for part in named_steps(trusted) if "BASE_SHA:" in part]
        self.assertEqual(len(trusted_steps), 5)
        for part in trusted_steps:
            run_at = part.find("\n        run:")
            self.assertGreater(run_at, 0)
            run = part[run_at:]
            self.assertIn("read-base-config.sh", run)
            if 'sha="$BASE_SHA"' in run:
                self.assertLess(run.index("bash scripts/read-base-config.sh --check"), run.index('sha="$BASE_SHA"'))
            elif "python3 .trusted/scripts/house-rules.py" in run:
                self.assertLess(run.index("bash .trusted/scripts/read-base-config.sh --check"), run.index("python3"))
                self.assertIn('if [ "$code" -eq 0 ]; then', run)
            elif "python3 .trusted/scripts/rules-integrity.py" in run:
                self.assertLess(run.index("bash .trusted/scripts/read-base-config.sh --check"), run.index("python3"))
                self.assertIn('if [ "$code" -eq 0 ]; then', run)
            else:
                self.assertTrue(run.rstrip().endswith("bash .trusted/scripts/read-base-config.sh"))
        house_steps = [part for part in named_steps(house) if "BASE_SHA:" in part]
        self.assertEqual(len(house_steps), 2)
        for part in house_steps:
            run = part[part.find("\n        run:"):]
            self.assertNotIn("bash scripts/read-base-config.sh", run)
            if "python3 .repo-gates/scripts/house-rules.py" in run:
                self.assertLess(run.index("bash .repo-gates/scripts/read-base-config.sh --check"), run.index("python3"))
            else:
                self.assertTrue(run.rstrip().endswith("bash .repo-gates/scripts/read-base-config.sh"))


if __name__ == "__main__":
    unittest.main()
