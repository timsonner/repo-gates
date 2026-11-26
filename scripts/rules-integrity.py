#!/usr/bin/env python3
import ast
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESERVED_WORKFLOWS = {"trusted-gate.yml", "release.yml"}
LEVEL_RANK = {"off": 0, "PASS": 0, "pass": 0, "WARN": 1, "warn": 1, "FAIL": 2, "fail": 2}
SKIP_DECORATORS = {"skip", "skipIf", "skipUnless", "expectedFailure"}
PATTERN_LISTS = ("trailer_patterns", "agent_footers", "self_check_labels")


def empty_snapshot():
    return {
        "manifest": None,
        "fixtures": {},
        "tests": {},
        "workflows": {},
        "pin": None,
        "house": None,
        "fail_on_old": None,
    }


def read_json(text):
    if text is None:
        return None
    return json.loads(text)


def snapshot_from_map(files):
    snap = empty_snapshot()
    if "rules/manifest.json" in files:
        snap["manifest"] = read_json(files["rules/manifest.json"])
    if ".github/trusted-gates.json" in files:
        snap["pin"] = read_json(files[".github/trusted-gates.json"])
    snap["house"] = files.get("scripts/house-rules.py")
    snap["fail_on_old"] = files.get("tests/fail_on_old.py")
    for path, text in files.items():
        if path.startswith("tests/fixtures/") and path.endswith(".json"):
            snap["fixtures"][path] = read_json(text)
        elif path.startswith("tests/") and path.endswith(".py"):
            snap["tests"][path] = text
        elif path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            snap["workflows"][Path(path).name] = text
    return snap


def list_dir_files(root):
    base = Path(root)
    found = {}
    if not base.is_dir():
        return found
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        rel = path.relative_to(base).as_posix()
        if not rel.startswith(("rules/", "tests/", "scripts/", ".github/")):
            continue
        try:
            found[rel] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    return found


def git_paths(sha):
    proc = subprocess.run(["git", "ls-tree", "-r", "--name-only", sha], capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    return [line for line in proc.stdout.splitlines() if line]


def git_file(sha, path):
    proc = subprocess.run(["git", "show", sha + ":" + path], capture_output=True)
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8")


def snapshot_from_git(sha):
    files = {}
    for path in git_paths(sha):
        if path.startswith(("rules/", "tests/", "scripts/", ".github/")):
            text = git_file(sha, path)
            if text is not None:
                files[path] = text
    return snapshot_from_map(files)


def risk_of(body):
    for line in (body or "").splitlines():
        match = re.match(r"^(?:-\s*)?Risk:\s*(\S+)", line.strip())
        if match:
            return match.group(1)
    return ""


def severity_rank(value):
    return LEVEL_RANK.get(value, LEVEL_RANK.get(str(value).upper(), 0))


def shape_key(item):
    if isinstance(item, str):
        return item
    return "".join(item.get("regex_parts", []))


def decorators(node):
    names = []
    for item in node.decorator_list:
        names.append(decorator_name(item))
    return names


def decorator_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return decorator_name(node.func)
    return ""


def test_index(source):
    if not source:
        return {}
    tree = ast.parse(source)
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            found[("func", node.name)] = set(decorators(node))
        elif isinstance(node, ast.ClassDef) and (node.name.startswith("Test") or node.name.startswith("test_")):
            found[("class", node.name)] = set(decorators(node))
    return found


def checked_ids(source):
    if not source:
        return set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "CHECKED" and isinstance(node.value, ast.Set):
                values = set()
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, int):
                        values.add(elt.value)
                return values
    return set()


def workflow_forbidden(name, text):
    if name in RESERVED_WORKFLOWS:
        return False
    if "pull_request_target" in text:
        return True
    if re.search(r"statuses:\s*write", text):
        return True
    if re.search(r"(?:trusted|release|gate)/", text):
        return True
    return False


def expect_loosened(old, new):
    problems = []
    old_expect = old.get("expect", {})
    new_expect = new.get("expect", {})
    for key, old_value in old_expect.items():
        if key == "exit":
            new_value = new_expect.get("exit", old_value)
            if old_value not in (0, "0") and new_value in (0, "0"):
                problems.append("exit moved toward passing")
            continue
        if key not in new_expect:
            problems.append("expect " + str(key) + " removed")
            continue
        if severity_rank(new_expect[key]) < severity_rank(old_value):
            problems.append("expect " + str(key) + " moved toward passing")
    return problems


def input_view(data):
    return {key: value for key, value in data.items() if key != "expect"}


def compare_snapshots(old, new, body, pin_checker=None):
    findings = []
    old_manifest = old.get("manifest")
    new_manifest = new.get("manifest")
    if old_manifest and new_manifest:
        old_checks = {item["id"]: item for item in old_manifest.get("checks", [])}
        new_checks = {item["id"]: item for item in new_manifest.get("checks", [])}
        for check_id, item in old_checks.items():
            if check_id not in new_checks:
                findings.append("removed check id " + str(check_id))
                continue
            for key in ("severity", "md_added_severity"):
                if key in item and severity_rank(new_checks[check_id].get(key, item[key])) < severity_rank(item[key]):
                    findings.append("lowered " + key + " on check " + str(check_id))
        for key in ("scope_mode", "comments_mode"):
            old_mode = old_manifest.get("defaults", {}).get(key)
            new_mode = new_manifest.get("defaults", {}).get(key)
            if old_mode and severity_rank(new_mode) < severity_rank(old_mode):
                findings.append("loosened default " + key)
        for key in PATTERN_LISTS:
            old_items = list(old_manifest.get(key, []))
            new_items = list(new_manifest.get(key, []))
            for entry in old_items:
                if entry not in new_items:
                    findings.append("removed " + key + " entry")
                    break
        old_allow = list(old_manifest.get("comment_allow", []))
        new_allow = list(new_manifest.get("comment_allow", []))
        for entry in new_allow:
            if entry not in old_allow:
                findings.append("added comment allow entry")
                break
        old_shapes = [shape_key(item) for item in old_manifest.get("token_shapes", [])]
        new_shapes = [shape_key(item) for item in new_manifest.get("token_shapes", [])]
        for entry in old_shapes:
            if entry not in new_shapes:
                findings.append("removed token shape")
                break
        old_limits = old_manifest.get("limits", {})
        new_limits = new_manifest.get("limits", {})
        for key, old_value in old_limits.items():
            if key not in new_limits:
                findings.append("removed limit " + key)
                continue
            new_value = new_limits[key]
            if key.startswith("max_") and new_value > old_value:
                findings.append("raised limit " + key)
            if key.startswith("min_") and new_value < old_value:
                findings.append("lowered limit " + key)
    elif old_manifest and not new_manifest:
        findings.append("removed manifest")
    old_fixtures = old.get("fixtures", {})
    new_fixtures = new.get("fixtures", {})
    new_by_id = {}
    for path, data in new_fixtures.items():
        if isinstance(data, dict) and "id" in data:
            new_by_id.setdefault(data["id"], []).append((path, data))
    for path, data in old_fixtures.items():
        if path not in new_fixtures:
            findings.append("deleted fixture " + path)
            continue
        current = new_fixtures[path]
        if isinstance(data, dict) and isinstance(current, dict):
            if data.get("id") == current.get("id"):
                if input_view(data) != input_view(current):
                    findings.append("edited fixture input " + str(data.get("id")))
                for problem in expect_loosened(data, current):
                    findings.append(path + " " + problem)
    for path, source in old.get("tests", {}).items():
        if path not in new.get("tests", {}):
            findings.append("deleted test file " + path)
            continue
        old_tests = test_index(source)
        new_tests = test_index(new["tests"][path])
        for key, old_decs in old_tests.items():
            if key not in new_tests:
                findings.append("deleted " + key[0] + " " + key[1])
                continue
            added = new_tests[key] - old_decs
            if added & SKIP_DECORATORS:
                findings.append("added skip on " + key[1])
    if old.get("house") and "HOUSE_RULES_TEST" in old["house"] and "HOUSE_RULES_TEST" not in (new.get("house") or ""):
        findings.append("removed HOUSE_RULES_TEST guard")
    if old.get("house") and "GITHUB_ACTIONS" in old["house"] and "GITHUB_ACTIONS" not in (new.get("house") or ""):
        findings.append("removed GITHUB_ACTIONS guard")
    if old.get("house") and "HOUSE_RULES_DISABLE" in old["house"] and "HOUSE_RULES_DISABLE" not in (new.get("house") or ""):
        findings.append("removed HOUSE_RULES_DISABLE guard")
    old_ids = checked_ids(old.get("fail_on_old"))
    new_ids = checked_ids(new.get("fail_on_old"))
    for check_id in sorted(old_ids - new_ids):
        findings.append("removed fail-on-old id " + str(check_id))
    old_pin = old.get("pin")
    new_pin = new.get("pin")
    pin_problems = check_pin(old_pin, new_pin, pin_checker)
    findings.extend(pin_problems)
    risk = risk_of(body)
    for name, text in new.get("workflows", {}).items():
        old_text = old.get("workflows", {}).get(name)
        if workflow_forbidden(name, text) and old_text != text:
            findings.append("workflow " + name + " declares a reserved gate")
        if name in RESERVED_WORKFLOWS and old_text != text and risk != "high":
            findings.append(name + " changed without Risk high")
    return findings


def check_pin(old_pin, new_pin, pin_checker):
    if new_pin is None:
        if old_pin is not None:
            return ["removed trusted-gates.json"]
        return []
    new_boot = new_pin.get("sha") == "bootstrap" or new_pin.get("tag") == "bootstrap"
    old_boot = old_pin is None or old_pin.get("sha") in (None, "bootstrap") or old_pin.get("tag") in (None, "bootstrap")
    if new_boot:
        if old_pin is not None and not old_boot:
            return ["pin moved back to bootstrap"]
        return []
    if old_pin == new_pin:
        return []
    if pin_checker is None:
        return ["pin change has no checker"]
    ok, reason = pin_checker(new_pin, old_pin)
    if not ok:
        return [reason or "pin is not a released main commit"]
    return []


def release_status_ok(sha):
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    repo = os.environ.get("GITHUB_REPOSITORY") or "timsonner/repo-gates"
    if not token:
        return False
    url = "https://api.github.com/repos/" + repo + "/commits/" + sha + "/statuses"
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "User-Agent": "repo-gates"})
    with urllib.request.urlopen(request) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return any(item.get("context") == "release/verify" and item.get("state") == "success" for item in payload)


def live_pin_checker(new_pin, old_pin):
    tag = new_pin.get("tag", "")
    sha = new_pin.get("sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha or ""):
        return False, "pin sha is not 40 hex"
    if not tag or tag == "bootstrap":
        return False, "pin tag is not a release"
    proc = subprocess.run(["git", "rev-parse", "--verify", "refs/tags/" + tag + "^{}"], capture_output=True, text=True)
    if proc.returncode != 0:
        proc = subprocess.run(["git", "rev-parse", "--verify", "refs/tags/" + tag], capture_output=True, text=True)
    if proc.returncode != 0 or proc.stdout.strip() != sha:
        return False, "tag does not point at sha"
    main_ref = os.environ.get("MAIN_REF", "origin/main")
    proc = subprocess.run(["git", "merge-base", "--is-ancestor", sha, main_ref], capture_output=True)
    if proc.returncode != 0:
        return False, "sha is not on main"
    if old_pin and old_pin.get("sha") not in (None, "", "bootstrap"):
        proc = subprocess.run(["git", "merge-base", "--is-ancestor", sha, old_pin["sha"]], capture_output=True)
        if proc.returncode == 0 and sha != old_pin["sha"]:
            return False, "pin moved backwards"
    try:
        if not release_status_ok(sha):
            return False, "release/verify is not success"
    except Exception:
        return False, "release/verify is not success"
    return True, ""


def render(findings, empty_base):
    lines = ["| Rule | Result | Reason |", "| --- | --- | --- |"]
    if not findings:
        reason = "pass against empty base" if empty_base else "pass"
        lines.append("| integrity | PASS | " + reason + " |")
    else:
        for item in findings:
            lines.append("| integrity | FAIL | " + item.replace("|", "/") + " |")
    return "\n".join(lines) + "\n"


def main():
    trusted_dir = os.environ.get("TRUSTED_DIR", "").strip()
    head = os.environ.get("HEAD_SHA", "HEAD")
    body = os.environ.get("PR_BODY", "")
    if trusted_dir:
        old = snapshot_from_map(list_dir_files(trusted_dir))
        empty_base = not any(old.get(key) for key in ("manifest", "fixtures", "tests", "workflows", "pin", "house", "fail_on_old"))
    else:
        old = empty_snapshot()
        empty_base = True
    new = snapshot_from_git(head)
    checker = None if empty_base and (new.get("pin") or {}).get("sha") == "bootstrap" else live_pin_checker
    if new.get("pin") == old.get("pin"):
        checker = None
    findings = compare_snapshots(old, new, body, checker)
    text = render(findings, empty_base)
    dest = os.environ.get("GITHUB_STEP_SUMMARY")
    if dest:
        with open(dest, "a", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
