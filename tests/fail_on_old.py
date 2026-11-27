#!/usr/bin/env python3
import ast
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKED = {2, 3, 4, 5, 6, 7, 9}


def run_tests(pattern, disable):
    env = os.environ.copy()
    env["HOUSE_RULES_TEST"] = "1"
    if disable is None:
        env.pop("HOUSE_RULES_DISABLE", None)
    else:
        env["HOUSE_RULES_DISABLE"] = str(disable)
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-k", pattern],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def check8_absent():
    house = (ROOT / "scripts" / "house-rules.py").read_text(encoding="utf-8")
    tree = ast.parse(house)
    banned = {"check_8", "check8", "model_pins"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in banned:
            return False
    for path in (ROOT / "tests").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name in banned or node.name.startswith("test_c8"):
                    return False
    return True


def without_base_sha_guard(text):
    marker = "\nrequire_base_sha\n"
    if text.count(marker) != 1:
        return None
    return text.replace(marker, "\n", 1)


def with_peel_check(text):
    old = 'if [ "$(git cat-file -t "$base" 2>/dev/null)" = "commit" ]; then'
    new = 'if git cat-file -e "$base^{commit}" >/dev/null 2>&1; then'
    if text.count(old) != 1:
        return None
    return text.replace(old, new, 1)


def run_base_sha_suite(script_path):
    env = os.environ.copy()
    env.pop("HOUSE_RULES_DISABLE", None)
    env.pop("HOUSE_RULES_TEST", None)
    if script_path:
        env["READ_BASE_CONFIG_SCRIPT"] = script_path
    else:
        env.pop("READ_BASE_CONFIG_SCRIPT", None)
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_read_base_config.py"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_integrity(script_path, pattern):
    env = os.environ.copy()
    env.pop("HOUSE_RULES_DISABLE", None)
    env.pop("HOUSE_RULES_TEST", None)
    env.pop("BASE_SHA", None)
    env.pop("HEAD_SHA", None)
    env.pop("TRUSTED_DIR", None)
    env.pop("GITHUB_STEP_SUMMARY", None)
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)
    if script_path:
        env["RULES_INTEGRITY_SCRIPT"] = script_path
    else:
        env.pop("RULES_INTEGRITY_SCRIPT", None)
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_rules_integrity.py", "-k", pattern],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def replace_once(text, old, new):
    if text.count(old) != 1:
        return None
    return text.replace(old, new, 1)


def without_base_pin(text):
    return replace_once(text, "    pin_old = use_base_pin(old, base)\n", "    pin_old = old.get(\"pin\")\n")


def without_reserved_scripts(text):
    return replace_once(text, "        extend_new(findings, reserved_script_findings(base, new, body))\n", "")


def without_unreadable_base(text):
    return replace_once(text, "            findings.append(\"BASE_SHA is unreadable\")\n", "            pass\n")


def caught_each(script_path, patterns):
    logs = []
    all_failed = True
    for pattern in patterns:
        code, out, err = run_integrity(script_path, pattern)
        if code == 0:
            all_failed = False
            logs.append(out)
            logs.append(err)
    if not all_failed:
        for item in logs:
            sys.stdout.write(item)
    return 1 if all_failed else 0


def integrity_row(name, weaken, disabled_patterns, enabled_pattern):
    text = (ROOT / "scripts" / "rules-integrity.py").read_text(encoding="utf-8")
    weakened = weaken(text)
    if weakened is None:
        sys.stdout.write(name + " marker missing\n")
        return False, "| " + name + " | missing | missing | FAIL |"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "rules-integrity.py"
        path.write_text(weakened, encoding="utf-8")
        disabled = caught_each(str(path), disabled_patterns)
    enabled, enabled_out, enabled_err = run_integrity("", enabled_pattern)
    ok = disabled != 0 and enabled == 0
    if not ok:
        sys.stdout.write(enabled_out)
        sys.stdout.write(enabled_err)
    line = "| " + name + " | " + str(disabled) + " | " + str(enabled) + " | " + ("PASS" if ok else "FAIL") + " |"
    return ok, line


def main():
    if not check8_absent():
        sys.stdout.write("check 8 function or test is present\n")
        return 1
    lines = ["| check | disabled | enabled | result |", "| --- | --- | --- | --- |"]
    failed = False
    for check_id in sorted(CHECKED):
        pattern = "test_c" + str(check_id) + "_"
        disabled, disabled_out, disabled_err = run_tests(pattern, check_id)
        enabled, enabled_out, enabled_err = run_tests(pattern, None)
        ok = disabled != 0 and enabled == 0
        if not ok:
            failed = True
            sys.stdout.write(disabled_out)
            sys.stdout.write(disabled_err)
            sys.stdout.write(enabled_out)
            sys.stdout.write(enabled_err)
        lines.append("| " + str(check_id) + " | " + str(disabled) + " | " + str(enabled) + " | " + ("PASS" if ok else "FAIL") + " |")
    script_text = (ROOT / "scripts" / "read-base-config.sh").read_text(encoding="utf-8")
    reverted_text = without_base_sha_guard(script_text)
    peeled_text = with_peel_check(script_text)
    if reverted_text is None or peeled_text is None:
        failed = True
        sys.stdout.write("base sha guard call missing\n")
        lines.append("| base-sha | missing | missing | FAIL |")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            reverted_path = Path(tmp) / "read-base-config.sh"
            reverted_path.write_text(reverted_text, encoding="utf-8")
            removed, removed_out, removed_err = run_base_sha_suite(str(reverted_path))
            peeled_path = Path(tmp) / "peeled.sh"
            peeled_path.write_text(peeled_text, encoding="utf-8")
            peeled, peeled_out, peeled_err = run_base_sha_suite(str(peeled_path))
        enabled, enabled_out, enabled_err = run_base_sha_suite("")
        disabled = 0 if removed == 0 or peeled == 0 else 1
        ok = disabled != 0 and enabled == 0
        if not ok:
            failed = True
            sys.stdout.write(removed_out)
            sys.stdout.write(removed_err)
            sys.stdout.write(peeled_out)
            sys.stdout.write(peeled_err)
            sys.stdout.write(enabled_out)
            sys.stdout.write(enabled_err)
        lines.append("| base-sha | " + str(disabled) + " | " + str(enabled) + " | " + ("PASS" if ok else "FAIL") + " |")
    proofs = [
        ("base-pin", without_base_pin, ["test_base_grade_pin_bootstrap", "test_base_grade_pin_other"], "test_base_grade_pin"),
        ("reserved-script", without_reserved_scripts, ["test_base_grade_house"], "test_base_grade_house"),
        ("base-unreadable", without_unreadable_base, ["test_base_grade_unreadable"], "test_base_grade_unreadable"),
    ]
    for name, weaken, disabled_patterns, enabled_pattern in proofs:
        ok_row, line = integrity_row(name, weaken, disabled_patterns, enabled_pattern)
        if not ok_row:
            failed = True
        lines.append(line)
    lines.append("| 8 | n/a | n/a | no function and no tests |")
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    dest = os.environ.get("GITHUB_STEP_SUMMARY")
    if dest:
        with open(dest, "a", encoding="utf-8") as handle:
            handle.write(text)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
