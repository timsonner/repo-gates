#!/usr/bin/env python3
import ast
import os
import subprocess
import sys
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
