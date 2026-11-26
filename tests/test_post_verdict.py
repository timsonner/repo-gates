#!/usr/bin/env python3
import base64
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHA = "a" * 40
OTHER = "b" * 40


def load_tool():
    path = ROOT / "tools" / "post-verdict.py"
    spec = importlib.util.spec_from_file_location("post_verdict_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeHTTP:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, body))
        for predicate, result in self.routes:
            if predicate(method, url):
                return result
        raise AssertionError(method + " " + url)


def route_has(fragment):
    return lambda method, url: fragment in url


def run(argv, http=None, signer=None):
    module = load_tool()
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = module.main(argv, http=http, signer=signer or (lambda signing, key: b"sig"), now=1700000000, api_base="https://example.test")
    return code, stdout.getvalue(), stderr.getvalue()


def status_item(context):
    return {"context": context, "state": "success", "creator": {"login": "github-actions[bot]"}}


def workflow_routes(names):
    listing = [{"name": name, "path": ".github/workflows/" + name} for name in names]
    routes = [(route_has("/contents/.github/workflows?"), (200, listing))]
    for name in names:
        encoded = base64.b64encode(b"name: ci\non:\n  pull_request:\n").decode("ascii")
        routes.append((route_has("/contents/.github/workflows/" + name), (200, {"content": encoded})))
    return routes


class TestPostVerdict(unittest.TestCase):
    def test_rejects_bad_arguments(self):
        code, _out, err = run(["--repo", "timsonner/repo-gates", "--sha", SHA, "--state", "failure", "--description", "nope", "--app-id", "1"])
        self.assertEqual(code, 2)
        self.assertIn("pr", err)
        code, _out, err = run(["--repo", "timsonner/repo-gates", "--sha", "abc", "--state", "failure", "--description", "nope", "--pr", "1", "--app-id", "1"])
        self.assertEqual(code, 2)
        self.assertIn("sha", err)
        code, _out, err = run(["--repo", "timsonner/repo-gates", "--sha", SHA, "--state", "nope", "--description", "nope", "--pr", "1", "--app-id", "1"])
        self.assertEqual(code, 2)
        long_text = "x" * 141
        code, _out, err = run(["--repo", "only", "--sha", SHA, "--state", "failure", "--description", "nope", "--pr", "1", "--app-id", "1"])
        self.assertEqual(code, 2)
        code, _out, err = run(["--repo", "timsonner/repo-gates", "--sha", SHA, "--state", "failure", "--description", long_text, "--pr", "1", "--app-id", "1"])
        self.assertEqual(code, 2)
        self.assertIn("140", err)

    def test_stale_head_refuses(self):
        http = FakeHTTP([(route_has("/pulls/5"), (200, {"head": {"sha": OTHER}}))])
        code, _out, err = run(["--repo", "timsonner/repo-gates", "--sha", SHA, "--state", "failure", "--description", "stale", "--pr", "5", "--app-id", "1"], http=http)
        self.assertEqual(code, 3)
        self.assertIn("stale", err)
        self.assertFalse(any(call[0] == "POST" for call in http.calls))

    def test_success_without_trusted_statuses_refuses(self):
        http = FakeHTTP(
            [
                (route_has("/pulls/5"), (200, {"head": {"sha": SHA}})),
                (route_has("/statuses"), (200, [])),
                (route_has("/contents/.github/workflows?"), (404, {})),
            ]
        )
        code, _out, err = run(["--repo", "timsonner/repo-gates", "--sha", SHA, "--state", "success", "--description", "grade", "--pr", "5", "--app-id", "1"], http=http)
        self.assertEqual(code, 4)
        self.assertTrue(err)
        self.assertFalse(any("/access_tokens" in call[1] for call in http.calls))

    def test_success_posts_when_trusted_statuses_match(self):
        statuses = [status_item("trusted/house-rules"), status_item("trusted/rules-integrity")]
        routes = [(route_has("/commits/" + SHA + "/statuses"), (200, statuses))]
        routes.extend(workflow_routes(["ci.yml", "trusted-gate.yml", "release.yml"]))
        http = FakeHTTP(routes)
        code, out, err = run(["--repo", "timsonner/repo-gates", "--sha", SHA, "--state", "success", "--description", "grade", "--app-id", "12"], http=http)
        self.assertEqual(code, 2)
        self.assertIn("pr", err)
        self.assertNotEqual(out.strip(), "42 success https://example.test/status/42")
        self.assertFalse(any(call[0] == "POST" for call in http.calls))

    def test_success_posts_when_pr_head_matches(self):
        statuses = [status_item("trusted/house-rules"), status_item("trusted/rules-integrity")]
        routes = [
            (route_has("/pulls/5"), (200, {"head": {"sha": SHA}})),
            (route_has("/commits/" + SHA + "/statuses"), (200, statuses)),
        ]
        routes.extend(workflow_routes(["ci.yml", "trusted-gate.yml", "release.yml"]))
        routes.extend(
            [
                (lambda method, url: url.endswith("/installation"), (200, {"id": 9})),
                (lambda method, url: url.endswith("/access_tokens"), (200, {"token": "installed-token"})),
                (lambda method, url: method == "POST" and url.endswith("/statuses/" + SHA), (201, {"id": 42, "state": "success", "url": "https://example.test/status/42"})),
            ]
        )
        http = FakeHTTP(routes)
        code, out, err = run(["--repo", "timsonner/repo-gates", "--sha", SHA, "--state", "success", "--description", "grade", "--pr", "5", "--app-id", "12"], http=http)
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "42 success https://example.test/status/42\n")
        self.assertNotIn("installed-token", out)
        self.assertNotIn("installed-token", err)

    def test_reserved_workflow_refuses_success(self):
        statuses = [status_item("trusted/house-rules"), status_item("trusted/rules-integrity")]
        listing = [{"name": "evil.yml", "path": ".github/workflows/evil.yml"}]
        encoded = base64.b64encode(b"context: trusted/house-rules\n").decode("ascii")
        http = FakeHTTP(
            [
                (route_has("/pulls/5"), (200, {"head": {"sha": SHA}})),
                (route_has("/commits/" + SHA + "/statuses"), (200, statuses)),
                (route_has("/contents/.github/workflows?"), (200, listing)),
                (route_has("/contents/.github/workflows/evil.yml"), (200, {"content": encoded})),
            ]
        )
        code, _out, err = run(["--repo", "timsonner/repo-gates", "--sha", SHA, "--state", "success", "--description", "grade", "--pr", "5", "--app-id", "1"], http=http)
        self.assertEqual(code, 4)
        self.assertIn("evil.yml", err)

    def test_jwt_window(self):
        module = load_tool()
        token = module.make_jwt("12", "ignored", now=1700000000, signer=lambda signing, key: b"abc")
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        self.assertEqual(data["iss"], "12")
        self.assertEqual(data["iat"], 1700000000 - 60)
        self.assertEqual(data["exp"], 1700000000 + 540)


if __name__ == "__main__":
    unittest.main()
