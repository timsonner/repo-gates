#!/usr/bin/env python3
import argparse
import base64
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_KEY = "/workspace/secrets/repo-gates/timsonner-gates.private-key.pem"
DEFAULT_APP_ENV = "/workspace/secrets/repo-gates/app.env"
API_BASE = "https://api.github.com"
CONTEXT = "gate/verdict"
TRUSTED = ("trusted/house-rules", "trusted/rules-integrity")
ALLOWED_WORKFLOWS = {"trusted-gate.yml", "release.yml"}
ACTIONS_LOGIN = "github-actions[bot]"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def read_app_id(path):
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.startswith("GATES_APP_ID="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(2)


def openssl_sign(signing, key_path):
    proc = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_path], input=signing.encode("ascii"), capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write("openssl sign failed\n")
        raise SystemExit(1)
    return proc.stdout


def make_jwt(app_id, key_path, now=None, signer=None):
    moment = int(time.time() if now is None else now)
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": moment - 60, "exp": moment + 540, "iss": str(app_id)}
    signing = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")) + "." + b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = signer(signing, key_path) if signer else openssl_sign(signing, key_path)
    return signing + "." + b64url(signature)


class UrllibHTTP:
    def __call__(self, method, url, headers, body):
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                raw = response.read().decode("utf-8")
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            try:
                payload = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                payload = {}
            return exc.code, payload


def validate(args):
    if not isinstance(args.repo, str) or args.repo.count("/") != 1:
        return "repo must be owner/name"
    owner, name = args.repo.split("/", 1)
    if not owner or not name or "/" in name:
        return "repo must be owner/name"
    if not re.fullmatch(r"[0-9a-fA-F]{40}", args.sha or ""):
        return "sha must be 40 hex"
    if args.state not in {"success", "failure", "pending"}:
        return "state must be success, failure, or pending"
    if not isinstance(args.description, str) or args.description == "" or len(args.description) > 140:
        return "description must be 1 to 140 characters"
    if args.pr is not None and args.pr <= 0:
        return "pr must be a positive integer"
    return ""


def creator_login(status):
    creator = status.get("creator") or {}
    return creator.get("login", "")


def declares_reserved(name, text):
    if name in ALLOWED_WORKFLOWS:
        return False
    return re.search(r"(?:trusted|release|gate)/[A-Za-z0-9._-]+", text) is not None


def trusted_problem(statuses, workflows):
    for context in TRUSTED:
        matches = [item for item in statuses if item.get("context") == context]
        if len(matches) != 1:
            return "expected one " + context
        if matches[0].get("state") != "success":
            return context + " is not success"
        if creator_login(matches[0]) != ACTIONS_LOGIN:
            return context + " was not posted by GitHub Actions"
    for name, text in workflows:
        if declares_reserved(name, text):
            return name + " declares a reserved context"
    return ""


def needs_trusted(owner, repo, statuses):
    if owner == "timsonner" and repo == "repo-gates":
        return True
    return any(str(item.get("context", "")).startswith("trusted/") for item in statuses)


def gh_headers(token):
    return {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "repo-gates",
    }


def get_json(http, method, url, headers, body=None):
    status, payload = http(method, url, headers, body)
    if status >= 300:
        sys.stderr.write("http " + str(status) + "\n")
        raise SystemExit(1)
    return payload


def list_workflows(http, base, owner, repo, sha):
    url = base + "/repos/" + owner + "/" + repo + "/contents/.github/workflows?ref=" + sha
    status, payload = http("GET", url, {"Accept": "application/vnd.github+json", "User-Agent": "repo-gates"}, None)
    if status == 404:
        return []
    if status >= 300:
        sys.stderr.write("http " + str(status) + "\n")
        raise SystemExit(1)
    found = []
    for item in payload:
        name = item.get("name", "")
        file_url = base + "/repos/" + owner + "/" + repo + "/contents/" + item.get("path", "") + "?ref=" + sha
        file_status, file_payload = http("GET", file_url, {"Accept": "application/vnd.github+json", "User-Agent": "repo-gates"}, None)
        if file_status >= 300:
            sys.stderr.write("http " + str(file_status) + "\n")
            raise SystemExit(1)
        encoded = file_payload.get("content", "")
        text = base64.b64decode(encoded).decode("utf-8")
        found.append((name, text))
    return found


def post(args, http, signer=None, now=None, app_id=None, api_base=API_BASE):
    problem = validate(args)
    if problem:
        sys.stderr.write(problem + "\n")
        return 2
    owner, repo = args.repo.split("/", 1)
    if args.pr is not None:
        pr = get_json(http, "GET", api_base + "/repos/" + owner + "/" + repo + "/pulls/" + str(args.pr), {"Accept": "application/vnd.github+json", "User-Agent": "repo-gates"})
        head = ((pr.get("head") or {}).get("sha")) or ""
        if head.lower() != args.sha.lower():
            sys.stderr.write("stale head\n")
            return 3
    if args.state == "success":
        statuses = get_json(http, "GET", api_base + "/repos/" + owner + "/" + repo + "/commits/" + args.sha + "/statuses", {"Accept": "application/vnd.github+json", "User-Agent": "repo-gates"})
        if needs_trusted(owner, repo, statuses):
            workflows = list_workflows(http, api_base, owner, repo, args.sha)
            reason = trusted_problem(statuses, workflows)
            if reason:
                sys.stderr.write(reason + "\n")
                return 4
    chosen_app = app_id if app_id is not None else read_app_id(args.app_env)
    token_jwt = make_jwt(chosen_app, args.key, now=now, signer=signer)
    install = get_json(http, "GET", api_base + "/repos/" + owner + "/" + repo + "/installation", gh_headers(token_jwt))
    access = get_json(
        http,
        "POST",
        api_base + "/app/installations/" + str(install["id"]) + "/access_tokens",
        gh_headers(token_jwt),
        {"repositories": [repo], "permissions": {"statuses": "write"}},
    )
    token = access["token"]
    body = {"state": args.state, "context": CONTEXT, "description": args.description}
    if args.target_url:
        body["target_url"] = args.target_url
    posted = get_json(http, "POST", api_base + "/repos/" + owner + "/" + repo + "/statuses/" + args.sha, gh_headers(token), body)
    sys.stdout.write(str(posted.get("id")) + " " + str(posted.get("state")) + " " + str(posted.get("url")) + "\n")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--target-url", default="")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--key", default=DEFAULT_KEY)
    parser.add_argument("--app-id", default="")
    parser.add_argument("--app-env", default=DEFAULT_APP_ENV)
    return parser


def main(argv=None, http=None, signer=None, now=None, api_base=API_BASE):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return 2 if code else 0
    client = http or UrllibHTTP()
    app_id = args.app_id or None
    return post(args, client, signer=signer, now=now, app_id=app_id, api_base=api_base)


if __name__ == "__main__":
    sys.exit(main())
