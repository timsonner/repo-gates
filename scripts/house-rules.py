#!/usr/bin/env python3
import io
import json
import os
import re
import subprocess
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "rules" / "manifest.json"
HASH = chr(35)
EM = "\u2014"
AGENT_FOOTER_EXACT = (
    re.compile(r"<!--\s*CURSOR_AGENT_PR_BODY_BEGIN\s*-->"),
    re.compile(r"<!--\s*CURSOR_AGENT_PR_BODY_END\s*-->"),
    re.compile(r"cursor\.com/agents/\S*cursor_ref=pr_footer"),
    re.compile(r"cursor\.com/background-agent[/?]\S*cursor_ref=pr_footer"),
)

DISPATCH = {
    1: "check_trailers",
    2: "check_identity",
    3: "check_em_dash",
    4: "check_pr_body",
    5: "check_head_pin",
    6: "check_risk_tier",
    7: "check_comments",
    9: "check_secrets",
}

PLAN_FIELDS = ("Goal", "Scope (paths)", "Success criteria", "Risk")
KNOWN_FIELDS = {
    "Goal",
    "Scope (paths)",
    "Steps",
    "Success criteria",
    "Risk",
    "Plan file",
    "Head",
    "Rollback",
    "Risks",
}


def load_manifest(path=None):
    target = Path(path) if path else MANIFEST_PATH
    return json.loads(target.read_text(encoding="utf-8"))


def refuse_disable():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return False
    if not os.environ.get("HOUSE_RULES_DISABLE", "").strip():
        return False
    if os.environ.get("HOUSE_RULES_TEST") == "1":
        return False
    return True


def skipped(check_id):
    if os.environ.get("HOUSE_RULES_TEST") != "1":
        return False
    raw = os.environ.get("HOUSE_RULES_DISABLE", "")
    parts = {item.strip() for item in raw.split(",") if item.strip()}
    return str(check_id) in parts


class Finding:
    def __init__(self, check, level, reason):
        self.check = check
        self.level = level
        self.reason = reason


class Ctx:
    def __init__(self, manifest, title, body, commits, files, added, head_sha, scope_mode, comments_mode, allowed_authors):
        self.manifest = manifest
        self.title = title or ""
        self.body = body or ""
        self.commits = commits or []
        self.files = files or []
        self.added = added or []
        self.head_sha = head_sha or ""
        self.scope_mode = scope_mode or manifest["defaults"]["scope_mode"]
        self.comments_mode = comments_mode or manifest["defaults"]["comments_mode"]
        self.allowed_authors = allowed_authors or ""


def check_meta(ctx, check_id):
    for item in ctx.manifest["checks"]:
        if item["id"] == check_id:
            return item
    return {"id": check_id, "severity": "FAIL"}


def gate(ctx, check_id):
    if skipped(check_id):
        return True
    if str(check_meta(ctx, check_id).get("severity", "FAIL")).lower() == "off":
        return True
    return False


def severity(ctx, check_id):
    return check_meta(ctx, check_id).get("severity", "FAIL")


def identity_text(ctx):
    item = ctx.manifest["identity"]
    return item["name"] + " <" + item["email"] + ">"


def allowed_identity_set(ctx):
    found = {identity_text(ctx)}
    for line in ctx.allowed_authors.splitlines():
        text = line.strip()
        if text:
            found.add(text)
    return found


def compile_shapes(manifest):
    compiled = []
    for item in manifest["token_shapes"]:
        if isinstance(item, str):
            compiled.append(re.compile(item))
        else:
            compiled.append(re.compile("".join(item["regex_parts"])))
    return compiled


def shape_sample(item):
    if isinstance(item, str):
        return item
    return "".join(item.get("sample_parts") or item.get("regex_parts") or [])


def section_text(body, title):
    lines = (body or "").splitlines()
    start = None
    marker = "## " + title
    for index, line in enumerate(lines):
        if line.strip() == marker:
            start = index + 1
            break
    if start is None:
        return None
    chunk = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        chunk.append(line)
    return "\n".join(chunk)


def parse_fields(text):
    found = {}
    current = None
    if text is None:
        return found
    for line in text.splitlines():
        stripped = line.strip()
        match = re.match(r"^(?:-\s*)?([^:]+):\s*(.*)$", stripped)
        name = match.group(1).strip() if match else ""
        if match and name in KNOWN_FIELDS:
            current = name
            found[current] = match.group(2).strip()
            continue
        if current and stripped:
            found[current] = (found[current] + "\n" + stripped).strip()
    return found


def is_placeholder(value, field_name, manifest):
    if value is None:
        return True
    text = value.strip()
    if text == "":
        return True
    if re.search(r"<[^>\n]+>", text):
        return True
    if text in manifest.get("placeholders", []):
        if field_name == "Plan file" and text.lower() == "n/a":
            return False
        return True
    lowered = text.lower()
    if lowered == "tbd":
        return True
    if lowered in {"n/a", "na"}:
        return field_name != "Plan file"
    return False


def risk_value(body, manifest):
    fields = parse_fields(section_text(body, "Plan"))
    raw = fields.get("Risk", "")
    text = raw.strip().splitlines()[0].strip() if raw.strip() else ""
    if text in manifest.get("risk_ranks", {}):
        return text
    return ""


def scope_patterns(body):
    fields = parse_fields(section_text(body, "Plan"))
    raw = fields.get("Scope (paths)", "")
    parts = re.split(r"[,\n]", raw)
    cleaned = []
    for part in parts:
        item = part.strip().strip("`").lstrip("-").strip()
        if item:
            cleaned.append(item)
    return cleaned


def path_in_scope(path, patterns):
    import fnmatch

    norm = path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    for pattern in patterns:
        if fnmatch.fnmatchcase(norm, pattern):
            return True
        if any(ch in pattern for ch in "*?["):
            continue
        base = pattern.rstrip("/")
        if norm == base or norm.startswith(base + "/"):
            return True
    return False


def evidence_head(body, manifest):
    text = section_text(body, "Evidence")
    if text is None:
        return ""
    length = int(manifest["limits"]["min_head_sha_hex_length"])
    match = re.search(r"(?m)^(?:-\s*)?Head:\s*([0-9a-fA-F]+)\s*$", text)
    if not match:
        return ""
    sha = match.group(1)
    if len(sha) != length:
        return ""
    return sha


def rollback_text(body):
    fields = parse_fields(section_text(body, "Risk and rollback"))
    return fields.get("Rollback", "").strip()


def self_check_hits(body, manifest):
    text = section_text(body, "Self-check (pr-review-gate)")
    if text is None:
        return []
    need = int(manifest["limits"]["min_self_check_boxes"])
    labels = list(manifest["self_check_labels"])[:need]
    hits = []
    for label in labels:
        matched = False
        for line in text.splitlines():
            if re.match(r"^-\s*\[[xX]\]\s*" + re.escape(label) + r"(?:\s|$)", line.strip()):
                matched = True
                break
        hits.append((label, matched))
    return hits


def texts_for_trailers(ctx):
    items = [("title", ctx.title), ("body", ctx.body)]
    for commit in ctx.commits:
        items.append(("commit " + commit.get("sha", ""), commit.get("message", "")))
    return items


def matches_agent_footer(text, footer):
    if footer.lower() == "cursor":
        for pattern in AGENT_FOOTER_EXACT:
            if pattern.search(text):
                return True
        return False
    return footer.lower() in text.lower()


def check_trailers(ctx):
    if gate(ctx, 1):
        return []
    level = severity(ctx, 1)
    exact = ctx.manifest.get("signed_off_allow_exact", identity_text(ctx))
    found = []
    for label, text in texts_for_trailers(ctx):
        for line in text.splitlines() or [""]:
            stripped = line.strip()
            if not stripped:
                continue
            for pattern in ctx.manifest["trailer_patterns"]:
                if re.search(r"signed-off-by", pattern, re.I):
                    match = re.match(r"(?i)^signed-off-by:\s*(.*)$", stripped)
                    if match and match.group(1).strip() == exact:
                        continue
                if re.search(pattern, stripped, re.I):
                    found.append(Finding(1, level, label + " matches " + pattern))
                    break
            for footer in ctx.manifest["agent_footers"]:
                if matches_agent_footer(stripped, footer):
                    found.append(Finding(1, level, label + " has agent footer " + footer))
                    break
    return found


def check_identity(ctx):
    if gate(ctx, 2):
        return []
    level = severity(ctx, 2)
    allowed = allowed_identity_set(ctx)
    found = []
    for commit in ctx.commits:
        author = commit.get("author_name", "") + " <" + commit.get("author_email", "") + ">"
        committer = commit.get("committer_name", "") + " <" + commit.get("committer_email", "") + ">"
        sha = commit.get("sha", "")
        if author not in allowed:
            found.append(Finding(2, level, "author " + author + " on " + sha))
        if committer not in allowed:
            found.append(Finding(2, level, "committer " + committer + " on " + sha))
    return found


def check_em_dash(ctx):
    if gate(ctx, 3):
        return []
    level = severity(ctx, 3)
    md_level = check_meta(ctx, 3).get("md_added_severity", "WARN")
    found = []
    if EM in ctx.title:
        found.append(Finding(3, level, "em dash in title"))
    if EM in ctx.body:
        found.append(Finding(3, level, "em dash in body"))
    for commit in ctx.commits:
        if EM in commit.get("message", ""):
            found.append(Finding(3, level, "em dash in commit " + commit.get("sha", "")))
    if str(md_level).lower() == "off":
        return found
    for line in ctx.added:
        path = line.get("path", "")
        if path.endswith(".md") and EM in line.get("text", ""):
            found.append(Finding(3, md_level, "em dash in added markdown " + path))
    return found


def check_pr_body(ctx):
    if gate(ctx, 4):
        return []
    level = severity(ctx, 4)
    found = []
    plan = section_text(ctx.body, "Plan")
    if plan is None:
        found.append(Finding(4, level, "missing Plan section"))
    else:
        fields = parse_fields(plan)
        for name in PLAN_FIELDS:
            value = fields.get(name)
            if name == "Risk":
                if is_placeholder(value, name, ctx.manifest) or value not in ctx.manifest.get("risk_ranks", {}):
                    found.append(Finding(4, level, "Risk is missing or not a single tier"))
                continue
            if is_placeholder(value, name, ctx.manifest):
                found.append(Finding(4, level, name + " is missing"))
        patterns = scope_patterns(ctx.body)
        mode = (ctx.scope_mode or "warn").lower()
        scope_level = "FAIL" if mode == "fail" else "WARN"
        outside = [path for path in ctx.files if not path_in_scope(path, patterns)]
        if outside:
            found.append(Finding(4, scope_level, "outside scope: " + ", ".join(outside)))
    evidence = section_text(ctx.body, "Evidence")
    if evidence is None:
        found.append(Finding(4, level, "missing Evidence section"))
    else:
        if not evidence_head(ctx.body, ctx.manifest):
            found.append(Finding(4, level, "Evidence Head is not a full sha"))
        has_exit = re.search(r"exit\s*=\s*\d+|exit\s+\d+|\(\d+\)", evidence) is not None
        has_run = re.search(r"https://github\.com/\S+/actions/runs/\d+", evidence) is not None
        if not has_exit and not has_run:
            found.append(Finding(4, level, "Evidence has no command exit code or workflow run"))
    risk = risk_value(ctx.body, ctx.manifest)
    limit = int(ctx.manifest["limits"]["max_risk_rank_without_rollback"])
    rank = ctx.manifest.get("risk_ranks", {}).get(risk, 0)
    if rank > limit:
        rollback = rollback_text(ctx.body)
        if is_placeholder(rollback, "Rollback", ctx.manifest):
            found.append(Finding(4, level, "Rollback is missing for risk " + risk))
    labels = self_check_hits(ctx.body, ctx.manifest)
    if section_text(ctx.body, "Self-check (pr-review-gate)") is None:
        found.append(Finding(4, level, "missing Self-check section"))
    else:
        for label, matched in labels:
            if not matched:
                found.append(Finding(4, level, "unticked self-check: " + label))
        need = int(ctx.manifest["limits"]["min_self_check_boxes"])
        ticked = len([item for item in labels if item[1]])
        if ticked < need and len(labels) < need:
            found.append(Finding(4, level, "self-check box count under limit"))
    return found


def check_head_pin(ctx):
    if gate(ctx, 5):
        return []
    level = severity(ctx, 5)
    pinned = evidence_head(ctx.body, ctx.manifest)
    if not ctx.head_sha:
        return [Finding(5, level, "HEAD_SHA is missing")]
    if pinned.lower() != ctx.head_sha.lower():
        return [Finding(5, level, "Head " + (pinned or "missing") + " != " + ctx.head_sha)]
    return []


def check_risk_tier(ctx):
    if gate(ctx, 6):
        return []
    level = severity(ctx, 6)
    workflows = [path for path in ctx.files if path.replace("\\", "/").startswith(".github/workflows/")]
    if not workflows:
        return []
    risk = risk_value(ctx.body, ctx.manifest)
    if risk != "high":
        return [Finding(6, level, "workflow change requires Risk high, got " + (risk or "missing"))]
    return []


def hash_comment_at(text, triples=False, shell=False):
    quote = ""
    triple = False
    escaped = False
    brace = 0
    index = 0
    length = len(text)
    while index < length:
        ch = text[index]
        if quote:
            if triple:
                if text.startswith(quote * 3, index):
                    quote = ""
                    triple = False
                    index += 3
                    continue
            elif escaped:
                escaped = False
            elif ch == "\\" and quote == '"':
                escaped = True
            elif ch == quote:
                quote = ""
            index += 1
            continue
        if triples and (text.startswith('"""', index) or text.startswith("'''", index)):
            quote = text[index]
            triple = True
            index += 3
            continue
        if ch in ("'", '"'):
            quote = ch
            triple = False
            escaped = False
            index += 1
            continue
        if shell and ch == "$" and index + 1 < length and text[index + 1] == "{":
            brace += 1
            index += 2
            continue
        if shell and ch == "}" and brace:
            brace -= 1
            index += 1
            continue
        if ch == HASH:
            if shell:
                if brace == 0 and (index == 0 or text[index - 1].isspace()):
                    return index
            elif index == 0 or text[index - 1] not in ("$", "{"):
                return index
        index += 1
    return None


def python_comment_at(text):
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type != tokenize.COMMENT:
                continue
            comment = token.string
            body = text.splitlines()[0] if text.splitlines() else text
            if body.endswith(comment):
                return len(body) - len(comment)
            found = body.rfind(comment)
            if found >= 0:
                return found
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return hash_comment_at(text, triples=True)
    return None


def slash_comment_at(text, suffix):
    if suffix == ".rs":
        quotes = {'"'}
    elif suffix == ".go":
        quotes = {'"', "`"}
    else:
        quotes = {'"', "'", "`"}
    quote = ""
    escaped = False
    index = 0
    length = len(text)
    while index < length:
        ch = text[index]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\" and quote != "`":
                escaped = True
            elif ch == quote:
                quote = ""
            index += 1
            continue
        if ch in quotes:
            quote = ch
            escaped = False
            index += 1
            continue
        if text.startswith("//", index) or text.startswith("/*", index):
            return index
        index += 1
    return None


def comment_slice(text, suffix):
    if suffix == ".py":
        index = python_comment_at(text)
    elif suffix in {".sh", ".nix"}:
        index = hash_comment_at(text, shell=(suffix == ".sh"))
    elif suffix in {".rs", ".js", ".ts", ".go", ".swift"}:
        index = slash_comment_at(text, suffix)
    else:
        index = None
    if index is None:
        return None
    return text[index:]


def comment_allowed(stripped, line_no, allow):
    for entry in allow:
        if entry == "#!":
            if line_no == 1 and stripped.startswith("#!"):
                return True
            continue
        if entry.startswith("/") or entry.startswith("#!"):
            if stripped.startswith(entry):
                return True
            continue
        if entry in stripped:
            return True
    return False


def check_comments(ctx):
    if gate(ctx, 7):
        return []
    mode = (ctx.comments_mode or ctx.manifest["defaults"]["comments_mode"]).lower()
    level = "FAIL" if mode == "fail" else "WARN"
    extensions = set(ctx.manifest["comment_extensions"])
    allow = ctx.manifest["comment_allow"]
    found = []
    for line in ctx.added:
        path = line.get("path", "")
        suffix = Path(path).suffix.lower()
        if suffix not in extensions:
            continue
        raw = line.get("text", "")
        if not raw.strip():
            continue
        comment = comment_slice(raw, suffix)
        if comment is None:
            continue
        line_no = int(line.get("line_no") or 0)
        if comment_allowed(comment.lstrip(), line_no, allow):
            continue
        found.append(Finding(7, level, "comment in " + path + ":" + str(line_no)))
    return found


def check_secrets(ctx):
    if gate(ctx, 9):
        return []
    level = severity(ctx, 9)
    shapes = compile_shapes(ctx.manifest)
    email = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
    found = []
    for line in ctx.added:
        text = line.get("text", "")
        path = line.get("path", "")
        for shape in shapes:
            if shape.search(text):
                found.append(Finding(9, level, "token shape in " + path))
                break
        for match in email.finditer(text):
            if not match.group(0).endswith("@users.noreply.github.com"):
                found.append(Finding(9, level, "email in " + path))
                break
    return found


def run_checks(ctx):
    found = []
    for check_id in [item["id"] for item in ctx.manifest["checks"]]:
        name = DISPATCH.get(check_id)
        if not name:
            continue
        found.extend(globals()[name](ctx))
    return found


def worst(findings, check_id):
    rank = {"PASS": 0, "WARN": 1, "FAIL": 2}
    levels = [item.level for item in findings if item.check == check_id]
    if not levels:
        return "PASS"
    return max(levels, key=lambda level: rank[level])


def render(findings, manifest, risk):
    lines = ["Risk tier: " + (risk or "missing"), "", "| Check | Result | Reason |", "| --- | --- | --- |"]
    grouped = {}
    for item in findings:
        grouped.setdefault(item.check, []).append(item)
    for check in manifest["checks"]:
        check_id = check["id"]
        items = grouped.get(check_id, [])
        level = worst(items, check_id)
        reason = "; ".join(item.reason for item in items).replace("|", "/").replace("\n", " ")
        lines.append("| " + str(check_id) + " | " + level + " | " + reason + " |")
    return "\n".join(lines) + "\n"


def git_text(args):
    proc = subprocess.run(["git", *args], capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def parse_commits(raw):
    commits = []
    for record in raw.split("\x1e"):
        record = record.strip("\n")
        if not record.strip():
            continue
        parts = record.split("\x00")
        if len(parts) < 6:
            continue
        commits.append(
            {
                "sha": parts[0],
                "author_name": parts[1],
                "author_email": parts[2],
                "committer_name": parts[3],
                "committer_email": parts[4],
                "message": parts[5],
            }
        )
    return commits


def parse_added(diff):
    added = []
    path = None
    new_line = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path = None
            new_line = None
            continue
        if line.startswith("+++ "):
            name = line[4:]
            if name.startswith("b/"):
                name = name[2:]
            path = None if name == "/dev/null" else name
            continue
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            new_line = int(match.group(1)) if match else 0
            continue
        if line.startswith("+") and not line.startswith("+++"):
            if path is not None and new_line:
                added.append({"path": path, "line_no": new_line, "text": line[1:]})
                new_line += 1
            elif path is not None and new_line == 0:
                new_line = 1
                added.append({"path": path, "line_no": new_line, "text": line[1:]})
                new_line += 1
            continue
        if line.startswith("-"):
            continue
        if line.startswith("\\"):
            continue
        if path is not None and new_line:
            new_line += 1
    return added


def load_git(base, head):
    code, log_text, err = git_text(["log", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x1e", base + ".." + head])
    if code != 0:
        raise RuntimeError(err.strip() or "git log failed")
    code, names, err = git_text(["diff", "--name-only", base + "..." + head])
    if code != 0:
        raise RuntimeError(err.strip() or "git diff names failed")
    code, diff, err = git_text(["diff", "-U0", base + "..." + head])
    if code != 0:
        raise RuntimeError(err.strip() or "git diff failed")
    files = [line for line in names.splitlines() if line.strip()]
    return parse_commits(log_text), files, parse_added(diff)


def build_ctx_from_env(manifest):
    base = os.environ.get("BASE_SHA", "")
    head = os.environ.get("HEAD_SHA", "")
    commits, files, added = ([], [], [])
    if base and head:
        commits, files, added = load_git(base, head)
    return Ctx(
        manifest,
        os.environ.get("PR_TITLE", ""),
        os.environ.get("PR_BODY", ""),
        commits,
        files,
        added,
        head,
        os.environ.get("SCOPE_MODE", ""),
        os.environ.get("COMMENTS_MODE", ""),
        os.environ.get("ALLOWED_AUTHORS", ""),
    )


def main():
    if refuse_disable():
        sys.stderr.write("HOUSE_RULES_DISABLE is refused\n")
        return 2
    manifest = load_manifest()
    try:
        ctx = build_ctx_from_env(manifest)
    except RuntimeError as exc:
        text = "Risk tier: missing\n\n| Check | Result | Reason |\n| --- | --- | --- |\n| 4 | FAIL | " + str(exc).replace("|", "/") + " |\n"
        write_summary(text)
        return 1
    findings = run_checks(ctx)
    risk = risk_value(ctx.body, manifest)
    text = render(findings, manifest, risk)
    write_summary(text)
    if any(item.level == "FAIL" for item in findings):
        return 1
    return 0


def write_summary(text):
    dest = os.environ.get("GITHUB_STEP_SUMMARY")
    if dest:
        with open(dest, "a", encoding="utf-8") as handle:
            handle.write(text)
        return
    sys.stdout.write(text)


if __name__ == "__main__":
    sys.exit(main())
