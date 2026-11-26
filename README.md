# repo-gates

repo-gates is the shared pull request gate for timsonner repositories. A caller workflow checks out a pinned revision of this repo and runs `scripts/house-rules.py`. The script reads the pull request title, body, commits, and diff. It writes a markdown table to the job summary and exits 1 when any check fails.

Pull requests in this repo are not graded by the code in the pull request head. `.github/workflows/trusted-gate.yml` runs on `pull_request_target` and executes only the scripts from the commit named in `.github/trusted-gates.json`.

## Checks

| Check | Name | Result when it fires |
| --- | --- | --- |
| 2 | Author and committer identity | FAIL |
| 3 | Em dash in title, body, and commits; em dash on an added markdown line | FAIL, and WARN for markdown |
| 4 | Pull request body content and changed-file scope | FAIL, scope follows scope_mode |
| 5 | Evidence Head pin | FAIL |
| 6 | Workflow edits require risk high | FAIL |
| 7 | New comments, including a trailing comment on an added line | WARN, or FAIL when comments_mode is fail |
| 8 | Model pins | dropped |
| 9 | Token shapes and non-noreply emails | WARN |

Checks 1 and 8 are not implemented. The summary has no row 1 or row 8.

## Adopt this in a repository

1. Copy `templates/caller-house-rules.yml` to `.github/workflows/house-rules.yml`. Replace both SHA placeholders with the same full commit SHA from the version table. Do not add YAML comments.
2. Copy `templates/pull_request_template.md` to `.github/pull_request_template.md`.
3. Merge the lines from `templates/AGENTS.md` into the repo `AGENTS.md`.
4. Open one pull request and let the check run.
5. Read the check-runs API for that head and confirm the context name. For a job id `house-rules` the context string to confirm is `house-rules / check`.
6. Apply `rulesets/baseline-a.json` after adding the repo's own CI context names beside `house-rules / check`.
7. Add `gate/verdict` as a required check only after the first successful post from `tools/post-verdict.py`.

`rulesets/baseline-d.json` is the default-branch ruleset for this repo. It requires `trusted/house-rules` and `trusted/rules-integrity`.

## Versions

| Tag | SHA |
| --- | --- |
| bootstrap | bootstrap |

Callers pin a full SHA. The workflow `uses` line does not float on a tag. The bootstrap row means this repo grades its own pull requests with the base commit until the first release tag.

## Post a verdict

`tools/post-verdict.py` posts the `gate/verdict` commit status. The GitHub App key stays outside this repo.

```
python3 tools/post-verdict.py --repo owner/name --sha <40 hex> --state success --description "short text" --pr <number>
```

The default key path is `/workspace/secrets/repo-gates/timsonner-gates.private-key.pem`. The default app id is `GATES_APP_ID` in `/workspace/secrets/repo-gates/app.env`. `--pr` is required. The command refuses unless `--sha` is the current head of that pull request. On this repo, a success verdict is refused unless `trusted/house-rules` and `trusted/rules-integrity` are both success on that exact sha, posted by GitHub Actions, exactly once each, and no other workflow declares a `trusted/`, `release/`, or `gate/` context. The script prints the status id, state, and URL. It does not print the token.

The first post on a repo needs Tim's OK.

## Rollback for an adopting repo

Revert the caller workflow pull request, or push a new commit that restores the previous workflow SHA pin. Remove the ruleset if it blocks merges. No data migration is required.

## Release

`.github/workflows/release.yml` is `workflow_dispatch` on `main`. It runs the previous release tests against the new checker, then the current tests. The tag job tags `github.sha` and posts `release/verify`. After that, open a one line pull request that sets `.github/trusted-gates.json` to the new tag and SHA. That pull request is graded by the previous pin. The new checker grades later pull requests only after the pin pull request merges.

Tag updates and deletions on `refs/tags/v*` should be blocked by a tag ruleset. The exact ruleset fields for a personal repo are UNVERIFIED until applied live.
