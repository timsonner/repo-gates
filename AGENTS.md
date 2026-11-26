# Agent rules for this repo

These rules apply to every author: any coding agent, whatever tool runs it, and humans.

- Work on a branch and open a PR. Never push to the default branch.
- Git author and committer: Tim Sonner <66705347+timsonner@users.noreply.github.com>. No Co-authored-by, Generated with, or agent footer lines in commits, PR titles or bodies.
- Before every push: format, lint with warnings as errors, and all tests green on that exact head, rebased on current main.
- Fill every section of the PR template with real content. Evidence must name the current head SHA. The house-rules check reads the PR body.
- No em dashes in prose.
- No code comments unless they carry a fact the code cannot: platform or hardware quirks, upstream bug links, `// SAFETY:` on Rust unsafe, license headers, Rust doc comments.
- Claims about hardware are tagged MEASURED (with the command) or UNVERIFIED.
- Do not merge. The owner squash-merges.
