# PR-H — Dependency batch & branch hygiene (LOW)

**Model:** Haiku · **Release:** v1.11.x (patch) · **Read [`AGENT-GUIDE.md`](AGENT-GUIDE.md) first.**
**Blocked by:** PR-A (CI must be green before any dependabot PR can pass its check).

## Why this exists (context)

There are **10 open dependabot PRs** and 6 stale non-dependabot remote branches. Every dependabot PR
is currently red — not because the bump is bad, but because they inherit the same failing baseline tag
check that PR-A fixes. Once `main` is green, these should merge quickly. This is mechanical, fully
gate-checked by CI → Haiku-safe.

## Open dependabot PRs (as of 2026-07-15)

| PR | Bump | Kind |
|---|---|---|
| 128 | tqdm >=4.67.3 → >=4.68.4 | pip |
| 127 | ruff >=0.11.0 → >=0.15.21 | pip (dev) — **coordinate with PR-A2's exact pin** |
| 126 | boto3 >=1.34.0 → >=1.43.45 | pip (lambda) |
| 123 | pytest >=9.0.3 → >=9.1.1 | pip |
| 117 | actions/checkout 6 → 7 | actions |
| 116 | aws-actions/configure-aws-credentials 4 → 6 | actions |
| 112 | gitleaks/gitleaks-action 2 → 3 | actions |
| 111 | pytest-asyncio >=1.3.0 → >=1.4.0 | pip |
| 108 | urllib3 >=2.6.3 → >=2.7.0 | pip |
| 107 | aiodns ~=4.0.3 → ~=4.0.4 | pip |

## Tasks

### H1 — Merge the dependabot backlog (after PR-A)

For each PR, in this order (low-risk tooling first, then libs):
1. Confirm PR-A is merged and `main` CI is green.
2. For each dependabot PR: trigger a re-run (`gh pr comment <n> --body "@dependabot rebase"` or push
   the base), wait for CI green, then squash-merge.
3. **Special cases:**
   - **PR 127 (ruff):** PR-A2 pins ruff to an exact version. Either close 127 in favour of the pin, or
     let it bump and update the exact pin to match — do **not** end up with an unpinned range again.
   - **PR 117 (checkout 6→7):** verify PR-A's `fetch-depth: 0` addition is preserved on v7 (the input
     is unchanged across v6/v7, but re-check the merged workflow).
   - **PR 126 (boto3) / lambda-only deps:** only relevant if PR-E keeps the Lambda code (Option 1). If
     the maintainer chose PR-E Option 2 (extract Lambda), close boto3-related dependabot PRs instead.
4. After each merge, verify `main` CI stays green before doing the next.

**Success criteria:** dependabot backlog empty or each item consciously closed; `main` green
throughout; no dependency left on an unpinned range that PR-A/A2 intended to pin.
**Effort:** M (mostly waiting on CI).

### H2 — Prune stale branches

Remote branches that are merged or abandoned:
`change_threading`, `oopify`, `pylint_pep8`, `media`, `add-claude-github-actions-1778244733634`, and any
`feature/*` already merged. For each: confirm it is fully merged into `main`
(`git branch -r --merged origin/main`) **or** genuinely abandoned, then delete with
`git push origin --delete <branch>`. **Do not delete `feat/cname-chain-depth-tracking`** — that is an
open feature PR (104); leave it for review.

**Success criteria:** stale branches removed; open feature branches and any unmerged work untouched;
list the branches you deleted in the report.
**Effort:** S.

## Release

No feature change — bundle any resulting version-relevant dep changes into the current patch line and
note the batch in the release. If only dependencies changed, a patch bump with a "dependency batch"
note is appropriate.
