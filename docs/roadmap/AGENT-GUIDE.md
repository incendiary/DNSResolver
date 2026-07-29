# Agent Guide — read this before starting any roadmap PR

You are implementing one bundled PR from [`../../ROADMAP.md`](../../ROADMAP.md). Each PR has its own
plan file in this folder. This guide holds the rules that apply to **all** of them. Follow it exactly
— it encodes the project's devops-practices standards. If anything here conflicts with a specific PR
plan, the PR plan wins for that task only.

## 0. Ground truth about this repo (so you don't rediscover it)

- **Language/runtime:** Python 3.12. Native dep `pycares` (via `aiodns`) needs a C toolchain to
  build wheels — normally fine on macOS/Linux with prebuilt wheels.
- **Entry points:** `resolver.py` (CLI) and `lambda_handler.py` (AWS Lambda). Both call the shared
  `run()` in `resolver.py`.
- **Config:** `config.json` has two keys — `config` (defaults: timeout, retries, output dir) and
  `domain_categorisation` (60 regex patterns classifying dangling-CNAME targets). CLI flags override
  config values.
- **Version source of truth:** the `VERSION` file (one line, `X.Y.Z`). `version.py` mirrors it, and a
  git tag `vX.Y.Z` + GitHub release must match. A baseline test enforces all three agree.
- **Tests:** `pytest`, async via `pytest.ini` `asyncio_mode = auto`. 144 tests pass today. Baseline
  invariant tests live in `tests/baseline/`.
- **Lint/format:** `ruff check .` and `ruff format --check .`. Both gate CI.
- **Coverage today:** 85% overall. It must **never go down**.

## 1. Environment setup (do this once)

```bash
cd /path/to/DNSResolver
/opt/homebrew/bin/python3.12 -m venv .venv      # or any Python 3.12; DO NOT use a broken pyenv shim
source .venv/bin/activate
pip install -r requirements-dev.txt -r requirements-lambda.txt   # dev = runtime+ruff+pytest; lambda = +boto3
python -c "import aiodns, dns, tqdm, boto3; print('deps OK')"
```

> **Why both files:** `requirements-lambda.txt` adds `boto3`. Without it, `tests/test_lambda_handler.py`
> fails with `ModuleNotFoundError: No module named 'boto3'` — that is an environment gap, **not** a
> code bug. CI installs both. Install both locally so your run matches CI.

## 2. Branch & commit discipline (devops-practices)

- **Branch from latest `main`:** `git fetch origin && git checkout -b <type>/<short-name> origin/main`.
  Branch names: `fix/…`, `feat/…`, `docs/…`, `ci/…`, `chore/…`, `test/…`.
- **Never rebase a pushed branch onto main.** Use `git merge main` to catch up (rebase silently drops
  commits when squash-merge is in use).
- **Conventional commit titles:** `fix:`, `feat:`, `docs:`, `ci:`, `chore:`, `test:`. One logical
  change per commit where practical.
- **Squash merge to main.** History stays linear.
- **End every commit message with:**
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```
- **Do NOT commit or push unless the human asked you to.** Default: leave the work on a branch and
  report. If told to push, open a PR with a conventional title and a body that references the
  originating review item (use the full raw issue URL in backticks, never `owner/repo#N` shorthand —
  it creates cross-repo pingbacks).
- **NEVER create a git tag.** Tagging happens only when a release is actually cut, by the maintainer.
  Creating a tag for an unreleased version corrupts the baseline version-sync test for *every other
  branch* (a real incident: two agents tagged `v1.10.6`/`v1.11.0` locally and broke PR-A's baseline
  test, which correctly asserts VERSION is not older than the highest existing tag).
- **Do NOT bump `VERSION` or `version.py` unless your plan explicitly tells you to.** Versioning is
  handled **centrally at release time**, not per-PR. Reason (learned the hard way): when three agents
  each bumped VERSION on branches cut from the same base, every branch conflicted on `VERSION` +
  `version.py` at merge, and two agents "solved" their failing baseline test by creating bogus tags.
  devops-practices groups related PRs into a *single* point bump per batch — so the batch gets one
  bump, not one per PR.
- **If the baseline tag test fails because a bumped VERSION has no tag** — that is expected and
  correct on an unreleased bump. After PR-A, the test tolerates it (VERSION newer than the highest tag
  passes). Do not "fix" it by creating a tag, and do not weaken the test.

## 3. The mandatory local gate (run before every push)

This project went red in CI from a change that looked green locally. Prevent a repeat:

```bash
# 1. Lint + format + tests exactly as CI runs them
bash ~/.claude/skills/local-ci/local-ci.sh --workflow ci.yml

# 2. Full test suite with coverage — coverage must be >= the number before your change
pytest --cov=classes --cov=imports --cov-report=term-missing
```

**Known blind spot:** running CI locally will show the baseline tag test as PASS even when it fails
in CI, because your clone has git tags and CI's shallow checkout does not. PR-A fixes this. Until
then, do not trust a green local baseline test as proof CI is green — check the actual CI run:
`gh run list --branch <your-branch> --limit 1`.

## 4. Testing rules

- **Add a regression test for every bug you fix.** If it broke once without a test, it will again.
- **Assertions must be real.** Do not make a test pass by weakening it. Assert the *outcome*
  (a classification string, a precedence result, a graceful `([], [])` return), not merely that a
  function "ran without raising". A green-but-toothless test is worse than no test.
- **Coverage direction is up only.** Your PR's coverage number ≥ the pre-change number.
- **Mock the network.** No test may make a real DNS query or HTTP request. Patch `aiodns`,
  `requests`, `urllib3`/`urlopen`, and `dns.resolver` as the existing tests do (see
  `tests/conftest.py` and `tests/test_dns_handler.py` for the established patterns).

## 5. Scope discipline (Karpathy / surgical changes)

- Touch only what the PR plan lists. No drive-by refactors, no reformatting adjacent code, no
  "while I'm here" improvements.
- If you spot an unrelated problem, **note it in your report** — do not fix it in this PR.
- If your change orphans an import/variable/function, remove that orphan (your mess). Do not remove
  pre-existing dead code unless the plan says to.
- The DNS-only scope is firm: **do not add HTTP/HTTPS, TLS, port-scanning, or screenshot features.**
  Those belong to a separate project.

## 6. Definition of done (every PR)

1. The PR plan's success criteria are all met and independently verified (you ran the check, you saw
   it pass — quote the output in your report).
2. `ruff check .` and `ruff format --check .` clean.
3. Full `pytest` green; coverage ≥ prior.
4. `VERSION`, `version.py` bumped per the plan; the change is described for the release notes.
5. A short report: what changed, why, the commands you ran, their output, and anything you noticed
   but deliberately left out of scope.
