# PR-A — CI reliability (CRITICAL)

**Model:** Sonnet · **Release:** v1.10.5 (patch) · **Read [`AGENT-GUIDE.md`](AGENT-GUIDE.md) first.**

## Why this exists (context)

CI on `main` is **red** and has been since the ruff/tooling modernisation. The failure is *not*
application code. The baseline test `tests/baseline/test_baseline.py::test_version_tag_exists_in_git`
reads `VERSION` (e.g. `1.10.4`), computes the expected tag `v1.10.4`, and asserts that
`git tag -l v1.10.4` prints it. In CI this **always fails**, because the workflow checks out with
`actions/checkout@v6` at default depth, which does **not** fetch git tags. So `git tag -l` returns
empty and the assertion fails.

It passes on your laptop because your clone has the tags — which is exactly why running CI locally
does not catch it. All 10 open dependabot PRs inherit this red check and cannot merge.

There is also a deeper design flaw: even with tags fetched, this test can never pass on the *commit
that bumps the version*, because the `vX.Y.Z` tag is created **after** that commit is pushed. So the
test must tolerate "tag not yet created" without failing the build.

Separately, CI installs `ruff>=0.11.0` unpinned. A future ruff release can add a lint/format rule and
turn `main` red with zero code changes.

## Tasks

### A1 — Make the tag baseline test CI-robust, and fetch tags in CI

**Two coordinated changes:**

1. `.github/workflows/ci.yml` — make the checkout fetch full history + tags:
   ```yaml
         - uses: actions/checkout@v6
           with:
             fetch-depth: 0
   ```
   (Add the `with:` block to the existing checkout step. `fetch-depth: 0` fetches all history and
   tags. Do not change the action version.)

2. `tests/baseline/test_baseline.py::test_version_tag_exists_in_git` — make it **tolerant**: if the
   repo has **no tags at all** (shallow checkout that somehow still lacks them, or a fresh repo before
   the first release), the invariant it guards (VERSION matches the *latest* tag) cannot be evaluated,
   so it must **skip**, not fail. And it should check the VERSION tag against the set of existing tags
   rather than requiring the exact current tag to already exist (which is false on the bump commit).

   Replace the test body so it:
   - Gets all tags: `git -C REPO_ROOT tag -l 'v*'`.
   - If there are **zero** tags → `pytest.skip("no git tags present (shallow checkout or pre-release)")`.
   - If tags exist → assert that either the expected `vX.Y.Z` tag is present **or** `VERSION` is
     strictly greater than the highest existing tag (meaning: this is an unreleased bump, which is
     allowed). Use a simple tuple-of-ints semver comparison; do not add a new dependency.

   Add `import pytest` at the top of the file.

**Success criteria:**
- `pytest tests/baseline/ -v` passes locally (all 4 baseline tests green).
- Simulate CI's tagless state and confirm the test **skips** rather than fails:
  ```bash
  git clone --depth 1 file://$PWD /tmp/dnsr-shallow && cd /tmp/dnsr-shallow
  python -m venv .venv && source .venv/bin/activate && pip install -r requirements-dev.txt
  pytest tests/baseline/test_baseline.py -v   # tag test must SKIP, others pass
  ```
- After pushing the branch, the actual CI run is green: `gh run list --branch <branch> --limit 1`.

**Files to change:** `.github/workflows/ci.yml`, `tests/baseline/test_baseline.py`.
**Effort:** S.

### A2 — Pin ruff

In `requirements-dev.txt`, change `ruff>=0.11.0` to an exact pin at the currently-installed version
(check with `ruff --version`; today that is `0.15.21`) → `ruff==0.15.21`. This makes lint/format
parity deterministic between laptop and CI. Leave a comment: `# pinned exact — bump deliberately, not via range`.

**Success criteria:** `ruff --version` matches the pin; `ruff check .` and `ruff format --check .`
still pass; CI's `github-actions-locally` toolchain check now reports ruff parity as *verified*
instead of "CI does not pin it".
**Files to change:** `requirements-dev.txt`.
**Effort:** XS.

### A3 — Document the local-CI habit

Add a short "Before you push" section to a new `CONTRIBUTING.md` (or the README Contributing section
if you prefer one file) instructing contributors to run the local CI parity command **and** to check
the actual CI run, noting the tag-test blind spot that A1 fixes. Cross-link `docs/roadmap/AGENT-GUIDE.md`.

**Success criteria:** the doc exists, renders, and names the exact command from AGENT-GUIDE §3.
**Files to change:** `CONTRIBUTING.md` (new) and/or `README.md`.
**Effort:** XS.

## Release

Bump `VERSION` and `version.py` to `1.10.5`. After merge, tag `v1.10.5` and cut the release (see
`github-release-workflow`). This PR is the prerequisite for PR-H (dependency batch).
