# DNSResolver — Roadmap

Single source of truth for planned work. Derived from [`REVIEW.md`](REVIEW.md) (holistic review,
2026-07-15). Items are bundled into **atomic point-release PRs of similar nature** (per
devops-practices). Each group has a detailed, self-contained execution plan under
[`docs/roadmap/`](docs/roadmap/) written so a less-capable agent can run it independently.

**Working rules for anyone (human or agent) picking up an item:**
- Follow [`docs/roadmap/AGENT-GUIDE.md`](docs/roadmap/AGENT-GUIDE.md) **first** — it encodes the
  devops-practices standards (branch naming, conventional commits, squash merge, run CI locally
  before pushing, coverage only goes up, add a regression test for every bug).
- One logical change per PR. Bundle only same-nature changes listed in the same group.
- Green CI is a merge gate. Run `bash ~/.claude/skills/local-ci/local-ci.sh --workflow ci.yml` before
  every push (a fail-closed `pre-push` hook enforces this; the `pre-commit` slot chains gitleaks + ruff).

---

## Model tier per group (via model-selection-framework)

The framework decides on **verifiability** (can a gate prove correctness cheaply?) and **blast
radius** (how wide/destructive is the change?). Justifications below.

| Group | Nature | Verifiability | Blast radius | **Model** | Why |
|---|---|---|---|---|---|
| PR-A | CI YAML + test-logic fix | High (CI itself is the gate) but the bug is env-drift a green local run hides | Medium (touches CI + a baseline test all PRs depend on) | **Sonnet** | Needs judgment about *why* it's green locally / red in CI; mechanical enough for Sonnet, too subtle for Haiku |
| PR-B | Reliability + correctness defects | High for B1/B2; **B3 lower** (subtle recursion/classification) | Medium (control flow + classification logic) | **Sonnet (B1/B2); escalate B3 to Opus if loop-detection grows** | B3 is "wrong but green" sensitive — assert real categories, not just "ran" |
| PR-C | Performance refactor | Medium (correctness gate-able, perf harder) | Medium (touches hot path, must not change match results) | **Sonnet** | "Wrong but green" risk if a match is silently dropped — needs care, not a weak model |
| PR-D | Test coverage | High (coverage % + tests are the gate) — **but** "wrong but green" (toothless assertions) is the classic weak-model failure here | Small (additive tests; one small seam extraction) | **Sonnet writes the seam + first tests; Haiku may extend** | Extracting the network seam needs judgment (Sonnet). Once the harness exists and asserts real outcomes, mechanical test-filling is Haiku-safe (Strategy 1: strengthen the gate, then let cheap run) |
| PR-E | Docs move + scope note | High for docs move (nothing breaks); judgment for the boundary note | Medium (moves ~160 README lines; possible file relocation) | **Sonnet** | Deciding *what* is Lambda-only vs core needs understanding; wording the boundary note needs care |
| PR-F | New DNS features | **Low** (new logic; subtle correctness; wildcard/DNSSEC edge cases hard to gate) | Medium–Large (new code paths, new output semantics) | **Opus** | Worst quadrant: low verifiability + real correctness subtlety. The model is the gate |
| PR-G | Docs & release polish | High (renders/reads fine or not) | Small (additive docs, a helper script) | **Haiku** | Mechanical, isolated, cheap to review; gate = it reads correctly |
| PR-H | Dependency batch merge | High (CI is the gate, once green) | Small per PR (dep bumps), additive | **Haiku** | Fully gate-checked by CI after PR-A; mechanical merge/verify |

> Escalation rule (framework Strategy 2): if a Haiku/Sonnet task fails its gate twice or the diff
> looks wrong on review, escalate *that item* to the next tier up. Don't pre-pay for strength.

---

## Priority order & release grouping

Ship in this order. Each group is one point release (patch unless noted).

> **Versioning note (learned in execution):** do **not** bump `VERSION` per PR. Three branches each
> bumping it off the same base conflicted on every merge, and two agents "fixed" their failing
> baseline test by creating bogus tags. Version **centrally, once per batch, at release time** — which
> is what devops-practices means by "group several PRs on the same subject into one patch bump".

### 🔴 CRITICAL — do first (unblocks the repo)
- [x] **PR-A: CI reliability** → **v1.10.5** — plan: [`docs/roadmap/PR-A-ci-reliability.md`](docs/roadmap/PR-A-ci-reliability.md) — *done, branch `fix/ci-reliability`, verified against a simulated tagless CI checkout*
  - [x] A1: Make `test_version_tag_exists_in_git` tolerant of a tagless checkout; add `fetch-depth: 0` to CI checkout
  - [x] A2: Pin `ruff` to an exact version in `requirements-dev.txt`
  - [x] A3: Document "run CI locally before push" in AGENT-GUIDE + CONTRIBUTING

### 🟠 HIGH
- [x] **PR-B: Reliability & correctness** → **v1.10.6** — plan: [`docs/roadmap/PR-B-reliability.md`](docs/roadmap/PR-B-reliability.md) — *done, branch `fix/reliability-correctness`, verified on a live run*
  - [x] B3: **Fix self-referential misclassification** — dead NXDOMAIN/no-CNAME domains wrongly labelled `self_referential` (found by the live run; gated the check on `depth > 0`)
  - [x] B1: Replace `sys.exit(1)` in `fetch_ip_ranges_for_azure` with graceful `([], [])` return
  - [x] B2: Remove the orphan `timeout` output file from `OutputManager`
- [x] **B4: Don't report no-CNAME dead domains as dangling-CNAME takeover candidates** — *shipped, PR 143. Verified live: takeover candidates 9 → 0, dead hosts now reported as unresolved*
  - **Evidence:** after B3, the 9 dead hosts from the authorised live run correctly stopped being labelled `self_referential`, but they are *still* written as `DANGLING|<domain>|<domain>|unknown|Unclassified|N/A` and the run summary announces them under "TAKEOVER CANDIDATE(S) DETECTED — REVIEW IMMEDIATELY", rendering each domain as its own `CNAME target`. `dig +short @8.8.8.8 <host> A` and `... CNAME` return **nothing** for all of them — they have no CNAME at all.
  - **Why it matters:** a name that doesn't exist and has no CNAME is not a takeover candidate — there is nothing dangling to claim. `check_dangling_cname_async` writes a DANGLING record for *any* domain lacking A/AAAA/MX/NS, whether or not a CNAME exists. This inflates the candidate list with noise and buries real findings — a false-positive problem for a field tool.
  - **Fix direction:** only record a DANGLING candidate when an actual CNAME was observed. A bare NXDOMAIN with no CNAME should be reported as non-existent/unresolved, not as a takeover candidate. Also stop the summary presenting a domain as its own "CNAME target".
  - **Regression test:** NXDOMAIN + no CNAME → **not** in takeover candidates; real dangling CNAME → still flagged.
- [x] **PR-D: Coverage lift** → **v1.11.0** — plan: [`docs/roadmap/PR-D-coverage.md`](docs/roadmap/PR-D-coverage.md) — *done, branch `test/coverage-lift`*
  - [x] D1: Extract the external-IP probe behind a `fetch_external_ip()` seam; unit-test `EnvironmentManager` (35% → **86%**)
  - [x] D2: Add `cloud_ip_ranges` error-path tests; `output_manager` (**100%**) + `config_resolver` (**91%**) edges
  - [x] Target met: overall coverage **94%** (was 85%), 174 tests

### 🟡 MEDIUM
- [x] **PR-C: Scalability** → plan: [`docs/roadmap/PR-C-scalability.md`](docs/roadmap/PR-C-scalability.md) — *done, branch `perf/csp-matching`*
  - [x] C1: Memoised `parse_network()` (`lru_cache`) — each CIDR parsed once per run, not per IP
  - [x] C2: Whole-file-read dedupe replaced with a run-scoped in-memory set on `env_manager`; also fixes the substring false-dedupe and removes a blocking read from the async path
- [x] **PR-E: Lambda/scope cleanup** → plan: [`docs/roadmap/PR-E-scope-cleanup.md`](docs/roadmap/PR-E-scope-cleanup.md) — *done, branch `docs/scope-cleanup`*
  - [x] E1: Lambda walkthrough moved README → `docs/LAMBDA.md` (README 406 → 232 lines, content byte-identical)
  - [x] E2: Scope-boundary note added — **no URL/placeholder** (no companion project exists yet)
  - [x] E3: **Resolved** — maintainer chose the middle path: deployment machinery (`Dockerfile`, `ecr-build.yml`) removed in PR 142; `lambda_handler.py` and its tests kept as a reference entry point. Coverage and test count unaffected.
- [ ] **PR-F: New DNS features** — plan: [`docs/roadmap/PR-F-dns-features.md`](docs/roadmap/PR-F-dns-features.md) — *partially done, branch `feat/dns-capabilities`*
  - [ ] F1: Wildcard-DNS detection (suppress false-positive subdomains) — **NOT STARTED**
  - [x] F2: Record AAAA (IPv6) resolutions — concurrent A+AAAA query; unresolved only when **both** fail. **Verified on live DNS:** `ipv6.google.com` (AAAA-only) previously reported unresolved, now resolves to 4 IPv6 addresses; dual-stack hosts capture both families
  - [ ] F3: Add takeover signatures beyond the 60-pattern set — **NOT STARTED**

### 🟢 LOW
- [ ] **PR-G: Docs & release polish** → folded into the next release — plan: [`docs/roadmap/PR-G-docs.md`](docs/roadmap/PR-G-docs.md)
  - [ ] G1: README `## Roadmap` → brief summary + link to this file (stop duplicating the table)
  - [ ] G2: Add the crt.sh domain-list helper as `helper/crtsh_domains.sh`
  - [ ] G3: Document the A-record-only limitation and pattern-order rule
- [ ] **PR-H: Dependency batch** — plan: [`docs/roadmap/PR-H-dependencies.md`](docs/roadmap/PR-H-dependencies.md) — *in progress*
  - [x] **Root cause found and fixed:** branch protection required status checks named `CI` and `Secret Scan` (the *workflow* names). GitHub reports *job* names (`test`, `gitleaks`, `trufflehog`), so those contexts could never appear and **every** PR was permanently BLOCKED — the real reason the backlog accumulated. Contexts corrected.
  - [x] PR 116 (`aws-actions/configure-aws-credentials`) closed as moot — its only consumer, `ecr-build.yml`, was removed by E3
  - [ ] H1: Merge the remaining dependabot PRs (batch, verify each)
  - [ ] H2: Prune the 6 stale non-dependabot remote branches (`change_threading`, `oopify`, `pylint_pep8`, `media`, `add-claude-github-actions-*`, `feature/*` if merged)

---

## Shipped (v1.0 – v1.10.4)

The full historical changelog lives in the README roadmap table and GitHub Releases. Highlights:
v1.10.0 output consolidation, v1.10.1 actionable run summary, v1.10.2 version string, v1.10.3
self-referential CNAME classification, v1.10.4 README corrections, plus the tooling modernisation
(ruff, dependabot, secret scan, ECR build) at `a2d06fb`.
