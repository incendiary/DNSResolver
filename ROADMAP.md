# DNSResolver — Roadmap

Single source of truth for planned work.

## Goal-aligned roadmap — agreed August 2026

This section supersedes the priority claims in the historical roadmap below. The
older material remains as delivery history, but it was largely derived from a
review performed against the wrong product goal.

### Confirmed goal

DNSResolver is the DNS-only front end for a separate cloud-address reclaim
allocator. Cloud IP candidates are the primary product; dangling CNAME and NS
findings are secondary observations. AWS, GCP, and Azure are required providers.
The tool retains complete DNS observations, excludes wildcard, uncertain, and
incomplete results from actionable output, and fails closed. It must work
correctly before it is optimised. Lambda expansion is shelved.

### Delivery sequence

Each item is one independently verifiable PR. Branch from current `main`, run the
exact local CI workflow, validate resolver changes against real DNS/provider data,
then confirm GitHub jobs `test`, `gitleaks`, and `trufflehog` before squash merge.

| # | Work item | State | Done when |
|---|---|---|---|
| 1 | Scope secret scans to changed commits | Merged, PR 160 | New-branch push and PR scans use a valid merge-base range; all actions are SHA-pinned; both event paths pass. |
| 2 | Define the resolver-to-allocator contract | Merged, PR 159 | Schemas, examples, fail-closed invariants, current AWS consumer compatibility, and documentation drift tests pass. |
| 3 | Make DNS resolution reliable | Merged, PR 161 | Timeouts/nameservers reach both resolver libraries; A and AAAA fallback results survive; final retry state is correct; public dual-stack, IPv6-only, and negative controls behave correctly. |
| 4 | Fail closed on incomplete provider catalogues | Merged, PR 163 | AWS/GCP/Azure use bounded retries, validation, provenance, freshness-limited integrity-checked snapshots, and explicit states; no DNS processing occurs with an unusable provider. |
| 5 | Publish the versioned allocator target document | Merged, PR 164 | A successful run atomically publishes schema-valid provider-aware JSON, groups repeated metadata, excludes wildcard observations, and retains the legacy pipe output. |
| 6 | Pin Lambda input to the triggering object version | Merged, PR 165 | The reference handler reads the exact S3 object version from the event and rejects incomplete version information. This does not reopen Lambda expansion. |
| 7 | Preserve every provider attribution | Merged, PR 169 | Duplicate services, overlapping prefixes, identical CIDRs across providers, and multiple provider-published regions survive catalogue parsing, matching, pipe output, and JSON publication without changing the schema. Legacy scalar cache snapshots remain readable. |
| 8 | Replace linear cloud-range matching with an indexed matcher | Deferred until measured need | A deterministic benchmark is defined before implementation; outputs are byte-for-byte equivalent to item 7; measured runtime and memory are reported at representative scale. |
| 9 | Fail explicitly on required output errors | Merged, PR 170 | Required writes cannot be swallowed; partial runs cannot leave a stale actionable document; injected open/write/replace failures produce a nonzero, explicit failure with regression tests. |
| 10 | Publish observations and the run manifest | Implemented on `feat/publish-run-contracts`; PR pending | The checked observation and manifest contracts are emitted by real runs; manifest state reflects provider completeness and publication outcome; actionable output is null for incomplete/failed runs. |
| 11 | Validate the real allocator consumer end to end | Planned, cross-repository | The AWS consumer ingests a current DNSResolver document unchanged; GCP/Azure route only to provider-aware implementations or are explicitly rejected; a synthetic authorized fixture proves no provider is misrouted. |
| 12 | Measure and calibrate large-run behavior | Planned last | A repeatable representative benchmark replaces the unmeasured README scalability claim; resource limits and operational guidance reflect measured results. |

### Explicitly not doing

- No cloud allocation or reclaim API calls in DNSResolver.
- No HTTP probing, TLS inspection, screenshots, or active takeover confirmation.
- No Lambda expansion, deployment machinery, release, tag, or version bump in an
  individual work-item PR.
- No matcher-performance refactor inside attribution item 7; correctness is frozen
  first so optimisation has a trustworthy equivalence oracle.
- No standalone security-hardening phase is planned here. Items 9-10 are
  operational reliability improvements; item 8 is a performance change that
  remains deferred until measured need.
- No claim that unit coverage proves resolver behavior; real DNS, real provider
  catalogues, consumer validation, and actual merge CI remain separate gates.

### Delivery state — 2026-08-14

Items 7 and 9 were squash-merged in PRs 169 and 170. Item 10 is implemented on
`feat/publish-run-contracts` and ready for its focused pull request.

- Focused suite: 91 tests passed.
- Full local CI: Ruff and format passed; baseline 5 passed; full suite 310 passed
  at 95% coverage for `classes` and `imports`.
- Live catalogues: 4,826 AWS prefixes and 44,225 Azure prefixes have multiple
  attributions; Azure has 44,101 prefixes with multiple published regions.
- Live end-to-end synthetic-address acceptance used current provider catalogues:
  AWS preserved `AMAZON`, `EC2`, and `S3`; Azure preserved `global` and
  `southeastasia` as separate schema-valid targets.
- A production run through the host system resolver processed `s3.amazonaws.com`
  and `aws.amazon.com` using current AWS, GCP, and Azure catalogues. It emitted 43
  pipe attributions and 20 schema-valid allocator targets; one current S3 address
  retained `AMAZON`, `EC2`, and `S3`. Direct public-resolver transport and the real
  allocator consumer remain external acceptance gates.
- Before delivery: review the diff, run TruffleHog v3.96.0 on the intended commit
  range, commit, push, open one focused PR, and verify push, PR, and post-merge
  `main` checks.
- The live gate may be delegated using `docs/EXTERNAL-ACCEPTANCE.md`; its report
  must keep automated, catalogue, system-resolver, public-resolver, and allocator
  evidence separate.
- Item 9 focused suite: 55 tests passed. Full local CI: 315 tests passed at 95%
  coverage for `classes` and `imports`; Ruff and formatting passed. A production
  system-resolver run fetched all three current catalogues, resolved both public
  inputs, emitted 45 attribution records, and published 20 schema-valid targets
  without leaving a temporary allocator document.
- Item 10 focused suite: 32 tests passed. Full local CI: 320 tests passed at 95%
  coverage for `classes` and `imports`. A production system-resolver run published
  20 actionable targets, an empty but schema-valid observation document, and a
  schema-valid complete manifest referencing both documents; no temporary run
  document remained. A reserved `example.com` negative control separately
  published one schema-valid unresolved observation, an empty actionable array,
  and a complete manifest.

> **On its derivation.** The plan below came from [`REVIEW.md`](REVIEW.md) (2026-07-15), which
> assessed the tool against a misread goal — cloud attribution treated as a supporting attribute
> rather than as one of two co-equal products. That review now carries a correction, and the work
> recorded under "Since v1.12.0" came from the reframing rather than from this plan. Read
> [`AGENTS.md`](AGENTS.md) for what the tool is actually for before planning further work.

Derived from [`REVIEW.md`](REVIEW.md) (holistic review, 2026-07-15). Items are bundled into **atomic point-release PRs of similar nature** (per
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
- [x] **PR-F: New DNS features** — plan: [`docs/roadmap/PR-F-dns-features.md`](docs/roadmap/PR-F-dns-features.md) — *complete*
  - [x] F1: Wildcard-DNS detection — per-zone cached probes, `WILDCARD|` prefix, counted in the summary. Verified live against `github.io`. A live test caught that A-only probing missed dual-stack catch-alls; probes now cover A and AAAA
  - [x] F2: Record AAAA (IPv6) resolutions — concurrent A+AAAA query; unresolved only when **both** fail. **Verified on live DNS:** `ipv6.google.com` (AAAA-only) previously reported unresolved, now resolves to 4 IPv6 addresses; dual-stack hosts capture both families
  - [x] F3: 30 fingerprints added (60 → 90), plus the pattern set's first tests

### 🟢 LOW
- [x] **PR-G: Docs & release polish** — plan: [`docs/roadmap/PR-G-docs.md`](docs/roadmap/PR-G-docs.md) — *complete*
  - [x] G1: README roadmap table replaced with a link to this file
  - [x] G2: `helper/crtsh_domains.sh` added — retries, fails loudly, filters to valid hostnames
  - [x] G3: Known limitations section added to the README
- [x] **PR-H: Dependency batch** — plan: [`docs/roadmap/PR-H-dependencies.md`](docs/roadmap/PR-H-dependencies.md) — *complete*
  - [x] **Root cause found and fixed:** branch protection required status checks named `CI` and `Secret Scan` (the *workflow* names). GitHub reports *job* names (`test`, `gitleaks`, `trufflehog`), so those contexts could never appear and **every** PR was permanently BLOCKED — the real reason the backlog accumulated. Contexts corrected.
  - [x] PR 116 (`aws-actions/configure-aws-credentials`) closed as moot — its only consumer, `ecr-build.yml`, was removed by E3
  - [x] H1: All dependency PRs merged. Two needed recreating — their branches were pinned to a base predating the CI fix, so `update-branch` could not move them
  - [x] H2: No stale branches remained to prune; every remaining branch backs an open PR
  - [x] H2: No pruning needed — the stale branches listed here (`change_threading`, `oopify`, `pylint_pep8`, `media`, `add-claude-github-actions-*`) were already gone. Every remaining branch backs an open PR

---

## Shipped (v1.0 – v1.10.4)

The full historical changelog lives in the README roadmap table and GitHub Releases. Highlights:
v1.10.0 output consolidation, v1.10.1 actionable run summary, v1.10.2 version string, v1.10.3
self-referential CNAME classification, v1.10.4 README corrections, plus the tooling modernisation
(ruff, dependabot, secret scan, ECR build) at `a2d06fb`.

---

## Outstanding

Every item above has shipped. What remains is not roadmap work:

- ~~**PR 104 — CNAME chain depth tracking.**~~ Merged. Rebased against the reframing work with only
  a trivial conflict; the chain tracking coexists with the `depth > 0` self-referential gating and
  the CNAME-required rule.
- **Performance at true scale is unmeasured.** PR-C removed the known cliffs (per-IP CIDR parsing,
  O(n²) dedupe) but no benchmark has been run against a 10k+ domain list. The improvement is
  reasoned, not demonstrated.
- **Wildcard detection is DNS-only by design.** It cannot separate a real host from a catch-all when
  the host genuinely shares the wildcard's addresses. Resolving that needs active probing, which is
  deliberately out of scope for this tool.


---

## Since v1.12.0

Work that came from correcting the tool's stated purpose rather than from the plan above. All
merged; none of it was foreseen by the original review, because the review measured the wrong thing.

| PR | Change |
|---|---|
| 149 | `AGENTS.md` — states the actual purpose at repo root, so the next reader does not have to infer it |
| 150 | Cloud region and service captured from all three providers; `csp_matches` becomes structured handoff records |
| 151 | Wildcard answers kept out of cloud target counts; AWS `network_border_group` captured |
| 104 | CNAME chain depth and hop path in dangling output |
| 152 | README and `REVIEW.md` reframed — both purposes stated as co-equal, the review's premise corrected in place |
| 153 | Wildcard reported as two verdicts: confirmed catch-all versus catch-all zone |

The through-line: the cloud-matching path is one of the tool's two products and had never been
assessed as such. It was discarding every field that made a match actionable, counting hosting
platform addresses as targets, and reporting a wildcard test that silently missed rotating pools.

## Outstanding

Nothing blocking. Two items are genuinely open:

- [ ] **Performance at scale is unmeasured.** The known cliffs were removed (per-IP CIDR parsing,
      O(n²) dedupe) but no benchmark has been run against a 10k+ domain list. The improvement is
      reasoned, not demonstrated — and "practical for large domain lists" is a claim in the README.
- [ ] **The downstream consumer needs updating.** Output contracts changed materially:
      `csp_matches_*.txt` went from prose to seven structured fields, `resolution_results_*.txt` and
      `csp_matches_*.txt` gained a `WILDCARD_ZONE|` prefix, and `takeover_candidates_*.txt` gained
      hop count and chain path. Anything parsing the old formats will break. Outside this repo, but
      a real dependency of the work above.

## Shipped (v1.0 – v1.12.0)

See GitHub Releases for the full history. Highlights: consolidated output files, an actionable
end-of-run summary, correct handling of self-referential and non-existent CNAMEs, IPv6 (AAAA)
resolution, wildcard DNS detection, and 90 takeover fingerprints.
