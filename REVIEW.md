# DNSResolver — Holistic Codebase Review

> Produced: 2026-07-15 · Reviewed at commit `a2d06fb` (v1.10.4) · Method: `codebase-holistic-review` (8 phases) + `karpathy` goal/verify framework.
> Verification bar agreed with the maintainer: measured coverage %, a clean authorised live run against a client domain, and an honest feature-vs-goals gap analysis.

## Executive summary

DNSResolver is a mature, well-structured passive DNS-reconnaissance and subdomain-takeover
tool. The architecture is clean (small single-responsibility classes, a shared async
pipeline behind both a CLI and a Lambda entry point), local tests are green (**144 passed**),
lint/format are clean (ruff), overall **line coverage is 85%**, and dependencies have **no
known CVEs** (pip-audit). For its stated DNS-only scope it substantially meets its goals.

The single most urgent problem is that **CI on `main` is red** and has been since the tooling
modernisation. The cause is not application code — it is one environment-fragile baseline test
(`test_version_tag_exists_in_git`) that asserts a git tag exists, while CI's shallow
`actions/checkout` does not fetch tags. This test **passes locally** (your clone has the tags)
and **fails in CI** (tags absent) — so running CI locally does *not* catch it, which is exactly
the env-drift blind spot the baseline suite was meant to guard against. Fixing this unblocks the
10 stalled dependabot PRs, all of which inherit the same red check.

The authorised live run (see Phase 7) surfaced a **correctness bug** that
matters for the field-ready bar: every dead (NXDOMAIN, no-CNAME) subdomain is mislabelled
`self_referential` "points to itself", because that check is trivially true at recursion depth 0 —
mislabelling real dead names and potentially masking genuine dangling candidates (RA-B3 / PF-6).

Beyond that, the highest-value work is: two reliability defects (an `sys.exit(1)` buried in the
Azure fetch fallback that can hard-kill a run; an orphaned empty `timeout` output file), a
coverage gap in `environment_manager.py` (35%, because its constructor makes a live HTTP call),
and two scalability cliffs in CSP IP matching that will bite on large scans. None are
show-stoppers for current use; all are cheap to fix and worth doing to hit the "field-ready"
bar.

**Overall health: B+.** Green the CI, close the two reliability defects, and lift the one weak
coverage module, and this is an A-grade portfolio-and-field tool within its declared scope.

---

## Phase 1 — Architecture map

**Layering.** Presentation/entry (`resolver.py` CLI, `lambda_handler.py`) → orchestration
(`run()` shared pipeline) → environment/config (`EnvironmentManager` / `LambdaEnvironmentManager`,
`ConfigResolver`, `OutputManager`) → domain logic (`DNSHandler`, `TakeoverDetector`,
`DomainCategoriser`, CSP matching) → infrastructure (`cloud_ip_ranges` fetchers,
`EvidenceCollector` subprocess capture).

**Data flow.** Domains file → `EnvironmentManager.set_domains()` (regex validation) → per-domain
`asyncio` task (Semaphore-capped) → `DNSHandler.resolve_domain_async` (aiodns primary, dnspython
fallback) → on NXDOMAIN, `TakeoverDetector` (dangling CNAME + NS takeover, depth-limited chain
follow) → resolved IPs matched against fetched AWS/GCP/Azure ranges → results written to 4 text
files + 1 JSON under a timestamped directory.

| Module / Path | Responsibility | Concerns |
|---|---|---|
| `resolver.py` | CLI entry; builds `EnvironmentManager`, runs pipeline | Thin, fine |
| `lambda_handler.py` | Lambda entry (S3 in/out) | Couples repo to `boto3`; scope decision (see RA-E) |
| `classes/environment_manager.py` | CLI env: argparse glue, logging, domain I/O, external-IP probe | **Constructor does live HTTP** to ifconfig.io → untestable, 35% cov |
| `classes/lambda_environment_manager.py` | Lambda env: env vars, stdout logging, `/tmp` I/O | 98% cov, fine |
| `classes/config_resolver.py` | Parse CLI args, merge config.json | `sys.exit(1)` on bad args (acceptable at entry) |
| `classes/output_manager.py` | Build output dir tree, async writes | Creates an **orphan `timeout` file** never written (RA-B2) |
| `classes/dns_handler.py` | Async resolution, dnspython second opinion | A-record only (AAAA-only hosts read as unresolved — known limitation) |
| `classes/takeover_detector.py` | Dangling CNAME, NS takeover, self-ref detection | Core logic; well covered (97%) |
| `classes/domain_categoriser.py` | Regex classification of CNAME targets | First-match-wins → pattern order matters (document it) |
| `classes/domain_processing_context.py` | Per-domain state | Clean value object |
| `classes/csp_ip_addresses.py` | Holds fetched CSP ranges | Clean value object |
| `imports/cloud_ip_ranges.py` | Fetch/parse AWS/GCP/Azure ranges | **`sys.exit(1)` in Azure fetch** (RA-B1); Azure 3-stage fallback good |
| `imports/cloud_service_provider_checks.py` | Match resolved IPs to CSP ranges | **O(n²) dedupe + per-IP CIDR rebuild** (RA-C) |
| `imports/domain_processor.py` | Per-domain orchestration | Clean |

No module has a genuinely muddled responsibility. `environment_manager.py` is the only one
mixing concerns that hurt (network probe inside construction).

---

## Phase 2 — Risk inventory

| # | Category | Finding | Score | Location |
|---|---|---|---|---|
| 1 | Reliability | **CI red on main**: baseline tag test fails in tagless shallow checkout; passes locally so shift-left misses it | 5 | `tests/baseline/test_baseline.py:52`, `.github/workflows/ci.yml:16` |
| 2 | Reliability | `sys.exit(1)` on `RequestException` inside Azure fetch — can hard-kill a whole run even from the "resilient" fallback path | 4 | `imports/cloud_ip_ranges.py:48` |
| 3 | Maintainability | Orphan `timeout` output file created every run, never written (leftover from #82 consolidation); contradicts README's 4-file story | 2 | `classes/output_manager.py:26` |
| 4 | Maintainability | `environment_manager.py` 35% coverage — constructor makes live HTTP call to ifconfig.io, so it can't be unit-tested without a network | 3 | `classes/environment_manager.py:116` |
| 5 | Scalability | CSP matching rebuilds `ipaddress.ip_network(range)` for every resolved IP × every prefix (AWS ~7k, Azure ~60k prefixes) | 4 | `imports/cloud_service_provider_checks.py:68` |
| 6 | Scalability | `log_and_write` reads the entire CSP file on every write to dedupe (O(n²)); also a substring match that can false-dedupe | 3 | `imports/cloud_service_provider_checks.py:88` |
| 7 | Reliability | Blocking `open()`/file read inside the async event loop (CSP writes) while the rest uses `aiofiles` — inconsistent, can stall the loop | 2 | `imports/cloud_service_provider_checks.py:93` |
| 8 | Dependency | Test tooling (`pytest`, `pytest-asyncio`, `pytest-cov`) lives in runtime `requirements.txt`; mixed pin styles (`aiodns~=` vs `>=`) | 2 | `requirements.txt` |
| 9 | CI/CD | CI does not pin `ruff` — a new ruff release can turn `main` red with no code change | 3 | `.github/workflows/ci.yml:28`, `requirements-dev.txt` |
| 10 | Maintainability | 10 open dependabot PRs + 1 feature branch, all blocked behind the red check; 6 stale non-dependabot branches | 2 | GitHub |
| 11 | Scope | Lambda deployment (handler, `requirements-lambda.txt`, `ecr-build.yml`, ~160 lines of README) lives here, but is produced elsewhere | 2 | repo-wide |
| 12 | **Correctness** | **Self-referential misclassification** — any fully-unresolvable (NXDOMAIN, no CNAME) domain is labelled `self_referential` "points to itself", because the `current == original` check is trivially true at recursion depth 0. **Found by the live run** (9/9 dead hosts mislabelled) | 4 | `classes/takeover_detector.py:139` |

---

## Phase 3 — Predicted failure scenarios (score ≥ 3)

### PF-1: CI stays red, PRs pile up (Reliability, 5)
**What happens:** Every push and PR shows a failing "test" check; branch protection blocks merges;
dependabot PRs accumulate unmerged.
**Trigger:** Already occurring on every run since the tooling change.
**Timeline:** Now.
**Minimum fix:** Make the tag test tolerant of a tagless checkout **and** have CI fetch tags
(`fetch-depth: 0`). See RA-A1.

### PF-2: A run aborts mid-scan because Azure had a blip (Reliability, 4)
**What happens:** During a large authorised scan, `requests.get` to the Azure JSON raises
`RequestException`; `fetch_ip_ranges_for_azure` calls `sys.exit(1)`; the **entire process dies**,
discarding all resolution/takeover results gathered so far.
**Trigger:** Any transient network failure to the Azure download host — including from inside the
pinned-URL fallback that exists specifically to survive Azure being unreachable.
**Timeline:** Intermittent; more likely on long runs / flaky networks.
**Minimum fix:** Return `([], [])` and let the caller skip Azure, matching the AWS/GCP path. RA-B1.

### PF-3: Large scan slows to a crawl on CSP matching (Scalability, 4)
**What happens:** For a list of tens of thousands of domains, each resolved IP is tested against
every CSP prefix with a fresh `ip_network()` construction; wall-clock time balloons.
**Trigger:** Large domain lists (the tool's stated use case: "practical for large domain lists").
**Timeline:** At ~10× current typical input, or any full-org enumeration.
**Minimum fix:** Pre-build the CSP `ip_network` objects once at startup (they don't change during a
run); optionally group by prefix length. RA-C1.

### PF-4: environment_manager regressions ship silently (Maintainability, 3)
**What happens:** A change to config merging, domain validation, or output wiring breaks, but no
test catches it because the module is 35% covered and its constructor can't run offline.
**Trigger:** Any refactor of the CLI env path.
**Timeline:** On the next change to that file.
**Minimum fix:** Extract the external-IP probe behind a seam so the class is constructible without a
network, then add unit tests. RA-D1.

### PF-6: Dead subdomains mislabelled "self-referential", masking real dangling candidates (Correctness, 4)
**What happens:** A genuinely non-existent subdomain (NXDOMAIN, no CNAME) is reported as
`self_referential` with "the domain points to itself and will never resolve." The operator is told it
is a harmless misconfiguration when in fact it is a dead name that carries no CNAME at all — the
opposite of the self-referential case the label describes. Real dangling/claimable candidates can be
buried under this wrong label.
**Trigger:** Any input domain that fully fails to resolve and has no CNAME. Confirmed on the live
authorised live run: 9/9 dead hosts (verified via `dig`: no A, no CNAME) all mislabelled.
**Root cause:** `check_dangling_cname_async` is first entered with `current_domain == original_domain`
(depth 0). The self-referential branch (`current == original`) is trivially true there, so it fires for
every dead domain, not only for CNAME chains that loop back to the origin (which is the only case #89
intended).
**Timeline:** Every run containing dead subdomains — i.e. essentially every real enumeration.
**Minimum fix:** Gate the self-referential branch on `depth > 0` (we actually followed a CNAME back to
the origin). At depth 0 with no CNAME, categorise normally via `DomainCategoriser`. Add a regression
test with a NXDOMAIN-no-CNAME domain asserting the category is **not** `self_referential`, and a test
for a true looping CNAME asserting it **is**. See RA-B3.

### PF-5: Green CI turns red with no code change (CI/CD, 3)
**What happens:** A new `ruff` release adds/changes a rule; `ruff check`/`format --check` fail on
untouched code; `main` goes red.
**Trigger:** Unpinned `ruff>=0.11.0`.
**Timeline:** On the next ruff release with a rule change.
**Minimum fix:** Pin ruff to an exact version in `requirements-dev.txt` and bump deliberately. RA-A2.

---

## Phase 4 — Test coverage gaps

Current measured coverage (pytest-cov, `--cov=classes --cov=imports`): **85% overall, 144 tests
passing.** Weakest modules:

| Module | Cover | Why it matters | Test type needed |
|---|---|---|---|
| `classes/environment_manager.py` | **35%** | CLI env wiring, domain validation, config/pattern loading, env-info save | Unit: mock the HTTP probe; test `is_valid_domain` (valid/invalid/edge), `clean_domains`, `load_patterns` (missing/bad JSON), `set_domains`, `get_random_nameserver` |
| `classes/output_manager.py` | 70% | Builds the output tree every run | Unit: dir creation, file vs dir path handling, write error path |
| `imports/cloud_ip_ranges.py` | 84% | External data fetch + Azure fallback chain | Unit: mock `requests`/`urlopen`; assert **no `sys.exit`** on error (locks in RA-B1); cache hit/miss/pinned fallback |
| `classes/config_resolver.py` | 84% | Arg/config precedence | Unit: CLI overrides config; bad config file tolerated; `--resolvers` alias |

**Assertions to watch (not "wrong but green"):** the takeover tests are specific and strong (they
assert category strings and file targets) — keep that bar. When adding coverage, do **not** assert
merely that a function "runs"; assert the classification/precedence/error-handling outcome.

**Top 3 highest-value additions:**
1. `environment_manager` unit suite behind an injected/mocked IP probe (unblocks PF-4, biggest % gain).
2. `cloud_ip_ranges` error-path tests that assert graceful `([], [])` return (regression lock for RA-B1).
3. CSP-matching correctness test with a known IP in a known CSP range (guards RA-C refactor).

---

## Phase 5 — Dependency audit

- **CVEs:** `pip-audit -r requirements.txt` → **No known vulnerabilities.**
- **Freshness:** All core deps current (dnspython 2.8, aiodns 4.0.4, requests 2.34, urllib3 2.7).
- **Pinning:** Mixed — `aiodns~=4.0.3` (compatible-release) vs `>=` elsewhere; `ruff` unpinned in CI
  (RA-A2). Recommend consistent lower-bound `>=` for libraries, exact pin for the lint toolchain.
- **Layout smell:** test tooling in runtime `requirements.txt` (RA-B / hygiene). Split runtime vs
  test/dev cleanly: runtime → `requirements.txt`; test+lint → `requirements-dev.txt`.

---

## Phase 6 — CI/CD gap analysis

| Check | Present? | Note |
|---|---|---|
| Tests run on every PR | ✅ | `ci.yml` on push+PR+weekly schedule |
| Lint + format check | ✅ | ruff check + ruff format --check |
| Secret scanning | ✅ | `secret-scan.yml` (gitleaks) + `.gitleaks.toml` |
| Baseline invariants tested | ⚠️ | Present but **the tag test is env-fragile** (RA-A1) |
| Action versions pinned | ⚠️ | Actions pinned to major (`@v6`), but **`ruff` tool unpinned** (RA-A2) |
| Scheduled drift run | ✅ | Weekly cron — good; it is currently what surfaces the red baseline |
| Local pre-push CI parity | ⚠️ | `github-actions-locally` works but cannot catch the tag test (local has tags). Adopt it **and** fix the fragile test — RA-A3 |

**Fix snippet (CI tag fetch), for RA-A1:**
```yaml
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0   # fetch full history + tags so version-sync baseline can run
```

---

## Phase 7 — Feature-vs-goals gap analysis (the "how good is good enough?" answer)

**Stated goal (README):** passive, DNS-only bulk resolution + CSP attribution + dangling-CNAME and
NS-takeover detection + forensic evidence, practical for large lists. Active probing (HTTP/TLS/ports/
screenshots) is *deliberately* out of scope.

| Goal | State | Verdict |
|---|---|---|
| Bulk async DNS resolution | asyncio + Semaphore + retry loop | ✅ Met |
| Multi-IP fidelity (A records) | All A IPs captured, pipe-delimited, all fed to CSP match | ✅ Met |
| CSP attribution (AWS/GCP/Azure) | 3 providers, v4+v6, resilient Azure fetch | ✅ Met (perf caveat RA-C at scale) |
| Dangling CNAME takeover detection | Depth-limited chain follow, 60 classification patterns, self-ref handling | ✅ Met, strong |
| NS takeover detection | Unresolvable-NS check | ✅ Met |
| Forensic evidence | Async dig/nslookup capture | ✅ Met (CLI only, by design) |
| Actionable output | Consolidated 4 files + prioritised run summary | ✅ Met |
| "Practical for large lists" | True functionally; **perf cliff at scale** (RA-C) | ⚠️ Partial |
| Robustness under failure | Good, except **Azure `sys.exit`** (RA-B1) | ⚠️ One defect |

**Live-run verification (authorised client domain, 2026-07-15).** A 15-host run completed cleanly
end-to-end: no crash, correct concurrency/retry behaviour, the prioritised run summary and the 4-file
output all produced. This confirms the happy path and the operator-facing UX work as advertised. It
also **found a real bug**: all 9 non-resolving hosts were mislabelled `self_referential` (verified by
`dig`: they have no A and no CNAME — they are simply NXDOMAIN). That is RA-B3 / PF-6. The live run
doing its job and catching a classification defect is precisely why the maintainer set it as a
verification criterion.

**Honest gaps against the "field-ready" bar:**
1. **Self-referential misclassification** (RA-B3) — the field-run bug above; highest correctness impact.
2. **Perf at true scale** (RA-C) — the one place the "large lists" claim is fragile.
3. **Azure `sys.exit`** (RA-B1) — a single upstream blip can lose a whole run's results.
4. **AAAA-only hosts** read as unresolved (A-record-only resolution). Low priority for red-team use
   per maintainer, but should be **documented as a known limitation**, not left implicit.
5. **No confirmation of exploitability** — by design (that's the separate active-probing project).
   README should say so explicitly so users know where the boundary is and where to go next.

**Bottom line:** within its declared scope, the tool **meaningfully meets its original goals.** It is
not "unfinished." The remaining work is hardening and polish to clear the field-ready bar — not new
core capability. **"Good enough" for field-ready = CI green (PR-A) + the RA-B correctness/reliability
fixes (especially B3, the self-referential bug the live run caught) + the RA-D coverage lift.** Anything
past that (RA-C perf, RA-F features) is genuine improvement, not a gap between promise and delivery.

---

## Phase 8 — Action roadmap

Action items are grouped into **bundled PRs of similar nature** (per devops-practices: group related
changes into one point release). Full per-PR execution plans — written for a less-capable agent to
run independently — live in [`docs/roadmap/`](docs/roadmap/). Model tier per group is assigned via
`model-selection-framework` and justified in [`ROADMAP.md`](ROADMAP.md).

See [`ROADMAP.md`](ROADMAP.md) for the ordered, bundled roadmap with priorities, model tiers, and
release grouping. Summary of groups:

- **PR-A — CI reliability (CRITICAL):** fix the fragile tag baseline test + CI tag fetch; pin ruff;
  adopt local-CI habit. Greens `main`, unblocks everything.
- **PR-B — Reliability & correctness (HIGH):** fix self-referential misclassification (RA-B3, found by
  the live run); remove Azure `sys.exit`; remove orphan `timeout` file.
- **PR-C — Scalability (MEDIUM):** pre-build CSP networks; fix O(n²) dedupe.
- **PR-D — Coverage lift (HIGH):** make `environment_manager` testable + add unit suites; lift 85%→≥90%.
- **PR-E — Lambda/scope cleanup (MEDIUM):** move Lambda deploy docs to `docs/LAMBDA.md`; document the
  active-probing boundary and the companion project.
- **PR-F — New DNS features (MEDIUM):** wildcard-DNS detection; record AAAA resolutions; extra
  takeover signatures — all within the DNS-only boundary.
- **PR-G — Docs & release polish (LOW):** README roadmap → link ROADMAP.md; crt.sh helper; limitation notes.
- **PR-H — Dependency batch (LOW):** merge the 10 dependabot PRs once CI is green; prune stale branches.
