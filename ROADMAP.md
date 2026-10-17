# DNSResolver: Roadmap

Single source of truth for planned work. Written 2026-10-16 from [`REVIEW.md`](REVIEW.md) and
the maintainer decisions in it. Delivered history (the August goal-aligned plan, items 1 to 10, and
the earlier A to H plan) is in [`docs/roadmap/ARCHIVE.md`](docs/roadmap/ARCHIVE.md).

Read [`AGENTS.md`](AGENTS.md) before starting any item. It says what the tool is for and which
boundaries are firm.

## Goal

DNSResolver produces cloud-address targets (primary) and takeover observations (secondary) from a
list of domains, DNS only, with output files that are contracts. This plan does three things:
**remove what is not needed** (about 1,750 lines of code and tests, about 900 of docs, 4 runtime
dependencies), **make the structure honest** (records stay structured in memory instead of being
written as text and re-parsed), and **add a compact Markdown view** for agent and human readers.

## Decisions recorded

| ID | Decision | Date | Consequence |
|---|---|---|---|
| D-1 | Lambda is shelved: delete it | 2026-10-16 | R-04 |
| D-2 | Takeover side: harden only, do not slim | 2026-10-16 | No item shrinks `takeover_detector`, `domain_categoriser` or `config.json` patterns |
| D-3 | JSON is canonical and always published; Markdown is a rendered view, on by default; never parsed back | 2026-10-16 | R-13 |
| D-4 | Consumers are both a program (JSON) and an agent or human (Markdown) | 2026-10-16 | Markdown is sized for context windows |
| D-5 | Plan lives here; history archived | 2026-10-16 | Done |

| D-7 | `--format`: `md` (default) writes `run-report.md` in addition to the JSON documents; `json` skips the Markdown | 2026-10-16 | R-13 |
| D-8 | Lock runtime dependencies with hashes | 2026-10-16 | R-16b |
| D-9 | External-IP lookup becomes opt-in (`DNSRESOLVER_RECORD_EXTERNAL_IP` / `--record-external-ip`); configurable like every other option | 2026-10-16 | R-19 |
| D-10 | One release at the end (v3.0.0): Lambda removal is a removed entry point | 2026-10-16 | R-18 |
| D-6 | Delete `helper/find_authoritative_ns.py` (unwired, untested, known defect). The underlying idea is kept as unscheduled item I-1 | 2026-10-16 | R-05b, I-1 |
| D-12 | `NS_TAKEOVER` gains a fourth field naming the failing nameserver (`NS_TAKEOVER\|origin\|domain\|nameserver`, `-` where no nameserver is implicated); breaking for strict parsers, ships in v3.0.0 | 2026-10-16 | R-21 |
| D-13 | The shipped `config.json` default for `evidence` is `false`. The value `true` never took effect (the bug fixed in R-19a), the README documents `--evidence` as opt-in, and committed defaults stay conservative; anyone who wants it on sets `DNSRESOLVER_EVIDENCE=true` in their own `.envrc` (R-19b) or passes `--evidence` | 2026-10-17 | R-19a, R-19b |
| D-11 | Every option is settable from the environment (`DNSRESOLVER_*`), loaded by direnv from a git-ignored `.envrc`; a committed `.envrc.example` is the template. Precedence: CLI flag, then environment, then `config.json`, then built-in default | 2026-10-16 | R-19 |

There are no open decisions.

## Progress

Updated 2026-10-17. Merged to `main`; version stays 2.0.0 until R-18.

| Item | State | PR | Notes |
|---|---|---|---|
| R-01 dependency batch | Done | 203 | Eight Dependabot PRs combined |
| R-02 stale tool paths, R-03 golden test | Done | 206 | Golden fixture extended in 212 |
| R-04 remove Lambda stack | Done | 208 | Breaking; ships in v3.0.0 |
| R-05a dead code, R-05b helper | Done | 209 | I-1 keeps the idea |
| R-06 archive plan docs | Done | 210 | Also removed `get_config_file` |
| R-07, R-08, R-10 plumbing | Done | 211 | `_lines` helpers left separate (they differ) |
| R-09 records in memory | Done | 212 | Net source +27 lines, not the -200 estimated; the gain is structural |
| R-11a/b drop `requests`, `urllib3`, `aiofiles` | Done | 214 | Runtime dependencies: 7 to 3 |
| R-12 small simplifications | Done | 216 | |
| R-22 deterministic output order | Done | 217 | Pipe files now sorted |
| R-20 reorganise DNS tests | Done | 218 | 41 test bodies proven identical |
| R-21 NS_TAKEOVER nameserver field | Done | 219 | Breaking; ships in v3.0.0 |
| R-14 benchmark | Done | 220 | 10.6 ms per distinct address |
| R-15 matcher index | Done | 221 | 84.5 s to 1.32 s for about 8,000 distinct addresses; output identical |
| R-16a coverage floor, R-16b locked dependencies | Done | 222 | `pip-audit` workflow verified on GitHub |
| R-19a boolean config fix | PR open | 215 | D-13: shipped `evidence` default is `false`, so no behaviour change |
| R-19b environment variables and direnv template | Not started | | After 215 |
| R-13 Markdown report | Not started | | After R-19b |
| R-23 lock regeneration | Not started | | New; see below |
| R-17 allocator consumer, R-18 release | Not started | | Maintainer / release |

## Delivery rules for every item

1. One item, one PR, branched from current `origin/main`: `git fetch origin && git checkout -b
   <type>/<name> origin/main`. Types: `chore`, `refactor`, `feat`, `docs`, `test`, `ci`.
2. Environment (python3 on the maintainer machine is a broken shim; always be explicit):
   ```bash
   /opt/homebrew/bin/python3.12 -m venv .venv
   .venv/bin/pip install -r requirements-dev.txt -r requirements-lambda.txt
   ```
   After R-04 there is no `requirements-lambda.txt`; install `requirements-dev.txt` only.
3. Before every push, run CI locally and the full suite:
   ```bash
   bash ~/.claude/skills/ci-local/local-ci.sh --workflow ci.yml
   .venv/bin/pytest --cov=classes --cov=imports
   ```
   Both must pass. Coverage must not fall below the figure before your change. A skipped CI-only
   step is unverified, not passing.
4. Conventional commit titles, squash merge, no `VERSION` bump, **never run `git tag`**
   (`AGENTS.md` section 6). Required checks: `test`, `gitleaks`, `trufflehog`.
5. Never put real client or employer names in code, commits or docs. Use `example.com`.
6. No test performs a real DNS or HTTP request. Mock them.
7. **Delete only after grepping.** For every symbol or file you delete, run
   `grep -rn "<name>" --include='*.py' --include='*.md' --include='*.yml' --include='*.txt' .
   --exclude-dir=.venv --exclude-dir=.git` and read every hit. If a production caller exists, stop
   and report; do not delete.
8. **Stop conditions.** Stop and report (do not work around) if: the golden test (R-03) changes
   output after your edit and you cannot explain why; a step in your item fails twice; you would
   need to change an output format, a JSON schema in `contracts/`, or `VERSION`; or an instruction
   here contradicts what you find in the code.
9. Final message of every item: files changed, commands run with pass or fail, coverage before and
   after, anything skipped, anything you were unsure of.

**The standard for every item**

Every item, scheduled or idea, carries all of these, in this order, so a lesser agent can run it
cold without asking: **Tier and why**, **Depends on**, **Files**, **Context** (what is wrong and
where, with names and line references), **Steps** (numbered, exact commands or edits),
**Verify** (commands whose output proves it), **Do not** (the tempting wrong moves), **Done when**,
and **PR** (the conventional title). An item missing any of these is not ready to hand out.

## Agent rules

An executing agent **stops and reports** when:
- a gate changes output unexpectedly;
- a step fails twice;
- a contract, schema or public interface would change;
- an instruction contradicts the code.

## Model tiers

Tier is chosen on verifiability (can a gate prove it right cheaply?) and blast radius. Once R-03
exists, most refactors have a strong gate, which is why they can go to a mid-tier model.

| Tier | Use for | Models |
|---|---|---|
| T1 | Mechanical, fully specified, gate is `grep` or the existing suite | Haiku 4.5 |
| T2 | Multi-file refactors behind the golden test; new code with a written spec | Sonnet 5.5 |
| T3 | Design that sets a contract others build on; reviewing T2 output | Opus 5.5 (or the main session) |

Every T1 and T2 PR is reviewed by the main session before merge: read the diff, re-run the local
CI, and run `/ponytail:ponytail-review` on it (report findings, apply nothing without asking).

## Sequence

```
Phase 0  gates        R-01 R-02 R-03
Phase 1  deletions    R-04 R-05 R-06            (after R-03 for code; R-06 any time)
Phase 2  structure    R-07 R-08 R-09 R-10 R-11 R-12   (all after R-03; R-09 before R-13)
Phase 2b output       R-22 R-21                         (after R-09)
Phase 3  config+view  R-19 -> R-13              (R-19 after R-11a; both edit environment_manager.py)
Phase 4  scale + CI   R-14 -> R-15 (conditional), R-16
Phase 5  external     R-17 R-18
Tests    R-20             (after R-05a, R-07, R-12)
```

Items inside a phase touch different files unless noted and can run in parallel in separate
worktrees. Never run two items that both edit `resolver.py` or `cloud_service_provider_checks.py`
at once: R-07, R-09, R-12 and R-15 conflict, so run them one at a time in that order.

---

## Phase 0: Gates

### R-01 Land the dependency batch
**Status:** done 2026-10-16.
**Owner:** main session.
**Tier:** none (done by the main session).
**Depends on:** nothing.
**Files:** none (merge and close only)
**Context:** eight Dependabot PRs (202, 201, 200, 199, 198, 190, 187, 166) each bumped one
dependency. They were combined into one PR so one set of checks proved them together, including
ruff 0.17.0 (lint and format clean, no code changes needed) and the TruffleHog action pinned by
SHA (`action.yml` unchanged since v3.96.0).
**Steps:**
combined the bumps on one branch, resolved the one conflict in
`requirements-dev.txt`, ran the local CI (5 of 5 steps) and the full suite, opened PR 203, merged
it with squash, closed the eight PRs with a pointer to PR 203.
**Verify:**
`gh pr view 203 --json state` reports MERGED; `gh pr list --state open` shows none of
the eight.
Negative check: before closing, `gh pr list --state open` lists all eight Dependabot PRs; after, it lists none of them.
**Do not:** edit the TruffleHog version in archived documents (history stays as written).
**Done when:** PR 203 shows MERGED and none of the eight superseded Dependabot PRs is open.
**PR:** `chore(deps): batch dependabot updates` (PR 203, merged).

### R-02 Repair stale tool paths in docs
**Tier:** T1 (Haiku). Why: find and replace, verified by grep.
**Depends on:** nothing.
**Files:** `AGENTS.md`, `docs/roadmap/AGENT-GUIDE.md`.
**Context:** three docs cite `~/.claude/skills/local-ci/local-ci.sh`, which no longer exists; the
skill is `ci-local`. The git hooks were already repaired and verified on 2026-10-16.
**Steps:**
1. `grep -rn "skills/local-ci/" --include='*.md' . --exclude-dir=.venv --exclude-dir=.git`
2. In `AGENTS.md` and `docs/roadmap/AGENT-GUIDE.md`, replace `skills/local-ci/local-ci.sh` with
   `skills/ci-local/local-ci.sh`. Change nothing else on those lines.
3. In `docs/roadmap/AGENT-GUIDE.md` also replace the stale attribution line
   `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` with
   `(use the attribution line your harness gives you)`.
4. Re-run the grep from step 1; expect zero hits outside `docs/roadmap/ARCHIVE.md` and
   `docs/roadmap/REVIEW-2026-07.md` (history; leave those alone).
**Verify:**
`grep -rn "skills/local-ci/" --include='*.md' .` (excluding `.venv`, `.git`) shows hits only in `ROADMAP.md`, `REVIEW.md` and the two archive files, and those describe the stale path rather than cite it; local CI passes.
Negative check: reintroduce `skills/local-ci/` in `AGENTS.md`, confirm the grep reports it, then revert.
**Do not:** edit the archive files, or `ROADMAP.md`/`REVIEW.md` prose; change any wording on the touched lines beyond the path and the attribution line.
**Done when:** grep shows no live-doc hits; CI green.
**PR:** `docs: correct local-ci path`.

### R-03 Golden end-to-end characterisation test
**Tier:** T2 (Sonnet), reviewed by T3. Why: this is the gate for every later refactor, so it
must be right; the spec below makes it mid-tier work.
**Depends on:** nothing (first code item; everything after it depends on this).
**Files:** `tests/test_golden_run.py`, `tests/golden/**`. No source changes.
**Context:** nothing proves that the pipe files, JSON documents and console summary stay
consistent. Add one test that runs `resolver.run()` on fixed mocked inputs and compares every
output file byte for byte against checked-in expected files.
**Blast radius:** test-only.
**Steps:**
1. Read `tests/test_resolver.py` (the `run_environment` fixture) and `tests/conftest.py` for the
   mocking patterns. Do not invent new ones.
2. Create `tests/golden/` with `domains.txt` and `expected/`. The input must cover at least: an
   AWS A hit, a GCP hit, an Azure hit with two published regions, an IPv6-only hit, a domain in a
   confirmed `WILDCARD` zone, one in a `WILDCARD_ZONE` zone, a `DANGLING` CNAME, an `NS_TAKEOVER`,
   an unresolved name, and one address shared by two hostnames.
3. Create `tests/test_golden_run.py`: mock `aiodns`, `dns.resolver`, the three catalogue fetchers
   (return small fixed `ProviderCatalogue` objects with `status="complete"`), `fetch_external_ip`,
   `uuid.uuid4` (fixed run id and fixed wildcard labels) and the clock. Run `run()` against a
   `tmp_path` output directory.
4. Normalise only what must vary: the timestamped directory name in the pipe filenames. Compare:
   `resolution_results`, `unresolved_results`, `csp_matches`, `takeover_candidates`,
   `allocator-targets-v1.json`, `dns-observations-v1.json`, `run-manifest-v1.json`,
   `provider_catalogues.json`, and the captured console summary (`capsys`).
5. Generate the expected files once from the current code (`UPDATE_GOLDEN=1 pytest
   tests/test_golden_run.py`), then **read each expected file and confirm it is correct**, not just
   what the code produced. Commit them.
6. Prove the test works: change one character in a record format temporarily and confirm the test
   fails; revert.
**Verify:** run `PYTHONHASHSEED=0`, `1`, `7` and `99` with `UPDATE_GOLDEN` unset and confirm the test passes each time; make one deliberate record-format change, confirm the test fails, then revert; full suite and local CI pass; coverage not lower.
**Do not:** change any source file, any output format or `VERSION`; accept generated expected files without reading each one against the input; normalise away differences you cannot explain (fix the cause or stop and report); use a real DNS query or the real clock.
**Done when:** test passes; breaking a format fails it; full suite and CI green; coverage unchanged
or higher.
**PR:** `test: add golden end-to-end output test`.

---

## Phase 1: Deletions

### R-04 Remove the shelved Lambda stack (D-1)
**Breaking:** yes (a removed entry point; released as a major, D-10).
**Tier:** T1 (Haiku) with a mandatory grep sweep. Why: the deletions are mechanical and the
grep plus the golden test prove nothing live was broken.
**Depends on:** R-03.
**Files:** delete `lambda_handler.py`, `classes/lambda_environment_manager.py`,
`tests/test_lambda_handler.py`, `tests/test_lambda_environment_manager.py`, `docs/LAMBDA.md`,
`requirements-lambda.txt`. Edit `.github/workflows/ci.yml`, `README.md`, `AGENTS.md`,
`docs/roadmap/AGENT-GUIDE.md`, and `tests/baseline/test_baseline.py` only if it names Lambda files.
**Context:** the Lambda deployment idea is shelved (`AGENTS.md` section 2). Its code, tests,
documentation and the `boto3` dependency (about 746 lines) are carried and kept green for no
consumer. The shared `run()` pipeline in `resolver.py` stays; only the Lambda entry and its
environment manager go. Everything is restorable from tag `v2.0.0`.
**Steps:**
1. Run `git rm` on the six files above.
2. `grep -rn -i "lambda\|boto3" . -I --exclude-dir=.venv --exclude-dir=.git --exclude-dir=worktrees`
   and handle every remaining hit outside `docs/roadmap/ARCHIVE.md` and
   `docs/roadmap/REVIEW-2026-07.md` (history; leave alone):
   - `.github/workflows/ci.yml`: change `pip install -r requirements-dev.txt -r
     requirements-lambda.txt` to `pip install -r requirements-dev.txt`.
   - `requirements-dev.txt`: confirm nothing includes the lambda file.
   - `README.md`, `AGENTS.md` (sections 2 and 5): remove Lambda rows and the "install both
     requirements files" advice; keep a one-line note that the shared `run()` entry point remains.
   - `docs/roadmap/AGENT-GUIDE.md`: remove the same advice.
   - `tests/baseline/test_baseline.py`: remove only checks that name Lambda files.
3. Re-run the grep; only the two archive files may remain.
4. Confirm `resolver.run(env_manager)` is unchanged: `git diff origin/main -- resolver.py` is empty.
**Verify:**
in a fresh venv built from `requirements-dev.txt` only, `.venv/bin/pytest
--cov=classes --cov=imports` passes and coverage is not lower than before; the golden test (R-03)
is unchanged; `bash ~/.claude/skills/ci-local/local-ci.sh --workflow ci.yml` passes.
Negative check: restore one deleted Lambda test file, confirm the suite fails on its missing import, then delete it again.
**Do not:** touch `resolver.py`, any output format, or `VERSION`; delete history in the archive
files; remove anything the grep shows a non-Lambda caller for (stop and report instead).
**Done when:** the verification passes and the grep shows only archive hits.
**PR:** `chore!: remove the shelved Lambda entry point` (the `!` marks the breaking change).

### R-05a Delete confirmed dead code
**Tier:** T1 (Haiku). Why: each deletion is proved by a grep and the existing suite.
**Depends on:** R-03.
**Files:** `classes/wildcard_detector.py`, `classes/custom_exceptions.py`,
`classes/environment_manager.py`, and the tests that cover only the deleted symbols
(`tests/test_wildcard_detector.py`, `tests/test_custom_exceptions.py`,
`tests/test_environment_manager.py`).
**Context:** the 2026-10-16 audit found symbols with no production caller (tests only):
`WildcardDetector.is_wildcard_resolution` (superseded by `classify`), the exceptions
`FileDoesNotExistError`, `NotAnIntegerError` and `InvalidNameserversError`, and the methods
`EnvironmentManager.get_random_nameserver` and `get_config_file`. They look supported and are not.
**Steps:**
for each of the six targets:
1. Run the rule 7 grep for its name across source, tests, docs and workflows.
2. If every hit is its own definition or a test of it, delete the definition and those tests.
   If any production or documentation hit exists, leave the target and note it in your report.
3. If `tests/test_custom_exceptions.py` is left with no tests, delete the file.
4. Remove any import your deletion orphans, and nothing else.
**Verify:**
`.venv/bin/pytest --cov=classes --cov=imports` passes, collected-test count falls only
by the tests you deleted (state the numbers), coverage is not lower, golden test unchanged, local
CI passes.
Negative check: restore one deleted symbol's test without the symbol, confirm it fails, then revert.
**Do not:** delete a symbol with a production caller; "tidy" adjacent code; remove
`FileDoesNotExistError` and friends from documentation that describes behaviour still present.
**Done when:** the verification passes.
**PR:** `chore: remove unused code`.

### R-05b Delete the unreferenced helper (D-6)
**Tier:** T1 (Haiku). Why: one file, proved unused by grep.
**Depends on:** R-03.
**Files:** `helper/find_authoritative_ns.py` (delete); `README.md` only if it mentions it.
**Context:** the script walks DNS delegation by hand to print authoritative name servers. It has
no callers, no tests, is not in the README, has been unchanged since the initial release, and
assumes the registrable domain is the last two labels (wrong for `example.co.uk`). The maintainer
decided to delete it and keep the idea as unscheduled item I-1, which carries the full design.
**Steps:**
1. Run the rule 7 grep for `find_authoritative_ns` and `helper/` across the repo.
2. If the only hits are the file itself and archived history, `git rm` it.
3. Confirm `README.md` lists only `helper/crtsh_domains.sh` under the helpers.
**Verify:**
the grep finds no live references; suite and local CI pass; `ls helper` shows only
`crtsh_domains.sh`.
Negative check: restore the file from history, confirm no test or workflow fails because of its absence or presence (proves nothing depended on it), then delete it again.
**Do not:** delete `helper/crtsh_domains.sh`; port any of the script's code elsewhere (I-1 is a
fresh design, not a port).
**Done when:** the file is gone and CI is green.
**PR:** `chore: remove the unwired authoritative-NS
helper`. May be bundled with R-05a in the same PR (same type).

### R-06 Archive delivered per-PR plans
**Tier:** T1 (Haiku). Why: deletions verified by a link check; git history keeps every file.
**Depends on:** nothing (docs only; can run any time).
**Files:** delete `docs/roadmap/PR-A-ci-reliability.md` through `PR-H-dependencies.md` and
`docs/roadmap/README.md`; edit `README.md` and `HANDOVER.md` pointers only. Keep
`docs/roadmap/AGENT-GUIDE.md`, `ARCHIVE.md` and `REVIEW-2026-07.md`.
**Context:** the A to H plans (about 670 lines) describe work that was delivered long ago. They
are noise for a new agent and now partly wrong (stale paths, old model names). History retains
them.
**Steps:**
1. `git rm` the nine files named above.
2. Find references: `grep -rn "docs/roadmap/PR-\|roadmap/README" . --include='*.md'
   --exclude-dir=.venv --exclude-dir=.git`. Fix each hit outside the two archive files.
3. In `README.md` (the roadmap pointer, near the end) and `HANDOVER.md` (the lines naming
   `REVIEW.md` and `ROADMAP.md`) make sure pointers are accurate: the 2026-07 review is
   `docs/roadmap/REVIEW-2026-07.md`; the current review is `REVIEW.md`.
4. Link check: for every `](...md)` target in `README.md`, `AGENTS.md`, `HANDOVER.md`,
   `ROADMAP.md`, `REVIEW.md` and `docs/`, confirm the file exists
   (`grep -o "](\([^)]*\.md\)" file` then `ls`).
**Verify:**
the link check finds no dead links; local CI passes.
Negative check: add a deliberate dead `.md` link to `README.md`, confirm the link check reports it, then revert.
**Do not:** rewrite `HANDOVER.md` beyond pointers (its fate is a separate decision); edit the two
archive files.
**Done when:** verification passes.
**PR:** `docs: archive delivered per-PR plans`.

---

## Phase 2: Structure (all behaviour-preserving, gated by R-03)

### R-07 Replace `CSPIPAddresses` with the catalogue objects
**Tier:** T2 (Sonnet). Why: a multi-file refactor behind the golden test, with a written design.
**Depends on:** R-03.
**Files:** `resolver.py`,
`classes/csp_ip_addresses.py` (delete), `imports/cloud_service_provider_checks.py`,
`imports/domain_processor.py`, `classes/domain_processing_context.py`,
`imports/cloud_ip_ranges.py` (`ProviderCatalogue.__iter__`), affected tests.
**Context:** `ProviderCatalogue` already holds IPv4 ranges, IPv6 ranges and metadata.
`resolver.py` unpacks three catalogues into six lists to repack them into `CSPIPAddresses`, which
`get_vendor_ips` then re-expands into dicts.
**Steps:**
1. Write a one-paragraph design in the PR description: the matcher receives
   `catalogues: dict[str, ProviderCatalogue]`; `describe(provider, cidr)` becomes a function that
   reads `catalogues[provider].metadata.get(cidr)` with the same `[("unknown",)*3]` default.
2. Change `perform_csp_checks`, `get_vendor_ips`, `merge_matches` to loop over the dict (IPv4 and
   IPv6 ranges are `catalogue.ipv4_ranges` / `ipv6_ranges`). Keep iteration order `gcp, aws, azure`
   so output order is unchanged.
3. Remove `ProviderCatalogue.__iter__`, the unpack block in `run()` and the six `extreme` getter
   logs (replace with one loop over the dict logging the same text).
4. Delete `classes/csp_ip_addresses.py` and `tests/test_csp_ip_addresses.py`; port any assertion
   that tested real behaviour (the `unknown` default) into the matcher tests.
**Verify:**
R-03 golden test unchanged, byte for byte. Suite and CI green; coverage not lower.
Negative check: swap the provider iteration order in the matcher, confirm the golden test fails, then revert.
**Do not:** change output text, the order of records, or any contract.
**Done when:** verification passes and `classes/csp_ip_addresses.py` no longer exists.
**PR:** `refactor: match against provider catalogues directly`.

### R-08 One home for atomic output helpers
**Tier:** T1 (Haiku). Why: moves identical code; the golden test proves no output changed.
**Depends on:** R-03.
**Files:** `classes/run_contract.py`, `classes/allocator_contract.py`,
`resolver.py`, `imports/cloud_ip_ranges.py`.
**Context:** `_remove_output`, the atomic JSON write, `_lines` and `CONTRACT_VERSION` are each
defined in both contract modules, and `_timestamp` in `resolver.py` and
`imports/cloud_ip_ranges.py`. Four copies of the same safety logic drift apart.
**Steps:**
1. In `classes/allocator_contract.py`, `from classes.run_contract import _remove_output,
   _write_json_atomic, CONTRACT_VERSION` (and `_lines` if signatures match; if they differ, stop
   and report). Delete its local copies.
2. Make `publish_allocator_targets` call `_write_json_atomic`. Its inline temp-file block is the
   same logic; keep the `.json.tmp` temporary name and the exact `OutputWriteError` message text,
   because tests may assert it.
3. `_timestamp`: keep the datetime-taking version in `imports/cloud_ip_ranges.py`; in
   `resolver.py` delete the local one and call it with `datetime.now(timezone.utc)`.
**Verify:**
golden test byte-identical; suite and local CI pass; coverage not lower. If a test
about error text fails, stop and report (rule 8) rather than editing expected text.
Negative check: alter one `OutputWriteError` message, confirm the contract tests fail, then revert.
**Do not:** rename the helpers' behaviour, change any message, or touch the pipe formats.
**Done when:** verification passes.
**PR:** `refactor: share atomic output helpers` (bundle with
R-07, R-10 and R-12 per the PR table).

### R-09 Keep records structured in memory
**Tier:** T2 (Sonnet), design reviewed by T3 before coding.
**Depends on:** R-03, R-07, R-08.
This is the largest cut and the enabler for R-13.
**Files:** `imports/cloud_service_provider_checks.py`,
`imports/domain_processor.py`, `classes/dns_handler.py`, `classes/takeover_detector.py`,
`classes/allocator_contract.py`, `classes/run_contract.py`, `classes/run_summary.py`,
`classes/environment_manager.py`, `classes/output_manager.py`, tests.
**Context:** records are written to pipe files, then read back three times (see `REVIEW.md` F-1,
F-2). The pipe files remain an output contract and must stay byte-identical.
**Design (write it in the PR description first; get it reviewed before coding):**
- One module `classes/records.py` with three small frozen dataclasses: `Resolution(domain, ips,
  wildcard)`, `CspMatch(domain, ip, provider, region, service, prefix, border_group, wildcard)`,
  `Observation` kinds `dangling`, `ns_takeover`, `unresolved` (hostname, detail). Each has a
  `.pipe()` method that returns today's exact line.
- `EnvironmentManager` owns `records: list` and `record(r)` appends and (as now) writes `r.pipe()`
  to the correct file. Writers call `record(...)` instead of formatting strings.
- `publish_allocator_targets`, `publish_dns_observations` and `RunSummary` take the in-memory
  records instead of file paths. They stop splitting strings, and the `ValueError("Malformed ...")`
  paths go.
**Steps:**
(a) introduce `records.py` and make writers emit through it, no consumer change yet,
golden test green; (b) switch `allocator_contract` to consume records, golden green; (c) switch
`run_contract` observations, golden green; (d) switch `run_summary`, golden green; (e) delete the
dead re-parse code and its tests. One commit per step.
**Verify:**
golden test byte-identical at every step; JSON still validates against
`contracts/*.schema.json` (existing `tests/test_allocator_contract.py`); coverage not lower.
Negative check: alter one `.pipe()` format, confirm the golden test fails, then revert.
**Do not:** change a pipe line, a JSON field, or a schema. Do not make `Observation` a class
hierarchy; one dataclass with a `kind` string is enough.
**Done when:** verification passes at every step, `_parse_target`, the `startswith` ladder in `run_contract.py` and the line-splitting in `run_summary.py` are gone, and no `ValueError("Malformed ...")` remains for our own output.
**PR:** `refactor: stop re-parsing our own output files`.

### R-10 Trim `cloud_ip_ranges.py`
**Tier:** T2 (Sonnet): fail-closed cache validation is subtle.
**Depends on:** R-03.
**Files:** `imports/cloud_ip_ranges.py`, `tests/test_cloud_ip_ranges.py`.
**Context:** `imports/cloud_ip_ranges.py` (408 lines) carries code that no longer earns its place: a migration for snapshot formats that expired within 14 days of August, one-line wrappers around the parsers, range dumps that duplicate `--extreme` logging in `resolver.py`, and copy-pasted validation and exception tuples. Each makes the fail-closed logic harder to read, and that logic is the part that must stay correct.
**Steps:**
1. Remove the legacy scalar-snapshot branch in `_normalise_metadata` (the "Snapshots written
   before multi-valued metadata" case) and its test. Snapshots expire within 14 days, so none of
   that vintage can be valid. Confirm by reading `MAX_CACHE_AGE`.
2. Inline `fetch_ip_ranges` and `fetch_ip_ranges_for_azure` (one-line wrappers) by having
   `_fetch_catalogue` take the parser (`_parse_standard`/`_parse_azure`) and fetch the JSON itself;
   update the three public `fetch_*_ip_ranges` functions and any test that imported the wrappers.
3. Remove the `if extreme: print(...)` blocks in both parsers; `resolver.py` already logs the
   ranges under `--extreme`. Drop the now-unused `extreme` parameter only if nothing else reads
   it inside this module.
4. Fold the IPv4 and IPv6 loops in `_validate_ranges` into one helper taking the expected version.
5. Replace the two duplicated `except (OSError, ValueError, KeyError, TypeError,
   CatalogueFetchError)` tuples with one module constant.
**Verify:**
every existing fail-closed test passes unmodified except those deleted in steps 1 and
2; golden test unchanged. **Do not** change any freshness limit, retry count, or error text.
Negative check: set `MAX_CACHE_AGE` to a huge value, confirm the stale-cache test fails, then revert.
**Do not:** change any freshness limit, retry count or error text; weaken a fail-closed path; edit the Azure discovery order.
**Done when:** verification passes and each of the five steps is its own commit.
**PR:** `refactor: simplify provider catalogue loading`.

### R-11a Replace `requests` and `urllib3` with `urllib.request`
**Tier:** T2 (Sonnet). Why: small, but the error-path text is written to a contract file and
tests mock the old library.
**Depends on:** R-03.
**Files:** `classes/environment_manager.py`, `requirements.txt`, `tests/test_environment_manager.py`.
**Context:** `requests` and its `urllib3` pin exist only for one call, `fetch_external_ip`
(`classes/environment_manager.py:27`). `urllib.request.urlopen` is already used in
`imports/cloud_ip_ranges.py`. Removing both ends two dependencies and their Dependabot churn.
**Steps:**
1. Rewrite `fetch_external_ip` with `urllib.request.urlopen(url, timeout=timeout)`, decode and
   strip the body.
2. Catch `OSError` (covers `URLError` and timeouts) and return the same text as today:
   `An error occurred while trying to retrieve the external ip: {error}`, because it is written
   to `environment_results_*.json`.
3. Confirm no other user: `grep -rn "import requests\|from requests\|urllib3" --include='*.py'
   --include='*.txt' .` (excluding `.venv`). Then remove `requests` and `urllib3` from
   `requirements.txt`.
4. Update the test mocks: patch `urlopen`, not `requests.get`; keep one success and one failure
   test and assert the returned text.
**Verify:**
golden test unchanged; suite and local CI pass; a fresh venv from
`requirements-dev.txt` installs and runs the suite; coverage not lower.
Negative check: make the mocked `urlopen` raise `OSError` and confirm the returned text equals the old error string; change one character of that string and confirm the test fails.
**Do not:** change the URL, the timeout default, or the error text; make the lookup opt-in here
(that is R-19).
**Done when:** verification passes.
**PR:** `chore: drop requests and urllib3` (bundle with R-11b).

### R-11b Remove `aiofiles`
**Tier:** T2 (Sonnet). Why: touches the write path that every output uses.
**Depends on:** R-09 (both edit the write path; do R-09 first).
**Files:** `classes/output_manager.py`,
`requirements.txt`, `tests/test_output_manager.py`.
**Context:** `OutputManager.write_to_file` uses `aiofiles` to append one short line per call. The
CSP writer in `imports/cloud_service_provider_checks.py` already appends with plain
`open(path, "a")`, so the codebase has both. A single-threaded event loop and one small write per
call gain nothing from `aiofiles`.
**Steps:**
1. Change the body of `write_to_file` to a synchronous `with open(file_path, "a",
   encoding="utf-8") as f: f.write(content + "\n")`. Keep it `async def` so no caller changes.
   Keep the same `OSError` handling and the same `OutputWriteError` message text.
2. Confirm no other user: `grep -rn aiofiles --include='*.py' --include='*.txt' .` (excluding
   `.venv`); remove it from `requirements.txt`.
3. Add or keep a test that a failing write raises `OutputWriteError` with the message text.
**Verify:**
golden test unchanged; suite and local CI pass; coverage not lower.
Negative check: point the target at an unwritable path, confirm `OutputWriteError` is raised with the expected text.
**Do not:** make `write_to_file` synchronous (callers `await` it); add buffering or locking; touch
the opt-in external-IP lookup (R-19).
**Done when:** verification passes.
**PR:** `chore: drop aiofiles` (bundle with R-11a).

### R-12 Small simplifications
**Tier:** T1 (Haiku). Why: three tiny, independent edits, each covered by the golden test.
**Depends on:** R-07 and R-09 (same files; run after them).
**Files:** `classes/domain_processing_context.py`, `imports/domain_processor.py`, `resolver.py`,
`imports/cloud_service_provider_checks.py`, `classes/environment_manager.py`,
`classes/evidence_collector.py`, `tests/conftest.py` and the affected tests.
**Context:** (1) `dangling_domains` is collected, returned as the third value of
`process_domain_async`, and ignored (`resolver.py` binds it to `_dangling`). (2)
`perform_csp_checks` lazily creates `env_manager._csp_written_lines` with `hasattr`. (3)
`EvidenceCollector.check_tools_availability` runs `subprocess.run(["which", ...])`, a blocking
call inside the event loop, where `shutil.which` is the standard-library equivalent.
**Steps:**
1. Remove `dangling_domains`, `add_dangling_domain_to_domains` and the third return value of
   `process_domain_async`; update the unpack in `resolver.py` and the tests that asserted it.
2. Replace the `hasattr` lazy init with `self._csp_written_lines = set()` in
   `EnvironmentManager.__init__`; make any test that builds a bare environment manager set it
   (check `tests/conftest.py`).
3. Replace `subprocess.run(["which", tool], ...)` with `shutil.which(tool) is not None`; keep the
   function's return shape.
**Verify:**
golden test unchanged; suite and local CI pass; coverage not lower.
Negative check: remove the `self._csp_written_lines` initialisation, confirm the CSP tests fail, then restore it.
**Do not:** change `takeover_detector` behaviour (secondary side, D-2: hardening only); touch any
output format.
**Done when:** verification passes.
**PR:** `refactor: remove unused state and a blocking call`
(bundle with R-07, R-08 and R-10).

### R-21 Record the failing nameserver in NS_TAKEOVER (D-12)
**Tier:** T2 (Sonnet) builds, T3 reviews the contract change. Why: the code change is small, but it alters a documented output record, so a strong reviewer must confirm the fields before merge.
**Depends on:** R-09 (records own the formatting) and R-03. Decision D-12 is made: add the field.
**Files:** `classes/takeover_detector.py`, `classes/records.py` (from R-09), `classes/run_contract.py` or its R-09 replacement, `classes/run_summary.py`, `AGENTS.md` (section 4), `README.md` (output table), `tests/test_dns_handler_extended.py` (or `tests/test_takeover_detector.py` after R-20), `tests/golden/expected/` (affected files only).
**Context:** the golden test (R-03) showed that `NS_TAKEOVER|origin|domain` does not say which nameserver is the problem, so the observation reads "Nameserver did not resolve: <the queried domain>", which is wrong. Two different conditions share the tag. `classes/takeover_detector.py:47`: an NS record's host (`ns_domain`) fails an A query with NXDOMAIN or SERVFAIL, which is the real NS-takeover signal, but only the queried domain is written and `ns_domain` is dropped. `classes/takeover_detector.py:137`: a name returns NXDOMAIN for A, AAAA and MX, yet an NS query on it succeeds, which means a delegated zone with no address records. That is a different finding that currently looks identical. Also, SERVFAIL from a nameserver lookup is treated as takeover evidence; a transient failure and an unregistered domain are not the same, but this item does not change that rule (secondary side, hardening only, D-2).
**Steps:**
1. Per D-12, append a fourth field to the record, `NS_TAKEOVER|origin|domain|nameserver`, where `nameserver` is the failing NS host at line 47, and the literal `-` at line 137 (no nameserver implicated). Do not invent a new tag; if the two cases need distinct tags, stop and report.
2. In `takeover_detector.py` pass `ns_domain` into the line-47 record; leave line 137's meaning unchanged.
3. Update the observation reason text: line 47 case becomes `Nameserver did not resolve: <nameserver>`; the `-` case becomes `Name has NS records but no address records`.
4. Update the console summary line so it shows the nameserver when present.
5. Update the format tables in `AGENTS.md` section 4 and `README.md`, state that the field count changed, and mark it in the release notes.
6. Regenerate only the affected golden files (`UPDATE_GOLDEN=1`), read the diff line by line, and confirm nothing else moved.
**Verify:**
- `pytest tests/test_golden_run.py` passes after regeneration, and `git diff tests/golden/expected/` shows changes only to `takeover_candidates.txt`, `dns-observations-v1.json` and `console_summary.txt`.
- Full suite and `bash ~/.claude/skills/ci-local/local-ci.sh --workflow ci.yml` pass; coverage not lower.
- Negative check: temporarily drop `ns_domain` from the record and confirm a new unit test (assert the fourth field equals the failing nameserver) fails, then restore.
**Do not:** change the rule that decides when a record is written (SERVFAIL handling stays); add a new tag; touch the `DANGLING` format; ship before the release is planned as a major (D-10).
**Done when:** the record names the failing nameserver, the observation text is accurate, the docs match, and the verification passes.
**PR:** `fix!: record the failing nameserver in NS_TAKEOVER`

### R-22 Deterministic output order
**Tier:** T2 (Sonnet). Why: it touches the order of every output file, but the golden test proves content is unchanged and one regression test proves stability.
**Depends on:** R-09 (records in memory), R-03.
**Files:** `classes/environment_manager.py`, `classes/output_manager.py` or the R-09 record store, `resolver.py`, `tests/test_golden_run.py`, `tests/golden/expected/` (affected files only), `AGENTS.md` (section 4), `README.md`.
**Context:** two things make output order vary between runs of identical input. First, `EnvironmentManager.set_domains` builds `set(self.clean_domains(...))` (`classes/environment_manager.py:154`), and set order varies with `PYTHONHASHSEED`. Second, domains finish in DNS-latency order under the semaphore, so even with ordered input the write order is a race. The JSON documents are already sorted (`allocator-targets-v1.json`, `dns-observations-v1.json`), but the pipe files (`resolution_results_*`, `csp_matches_*`, `takeover_candidates_*`, `unresolved_results_*`) are not. A consumer or reviewer diffing two runs sees noise, and the golden test had to patch `set_domains` to get stable bytes.
**Steps:**
1. In `set_domains`, replace `set(...)` with an order-preserving de-duplicate (`list(dict.fromkeys(...))`); keep the attribute type consumers expect (check `grep -rn "\.domains" classes imports resolver.py`; if a caller needs set semantics, convert at that call site).
2. Make the pipe files stable: after all domains finish and before the JSON documents are published, write each pipe file sorted by line, atomically (temporary file then `os.replace`), using the records from R-09. Keep progress writes as they are during the run, so a crashed run still leaves partial output.
3. Sort key is the full line text. State in `AGENTS.md` section 4 that line order is sorted and stable, and that consumers must still not depend on it beyond stability.
4. Remove the `set_domains` patch from `tests/test_golden_run.py`, regenerate only the expected pipe files, and read the diff: the lines must be the same set, reordered.
**Verify:**
- Run the golden test under `PYTHONHASHSEED=0`, `1`, `7`, `99` with no `set_domains` patch: all pass.
- Run the golden harness twice with different seeds, keep both output directories, and `diff -r` them: the diff is empty.
- Full suite, local CI, coverage not lower.
- Negative check: temporarily comment out the final sort and confirm the seeded golden runs disagree or fail, then restore.
**Do not:** change any line's content or any JSON document; sort during the run in a way that holds all lines in memory beyond what R-09 already keeps; change concurrency or retry behaviour.
**Done when:** identical input yields byte-identical files under any hash seed and any completion order, with the verification above passing.
**PR:** `fix: make output file order deterministic`

### R-20 Reorganise and shrink the DNS tests
**Tier:** T2 (Sonnet). Why: test moves across files need judgement about which class each test exercises, and the collected-count gate catches mistakes.
**Depends on:** R-03, R-05a, R-12 (they delete tests in the same files).
**Files:** `tests/test_dns_handler.py`, `tests/test_dns_handler_extended.py`, `tests/test_dns_handler_resolution.py`, `tests/test_takeover_detector.py` (new), `tests/conftest.py`, `tests/test_wildcard_detector.py`, `tests/test_cloud_service_provider_checks.py`
**Context:** `tests/test_dns_handler.py`, `test_dns_handler_extended.py` and
`test_dns_handler_resolution.py` hold 43 tests on two classes; most test `TakeoverDetector`.
Six near-identical fixtures are repeated across them.
**Steps:**
1. List every test and the class it exercises (`grep -n "def test_" tests/test_dns_handler*.py`).
2. Move the fixtures that appear in two or more of these files into `tests/conftest.py`; keep
   names, so test bodies do not change.
3. Create `tests/test_takeover_detector.py`; move the tests whose subject is `TakeoverDetector`
   there, unchanged. Merge the remainder into `tests/test_dns_handler.py` and delete the
   `_extended` and `_resolution` files. Do not edit test bodies in this step; moves only.
4. Remove tutorial prose from test module docstrings (`tests/test_csp_ip_addresses.py` is deleted
   by R-07; `tests/test_dns_handler.py`).
5. Separate commit: in `tests/test_wildcard_detector.py` and
   `tests/test_cloud_service_provider_checks.py`, collapse sets of tests that differ only by input
   and expected value into `pytest.mark.parametrize`. Convert only where the bodies are genuinely
   identical; if unsure, leave it.
**Verify:**
the number of collected tests does not fall (`pytest --collect-only -q | tail -1`
before and after; parametrize cases count individually); coverage not lower; golden test green.
Negative check: delete one moved test, confirm the collected-count comparison catches it, then restore.
**Do not:** delete a test because it looks redundant; every test removed must have an identical
twin.
**Done when:** verification passes, no `test_dns_handler_extended.py` or `test_dns_handler_resolution.py` remains, and the collected-test count is unchanged.
**PR:** `test: split DNS tests by class and share fixtures`.

---

## Phase 3: New capability

### R-19 Configuration layer (D-9, D-11), delivered as two PRs
**Split:** PR 9a `fix:` covers steps 4 (tri-state flags) and 8 (the regression tests for the bug) only. PR 9b `feat!:` covers the rest (environment variables, `.envrc.example`, opt-in external IP, README). Do 9a first.
**Tier:** T2 (Sonnet), spec below is complete.
**Depends on:** R-03, and run it **before R-13** so
`--format` is added to the table once.
**Files:** `classes/config_resolver.py`,
`classes/environment_manager.py`, `.envrc.example` (new), `.gitignore`, `README.md`,
`tests/test_config_resolver.py`, `config.json` (comments only if absent; see step 6).
**Context:** options can today come from the CLI or the `config` block of `config.json`. There is
a real bug: `store_true` flags default to `False`, but the merge only fills values that are `None`,
so `evidence`, `verbose` and `extreme` in `config.json` are silently ignored (`config.json` sets
`"evidence": true`; the effective value is `False`; confirmed 2026-10-16). The maintainer runs
other projects with direnv loading a git-ignored `.envrc`; this tool should work the same way.
**Design:**
the tool reads **environment variables only**. direnv (or `set -a; source .envrc`, or
a CI secret store) is what loads the file; the tool never parses `.envrc` itself (it is a shell
script, and a Python parser for it would be wrong or a new dependency). Precedence, highest first:
CLI flag, `DNSRESOLVER_*` environment variable, `config.json` `config` block, built-in default.
**Also note for the maintainer (not part of this item):**
the committed `config.json` defaults are
`timeout: 1` and `max_threads: 2`, while the README says the concurrency default is 50. A 1 second
timeout can classify slow answers as unresolved. Decide the intended defaults separately.
**Steps:**
1. Add a table in `config_resolver.py` mapping every option to its variable and type, and
   resolve each option through one function. Variables (all optional):
   `DNSRESOLVER_DOMAINS_FILE`, `DNSRESOLVER_OUTPUT_DIR`, `DNSRESOLVER_NAMESERVERS`,
   `DNSRESOLVER_MAX_THREADS`, `DNSRESOLVER_TIMEOUT`, `DNSRESOLVER_RETRIES`,
   `DNSRESOLVER_VERBOSE`, `DNSRESOLVER_EXTREME`, `DNSRESOLVER_EVIDENCE`,
   `DNSRESOLVER_CONFIG_FILE`, `DNSRESOLVER_RECORD_EXTERNAL_IP`. R-13 adds `DNSRESOLVER_FORMAT`.
2. Booleans accept `1/true/yes/on` and `0/false/no/off` (case-insensitive); anything else is an
   error that names the variable and exits non-zero (fail closed, no silent default). Integers
   that do not parse are an error naming the variable.
3. Make `domains_file` optional on the CLI (`nargs="?"`) so it can come from
   `DNSRESOLVER_DOMAINS_FILE`; if neither is given, exit with a clear usage error.
4. Boolean flags need tri-state so "not given on the CLI" is distinguishable from "false":
   use `default=None` with `action=argparse.BooleanOptionalAction` (`--evidence` /
   `--no-evidence`, same for `--verbose`, `--extreme`). Keep the existing short flags working.
   This is the fix for the silent-ignore bug.
5. Add `--record-external-ip` (default **off**, per D-9). When off, `fetch_external_ip` is not
   called and `environment_results_*.json` records `"external_ip": null`. This changes the
   environment JSON value (documented in the release notes).
6. Create `.envrc.example` at the repo root: every variable above, each commented out with its
   default and a one-line description, plus a first-line comment `# copy to .envrc, then
   direnv allow`. Add `.envrc` and `.env` to `.gitignore`. Do not create a real `.envrc`.
   Do not put secrets in the template; this tool has none.
7. README: replace the Options table with one table of option, flag, variable, default, and add a
   short "Configuration" section: precedence, direnv usage (`cp .envrc.example .envrc && direnv
   allow`), and that `config.json` remains for defaults and for `domain_categorisation`.
8. Tests (no real environment leakage: use `monkeypatch`): each variable applies; CLI beats env;
   env beats `config.json`; `config.json` beats built-in default; bad boolean and bad integer exit
   with a message naming the variable; **regression for the bug**: `config.json` with
   `"evidence": true` and no flag yields `evidence is True`; `--no-evidence` beats it.
**Verify:**
golden test unchanged except for the new `external_ip: null` in the environment
fixture (update that one expected file and say so in the PR); suite and CI green; run
`python resolver.py --help` and confirm every option shows. Manually: with `direnv` installed,
`cp .envrc.example .envrc`, set `DNSRESOLVER_TIMEOUT=3`, confirm the logged "Effective
Configuration" shows 3.
Negative check: revert the tri-state flag change, confirm the `config.json` `evidence: true` regression test fails, then restore.
**Do not:** add `python-dotenv` or any parser dependency; read `.envrc` from Python; store
secrets; change the meaning of any existing flag; remove `--config-file`.
**Done when:** verification passes for each PR (9a and 9b), the regression test for the `config.json` boolean bug exists, and `.envrc.example` is committed while `.envrc` is ignored.
**PR:** `fix: apply boolean options from config.json` (PR 9a); then `feat!: configure every option from the environment (direnv)` (PR 9b)

### R-13 Markdown run report (D-3, D-4, D-7)
**Tier:** T2 (Sonnet) after T3 sketches the table.
**Depends on:** R-09, R-19. **Additive**, minor.
**Files:** `classes/config_resolver.py`, `classes/markdown_report.py` (new), `resolver.py`, `tests/golden/expected/run-report.md` (new), `tests/test_golden_run.py`, `README.md`
**Context:** an agent or human should be able to read a run in few tokens. JSON stays canonical
and is always written; Markdown is a view rendered from the same in-memory records and is never
parsed back.
**Spec:**
- New CLI flag `--format {md,json}` (variable `DNSRESOLVER_FORMAT`, via the R-19 table), default `md`. `md` additionally writes `run-report.md` in the
  output directory; `json` skips it. Add to `classes/config_resolver.py` (and README table).
- `run-report.md` sections, in order: a header (run id, status, version, counts); **Actionable
  targets** grouped by provider then region, one table per provider with columns `hostname | ip |
  services | prefix`; **Excluded observations** as a short count table by kind with up to 20
  hostnames each and "N more"; **Provider catalogues** one line each (status, snapshot id prefix,
  age). No per-row repeated constants (no `contract_version`, no `actionability`).
- If the run is `incomplete` or `failed`, the report says so in its first line and contains no
  targets section.
- Rendering lives in `classes/markdown_report.py` (one function `render(records, manifest)`), no
  dependency.
**Steps:**
1. Add `--format` (and `DNSRESOLVER_FORMAT`) through the R-19 option table; default `md`.
2. Write `classes/markdown_report.py` with `render(records, manifest) -> str`, consuming the in-memory records from R-09 (never re-reading files).
3. Call it from `run()` after the JSON documents are published; write `run-report.md` only when the format is `md`.
4. Extend the golden test with the expected `run-report.md`; add the `--format json` and byte-identical-JSON tests; record the size comparison in the PR.
**Verify:**
golden test extended with the expected `run-report.md`; a test that `--format json`
writes no report; a test that the JSON documents are byte-identical with either flag. Record in the
PR the size of `run-report.md` against `allocator-targets-v1.json` for the golden fixture (bytes
and `bytes/4` as a rough token proxy); the report must be materially smaller (target: at most 50%
of the JSON bytes for the actionable section).
Negative check: add a `contract_version` column to the table, confirm the size assertion fails, then revert.
**Do not:** add a Markdown parser, change any JSON schema, or put anything in the report that is
not in the JSON documents.
**Done when:** verification passes and the report is at most 50% of the JSON bytes for the actionable section on the golden fixture.
**PR:** `feat: add a compact Markdown run report`.

---

## Phase 4: Scale and CI

### R-14 Benchmark harness
**Tier:** T2 (Sonnet). Why: new code with a written spec; measures, changes no behaviour.
**Depends on:** R-07. **Replaces** archived items 8 and 12 (measure before optimising).
**Files:** new `bench/bench_matcher.py` and `bench/BASELINE.md`. No source changes. Not collected
by pytest.
**Context:** `AGENTS.md` section 7 says scale is "reasoned, not measured". A synthetic micro-test
(55,000 prefixes) already showed at least 8.4 ms per distinct address, synchronous inside the
event loop and not memoised across hostnames. That is a lower bound; this item measures the real
code path so R-15 is justified (or not) by numbers.
**Steps:**
1. Build a deterministic synthetic catalogue (seeded RNG) of about 55,000 prefixes, mixed /16 to
   /28, IPv4 and IPv6, with metadata, shaped like AWS plus Azure.
2. Generate N addresses for N = 1,000, 10,000 and 100,000 with a realistic repeat rate (a few
   shared CDN addresses used by many hostnames), and run `perform_csp_checks` over them via the
   same objects `resolver.run()` uses.
3. Record: total time, mean time per address, and the maximum event-loop stall (run a task that
   sleeps 1 ms in a loop alongside and record the largest gap between ticks).
4. Print a Markdown table. Write the results, the machine description and the commit hash to
   `bench/BASELINE.md`.
**Verify:**
`python bench/bench_matcher.py --n 10000` finishes in under a minute and is
repeatable (two runs agree within 20%); the suite and local CI are unaffected.
Negative check: replace the matcher with a no-op, confirm the harness reports near-zero time, then restore.
**Do not:** modify the matcher; use real provider data or any network; commit large generated
fixtures (generate in memory).
**Done when:** the baseline is committed.
**PR:** `test: add a matcher benchmark harness`
(bundle with R-16a, R-16b).

### R-15 Matcher speed-up (conditional on R-14)
**Tier:** T2 (Sonnet) builds, T3 reviews. Why: performance change on the primary path with
an exact-equivalence requirement.
**Depends on:** R-09, R-14.
**Run this item only if** R-14 shows more than 100 ms of event-loop stall per address, or more than
60 s for 10,000 distinct addresses. Otherwise record the measured numbers in `AGENTS.md` section 7
(replacing "reasoned, not measured"), mark this item closed, and stop.
**Files:** `imports/cloud_service_provider_checks.py`, tests, `bench/BASELINE.md`.
**Context:** matching scans every published prefix for every address and family. Overlapping
prefixes and multiple attributions per prefix are required output (PR 169), so the speed-up must
return exactly the same matches.
**Steps:**
1. Memoise results per address with `functools.lru_cache` on a function of the address (the
   catalogue is fixed for the run). Re-run R-14.
2. If still over budget, index the prefixes per family sorted by network address and use `bisect`
   to find candidates, then check containment, preserving overlap handling (every matching prefix
   must still be returned).
3. Keep the old linear scan in the test suite as the oracle: a property test over random
   addresses against the benchmark catalogue asserts identical match sets.
**Verify:**
golden test byte-identical; the property test passes; R-14 numbers before and after
are in the PR description; suite and local CI pass; coverage not lower.
Negative check: drop overlapping-prefix handling, confirm the property test fails, then revert.
**Do not:** change output text or ordering; drop overlapping matches; add a dependency.
**Done when:** verification passes and the numbers meet the thresholds above.
**PR:** `perf: index provider prefixes`.

### R-16a CI coverage floor and scope
**Tier:** T1 (Haiku). Why: one workflow line and one doc edit, verified by running it.
**Depends on:** nothing.
**Files:** `.github/workflows/ci.yml`, `AGENTS.md` (section 8).
**Context:** `AGENTS.md` says "coverage only goes up", but nothing enforces it, and CI measures
`--cov=.` (which counts the tests themselves) instead of `classes` and `imports`.
**Steps:**
1. Locally run `.venv/bin/pytest --cov=classes --cov=imports --cov-report=term-missing` and note
   the total (about 95%).
2. In `ci.yml` change the test step to `pytest --cov=classes --cov=imports
   --cov-fail-under=<floor> --cov-report=term-missing`, where `<floor>` is 95 if the measured
   figure is 95 or higher, otherwise the measured whole-number figure (say so in the PR).
3. In `AGENTS.md` section 8, change "Currently ~95%" to say the floor is enforced by CI.
**Verify:**
`bash ~/.claude/skills/ci-local/local-ci.sh --workflow ci.yml` passes; temporarily set
the floor to 99 and confirm CI fails, then revert; the GitHub `test` job passes on the PR.
**Do not:** lower an existing floor; add the floor before the code deletions land (run this after
R-04 to R-12 so the figure is final).
**Done when:** verification passes.
**PR:** `ci: enforce a coverage floor` (bundle with R-14 and
R-16b).

### R-16b Lock runtime dependencies (D-8)
**Tier:** T2 (Sonnet). Why: supply-chain and CI behaviour change; wrong hashes break every
build.
**Depends on:** R-04, R-11a, R-11b (the dependency set must be final first).
**Files:** `requirements.txt` (kept as the input), new `requirements.lock` (hashes),
`.github/workflows/ci.yml`, possibly `requirements-dev.txt`.
**Context:** runtime requirements use `>=` floors with no lock, while outputs are contracts. The
same input can behave differently between two runs after a dependency release. A hash-locked file
makes runs reproducible and detects tampering. Dependabot stays enabled and will propose lock
updates.
**Steps:**
1. Use the `deps-integrity` skill's Python route. In a fresh venv:
   `pip install pip-tools` then `pip-compile --generate-hashes --output-file requirements.lock
   requirements.txt`. Do the same for `requirements-dev.txt` if you also want dev reproducibility
   (`requirements-dev.lock`).
2. In `ci.yml`, install with `pip install --require-hashes -r requirements.lock` for the runtime
   set, plus the dev tools as today.
3. Add a scheduled (weekly) `pip-audit` job or step that fails on known vulnerabilities; run it
   once locally first and report any finding rather than suppressing it.
4. Document in `README.md` how to regenerate the lock and why.
**Verify:**
a fresh venv built only from `requirements.lock` runs the suite; `local-ci` and the
GitHub `test` job pass; changing one hash makes the install fail (prove it, then revert).
**Do not:** drop Dependabot; pin by editing `requirements.txt` into `==`; commit a lock built on
a different Python minor version than CI (CI uses 3.12).
**Done when:** verification passes.
**PR:** `ci: lock runtime dependencies with hashes and audit
them` (bundle with R-14 and R-16a).

---

## Phase 5: External

### R-23 Keep the lock files current
**Tier:** T2 (Sonnet). Why: CI and supply-chain behaviour; a wrong lock fails every build, but the `test` job proves it.
**Depends on:** R-16b.
**Files:** `.github/workflows/` (one new workflow or an edit to an existing one), `README.md`, possibly `.github/dependabot.yml`.
**Context:** PR 222 added `requirements.lock` and `requirements-dev.lock`. Dependabot's pip ecosystem reads `requirements.txt` and `requirements-dev.txt` but not `.lock` files, so a Dependabot bump to an input file leaves the lock stale and CI keeps installing the old locked versions. Today regenerating is a manual step documented in the README.
**Steps:**
1. Check `.github/dependabot.yml` (or the Dependabot settings) and note which files it watches.
2. Add a workflow that, on a Dependabot pull request touching `requirements*.txt`, runs `pip-compile --generate-hashes --strip-extras` for both locks on Python 3.12 and commits the result back to the PR branch (or fails the check with the exact command to run). Pin pip-tools exactly; SHA-pin every action as the other workflows do.
3. Document the behaviour in the README "Reproducible installs" section.
**Verify:**
- Open a throwaway pull request that edits one input file's version floor and confirm the workflow regenerates the locks (or fails with the instruction).
- Negative check: change an input file without regenerating the lock and confirm the check fails, then revert.
- `test`, `gitleaks` and `trufflehog` still pass.
**Do not:** auto-merge anything; give the workflow write access beyond the pull request branch; rename the `test`, `gitleaks` or `trufflehog` jobs; drop Dependabot.
**Done when:** a Dependabot bump of an input file produces a pull request whose lock files are current, or a clear failing check.
**PR:** `ci: keep the lock files in step with their inputs`

### R-17 Validate the real allocator consumer end to end
**Owner:** maintainer (cross-repository).
**Tier:** not delegable to an in-repo agent. Why: it spans another repository the agent cannot see; a strong model may assist with the fixture.
**Depends on:** nothing in this repo; run against the latest released contract (and again after
R-18 if any contract changed).
**Files:** none in this repository (the allocator repository is read and run, not edited)
**Context:** the contracts in `contracts/` are tested here against schemas only. Nothing proves the
real allocator accepts a current `allocator-targets-v1.json` unchanged, or that targets for each
provider reach a provider-aware implementation. The Markdown report (R-13) is not an input to the
allocator.
**Steps:**
1. Produce a document from a synthetic, authorised fixture (the golden fixture's output is
   suitable: `tests/golden/expected/allocator-targets-v1.json`).
2. Feed it unchanged to the allocator's ingest path.
3. Confirm AWS targets reach the AWS implementation; GCP and Azure targets either reach a
   provider-aware implementation or are explicitly rejected, never silently routed to AWS.
4. Record the allocator version and result in `ROADMAP.md` (a dated line under this item).
**Verify:**
the allocator reports each target's provider correctly in its own output or logs.
Negative check: submit a GCP-only fixture and confirm no target is routed to the AWS implementation.
**Do not:** point the allocator at real client infrastructure for this check; change a contract
here to satisfy the consumer without a roadmap item.
**Done when:** the dated result is recorded.
**PR:** `docs: record allocator consumer validation` (only when a dated result is added to this roadmap; otherwise none)

### R-18 Release
**Owner:** main session with the maintainer.
**Tier:** T3 (strong model with the maintainer). Why: an irreversible public release with a small diff and high blast radius.
**Depends on:** the PRs through PR 10
(R-19 and R-13) merged and `main` green. Decision D-10: one release, expected v3.0.0.
**Files:** `VERSION`, `version.py`, `README.md`
**Context:** Lambda removal is a removed entry point and the environment JSON changes when the
external-IP lookup becomes opt-in, so a major bump is correct (`AGENTS.md` section 6: version
centrally, once per batch). This repo has no release-please config; v2.0.0 was cut by hand as a
`chore: release vX.Y.Z` PR that bumped the version files and added the README notes, followed by a
GitHub release.
**Steps:**
1. Confirm `main` is green and the working tree is clean; run the full local CI.
2. Decide with the maintainer: set up release-please via the `release` skill, or release by hand.
   If by hand:
3. Branch `chore/release-v3.0.0`. Set `VERSION` to `3.0.0` and `version.py` to `__version__ =
   "3.0.0"` (a baseline test enforces they agree). Update the README version pin and breaking
   changes notes using the `release-readme-pin` skill.
4. Open the PR as `chore: release v3.0.0` with a body listing the breaking changes (removed Lambda
   entry point; external IP now opt-in; any format change) and merge with squash.
5. After merge, create the release and tag together: `gh release create v3.0.0 --target main
   --title "..." --notes-file <notes>`. This is the only way a tag is created; never `git tag`.
6. Run `/ponytail:ponytail-review` is not needed; instead verify the release: `gh release view
   --json tagName` and the baseline test passes on `main`.
**Verify:**
`gh release list` shows v3.0.0 as Latest; `VERSION`, `version.py` and the tag agree
(`tests/baseline/`); `main` CI is green afterwards.
Negative check: edit `VERSION` only, run `tests/baseline/`, confirm it fails on the mismatch, then revert.
**Do not:** bump `VERSION` in any earlier PR; create the tag before the release PR merges; edit
`docs/ALLOCATOR-CONTRACT.md` unless a contract changed (none is planned).
**Done when:** the release exists and the verification passes.
**PR:** `chore: release v3.0.0` (the release PR in step 4).

---

## Ideas, not scheduled

Not part of the sequence above. Each is written to the same standard as a scheduled item so it can
be promoted without rework. Promotion needs a maintainer decision, because both touch the
secondary (takeover) side, where D-2 currently says "harden only".

### I-1 Authoritative cross-check
**Status:** unscheduled.
**Origin:** `helper/find_authoritative_ns.py`, deleted in R-05b (D-6).
**Promote when:** real runs show stale-cache false candidates (a dangling or NS finding that
disappears on re-run) or a split-horizon or lame-delegation case that the recursive resolver
hides. Until then it is unproven value.
**Tier:** Strong (T3) designs, then mid (T2, Sonnet) builds: a new protocol-level module whose premise (stale caches matter) is unproven.
**Depends on:** R-09 (in-memory records) and R-19 (option table), and a maintainer decision lifting D-2 for this feature.
**Files:** `classes/authoritative_resolver.py` (new), `classes/dns_handler.py`, `contracts/dns-observations-v1.schema.json`, `docs/ALLOCATOR-CONTRACT.md`, `tests/test_authoritative_resolver.py` (new), `tests/test_golden_run.py`
**Context:** every query today goes through a recursive resolver (`--nameservers` or the system
one), which caches. For dangling-CNAME and NS-takeover findings a cached answer can be stale in
either direction: a record removed minutes ago still resolves (missed candidate), or a negative
answer outlives the fix (false candidate). Asking the zone's own authoritative servers returns the
current truth. Disagreement between the two is itself a finding: stale cache, split-horizon DNS,
or a lame delegation (a delegated nameserver that does not answer or does not exist).
**Tier if promoted:**
T3 designs the module and its output, then T2
(Sonnet) builds it.
**Why the old script was not the answer:**
it assumed the registrable domain is the last two
labels (wrong for `example.co.uk`), looked nameserver addresses up through the system resolver
instead of following the delegation, printed instead of returning data, and was never wired in.
**Design (decide before building):**
1. Find the zone cut by following referrals from the root, not by guessing labels. Start at a
   root server, ask for the name's NS, follow the referral to the next set of servers, and stop
   when a server answers authoritatively (AA flag). This needs no public-suffix list, so it needs
   no new dependency; `dnspython` (`dns.query.udp`, `dns.message`) is already a dependency.
2. Take nameserver addresses from the referral's additional section; if absent, resolve the NS
   name, and record a lame delegation if it does not resolve.
3. Query each authoritative server for the name's A, AAAA and CNAME, compare with the recursive
   answer, and emit one observation per disagreement.
4. Cache per zone (the same pattern as `WildcardDetector`: one lookup per zone, not per host),
   bound concurrency with the existing semaphore, and cap referral depth (suggest 10).
5. Output: a new observation `kind` (suggest `authoritative_mismatch`) in
   `dns-observations-v1.json`, always `actionability: "excluded"`; it must never reach
   `allocator-targets-v1.json`. This is an additive schema change: bump the observation schema
   in `contracts/` deliberately and update `tests/test_allocator_contract.py` and
   `docs/ALLOCATOR-CONTRACT.md`. Decision needed: additive minor bump or a new schema version.
6. Opt-in: `--authoritative-check` / `DNSRESOLVER_AUTHORITATIVE_CHECK`, default off, because it
   sends extra queries to third-party authoritative servers (DNS only; still inside the scope
   boundary, but not free).
**PR (if promoted):** `feat: optional authoritative cross-check of DNS answers`.
**Steps:**
1. New `classes/authoritative_resolver.py` with one class and one public coroutine
   `compare(domain, recursive_ips) -> list[Mismatch]`. Mock the network in tests; no test performs
   a real DNS query. Follow the mocking pattern in `tests/test_wildcard_detector.py`.
2. Tests: a delegation that resolves (agree, no observation); a record present in the
   authoritative answer but absent from the recursive one (mismatch); a lame delegation; a referral
   loop (stops at the depth cap, reports, does not hang); a multi-label suffix such as
   `a.example.co.uk` (zone cut found without a suffix list); a CNAME at the authoritative server
   that the recursive answer hides.
3. Wire into `DNSHandler` behind the flag; extend the golden test (R-03) with one mismatch case
   and update only the affected expected files.
4. Run once against a real domain you are authorised to test and attach the output to the PR
   (`AGENTS.md` section 8: unit tests cannot tell you the premise was wrong).
**Verify:**
golden test unchanged when the flag is off; full suite, local CI and coverage not
lower; the real-domain run agrees with `dig +norecurse @<authoritative server>`.
Negative check: simulate a referral loop, confirm the depth cap stops it and a test fails if the cap is removed.
**Do not:** add a public-suffix dependency, send HTTP, put findings in the actionable feed, or
make the check default-on.
**Done when:** the flag is off by default, the golden test is unchanged with it off, the real-domain run is attached, and the schema change is documented.
**PR:** `feat: optional authoritative cross-check of DNS answers`

## Explicitly not doing

- No cloud allocation or provider API calls, no HTTP probing, no TLS inspection (`AGENTS.md`).
- No slimming of the takeover side (D-2): `takeover_detector`, `domain_categoriser`,
  `evidence_collector` (except the blocking `which`), and the `config.json` pattern table stay.
- No change to any pipe format or JSON schema in this plan. Any such change is a new major item.
- No Markdown parser, and no schema for Markdown. It is a view.
- No version bump or tag inside an item PR.

## Verification principle

Unit coverage did not catch the defects that mattered before (`AGENTS.md` section 8). Refactors
here are gated by a byte-exact end-to-end test (R-03). Anything that changes resolution or
classification (none planned) needs a run against real DNS before it is believed.
