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
| D-11 | Every option is settable from the environment (`DNSRESOLVER_*`), loaded by direnv from a git-ignored `.envrc`; a committed `.envrc.example` is the template. Precedence: CLI flag, then environment, then `config.json`, then built-in default | 2026-10-16 | R-19 |

There are no open decisions.

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
**Status:** PR 203 open, all checks green (`test`, `gitleaks`, `trufflehog`). **Tier:** main session.
**Done when:** PR 203 is squash-merged; the eight superseded Dependabot PRs (202, 201, 200, 199,
198, 190, 187, 166) are closed with a comment pointing at PR 203 (the maintainer confirms the
closures). Also update the stale TruffleHog version in the prose of the archived roadmap only if
a later edit touches it; do not edit history otherwise.

### R-02 Repair stale tool paths in docs
**Tier:** T1 (Haiku). **Why:** find and replace, verified by grep.
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
**Files:** `AGENTS.md`, `docs/roadmap/AGENT-GUIDE.md`.
**Done when:** grep shows no live-doc hits; CI green. **PR:** `docs: correct local-ci path`.

### R-03 Golden end-to-end characterisation test
**Tier:** T2 (Sonnet), reviewed by T3. **Why:** this is the gate for every later refactor, so it
must be right; the spec below makes it mid-tier work. **Blast radius:** test-only.
**Context:** nothing proves that the pipe files, JSON documents and console summary stay
consistent. Add one test that runs `resolver.run()` on fixed mocked inputs and compares every
output file byte for byte against checked-in expected files.
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
**Files:** `tests/test_golden_run.py`, `tests/golden/**`. No source changes.
**Done when:** test passes; breaking a format fails it; full suite and CI green; coverage unchanged
or higher. **PR:** `test: add golden end-to-end output test`.

---

## Phase 1: Deletions

### R-04 Remove the shelved Lambda stack (D-1)
**Tier:** T1 (Haiku) with a mandatory grep sweep. **Depends on:** R-03. **Breaking:** yes (removed
entry point; release as a major, see D-10).
**Steps:**
1. Delete: `lambda_handler.py`, `classes/lambda_environment_manager.py`,
   `tests/test_lambda_handler.py`, `tests/test_lambda_environment_manager.py`, `docs/LAMBDA.md`,
   `requirements-lambda.txt`.
2. `grep -rn -i "lambda\|boto3" . --include='*' --exclude-dir=.venv --exclude-dir=.git
   --exclude-dir=worktrees -I` and handle every remaining hit outside the two archive files:
   - `.github/workflows/ci.yml`: change `pip install -r requirements-dev.txt -r
     requirements-lambda.txt` to `pip install -r requirements-dev.txt`.
   - `requirements-dev.txt`: ensure nothing includes the lambda file.
   - `README.md`, `AGENTS.md` (sections 2 and 5): remove Lambda rows and the "install both
     requirements files" advice; keep a one-line note that the shared `run()` entry point remains.
   - `docs/roadmap/AGENT-GUIDE.md`: same advice, remove.
   - `tests/baseline/test_baseline.py`: if it references Lambda files, remove only those checks.
3. Confirm `resolver.run(env_manager)` is untouched.
**Done when:** the second grep shows only archive hits; `pytest` passes; coverage figure noted
(it may rise slightly because untested-ratio changes; it must not fall); CI green.
**PR:** `chore!: remove the shelved Lambda entry point` (the `!` marks the breaking change).

### R-05a Delete confirmed dead code
**Tier:** T1 (Haiku). **Depends on:** R-03.
**Targets (grep each per rule 7 first):** `WildcardDetector.is_wildcard_resolution`
(`classes/wildcard_detector.py`), `FileDoesNotExistError`, `NotAnIntegerError`,
`InvalidNameserversError` (`classes/custom_exceptions.py`), `EnvironmentManager.get_random_nameserver`
and `get_config_file` (`classes/environment_manager.py`).
**Steps:** for each target, grep; if the only hits are its own definition and tests of it, delete
the definition and those tests; if `tests/test_custom_exceptions.py` becomes empty, delete the
file. If any production hit exists, leave that item and report.
**Done when:** suite and CI green; coverage not lower. **PR:** `chore: remove unused code`.

### R-05b Delete the unreferenced helper (D-6)
**Tier:** T1. Delete `helper/find_authoritative_ns.py` (no callers, no tests, absent from the
README, wrong for multi-label suffixes such as `example.co.uk`). Run the rule 7 grep first.
Check `README.md` still lists only `helper/crtsh_domains.sh`. The idea behind it is kept as I-1.

### R-06 Archive delivered per-PR plans
**Tier:** T1 (Haiku). **Why:** deletion verified by link checks; history keeps the files.
**Steps:**
1. Delete `docs/roadmap/PR-A-ci-reliability.md` through `PR-H-dependencies.md` and
   `docs/roadmap/README.md`.
2. Fix every reference found by `grep -rn "docs/roadmap/PR-\|roadmap/README" . --include='*.md'
   --exclude-dir=.venv --exclude-dir=.git` outside the two archive files. Keep
   `docs/roadmap/AGENT-GUIDE.md`, `ARCHIVE.md`, `REVIEW-2026-07.md`.
3. In `README.md` (roadmap pointer, around line 349) and `HANDOVER.md` (lines referencing
   `REVIEW.md` and `ROADMAP.md`) make the pointers accurate: the 2026-07 review is at
   `docs/roadmap/REVIEW-2026-07.md`, the current review is `REVIEW.md`. Do not rewrite
   `HANDOVER.md` otherwise (its fate is a separate maintainer decision).
**Done when:** a markdown link check by eye (`grep -o "](.*\.md" ` and confirm each target exists)
finds no dead links; CI green. **PR:** `docs: archive delivered per-PR plans`.

---

## Phase 2: Structure (all behaviour-preserving, gated by R-03)

### R-07 Replace `CSPIPAddresses` with the catalogue objects
**Tier:** T2 (Sonnet). **Depends on:** R-03. **Files:** `resolver.py`,
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
**Verify:** R-03 golden test unchanged, byte for byte. Suite and CI green; coverage not lower.
**Do not:** change output text, the order of records, or any contract.
**PR:** `refactor: match against provider catalogues directly`.

### R-08 One home for atomic output helpers
**Tier:** T1 (Haiku) **Depends on:** R-03. **Files:** `classes/run_contract.py`,
`classes/allocator_contract.py`, `resolver.py`, `imports/cloud_ip_ranges.py`.
**Steps:**
1. `_remove_output`, `_write_json_atomic`, `CONTRACT_VERSION`, `_lines` are defined in both
   contract modules. Keep the `classes/run_contract.py` versions; in `allocator_contract.py`
   `from classes.run_contract import ...` them and delete its copies. Make `publish_allocator_targets`
   use `_write_json_atomic` (its inline temp-file block is the same logic; keep the same
   `.json.tmp` temp name and the same error message text, since tests may assert it).
2. Define `_timestamp` once (in `imports/cloud_ip_ranges.py` it takes a datetime; in `resolver.py`
   it takes none). Keep the datetime-taking one, and in `resolver.py` call it with
   `datetime.now(timezone.utc)`.
**Verify:** golden test unchanged; suite green. If the golden test or a test about error text
fails, stop and report (rule 8) rather than editing expected text.
**PR:** `refactor: share atomic output helpers`.

### R-09 Keep records structured in memory
**Tier:** T2 (Sonnet), design reviewed by T3 before coding. **Depends on:** R-03, R-07, R-08.
This is the largest cut and the enabler for R-13. **Files:** `imports/cloud_service_provider_checks.py`,
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
**Steps:** (a) introduce `records.py` and make writers emit through it, no consumer change yet,
golden test green; (b) switch `allocator_contract` to consume records, golden green; (c) switch
`run_contract` observations, golden green; (d) switch `run_summary`, golden green; (e) delete the
dead re-parse code and its tests. One commit per step.
**Verify:** golden test byte-identical at every step; JSON still validates against
`contracts/*.schema.json` (existing `tests/test_allocator_contract.py`); coverage not lower.
**Do not:** change a pipe line, a JSON field, or a schema. Do not make `Observation` a class
hierarchy; one dataclass with a `kind` string is enough.
**PR:** `refactor: stop re-parsing our own output files`.

### R-10 Trim `cloud_ip_ranges.py`
**Tier:** T2 (Sonnet): fail-closed cache validation is subtle. **Depends on:** R-03.
**Files:** `imports/cloud_ip_ranges.py`, `tests/test_cloud_ip_ranges.py`.
**Steps (one commit each, tests green after each):**
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
**Verify:** every existing fail-closed test passes unmodified except those deleted in steps 1 and
2; golden test unchanged. **Do not** change any freshness limit, retry count, or error text.
**PR:** `refactor: simplify provider catalogue loading`.

### R-11a Replace `requests` and `urllib3` with `urllib.request`
**Tier:** T2. **Depends on:** R-03. **Files:** `classes/environment_manager.py`,
`requirements.txt`, `tests/test_environment_manager.py`.
**Steps:** rewrite `fetch_external_ip` with `urllib.request.urlopen(..., timeout=timeout)`, keeping
the same return text on error (including the `An error occurred ...` string, because it is written
to the environment JSON). Catch `OSError` (covers `URLError`, timeouts). Remove `requests` and
`urllib3` from `requirements.txt` after `grep -rn "import requests\|urllib3"` shows no other user.
Update the mocks in tests (mock `urlopen`, not `requests.get`).
**Done when:** golden test and suite green; `pip install -r requirements-dev.txt` in a fresh venv
works; CI green. **PR:** `chore: drop requests and urllib3`.

### R-11b Remove `aiofiles`
**Tier:** T2. **Depends on:** R-09 (both touch the write path). **Files:** `classes/output_manager.py`,
`requirements.txt`, tests.
**Steps:** `write_to_file` becomes a plain synchronous append (`open(path, "a")`, same
`OutputWriteError` text). It stays `async def` so no caller changes. Single-threaded event loop,
one small write per call, same as the CSP writer. Remove `aiofiles` after grep confirms no other
user. **Verify:** golden test; a test that a failing write raises `OutputWriteError`.
(The opt-in external-IP lookup, D-9, is delivered by R-19, not here.)
**PR:** `chore: drop aiofiles`.

### R-12 Small simplifications
**Tier:** T1 (Haiku). **Depends on:** R-07, R-09 (same files).
**Steps (one commit each):**
1. `classes/domain_processing_context.py`: `dangling_domains`, `add_dangling_domain_to_domains`
   and the third return value of `process_domain_async` are never used (`resolver.py` binds it to
   `_dangling`). Remove them; update the unpack in `resolver.py` and tests.
2. `imports/cloud_service_provider_checks.py`: replace the `hasattr(env_manager,
   "_csp_written_lines")` lazy init with `self._csp_written_lines = set()` in
   `EnvironmentManager.__init__`; tests that build a bare env manager should set it too (check
   `tests/conftest.py`).
3. `classes/evidence_collector.py`: replace `subprocess.run(["which", x], ...)` with
   `shutil.which(x) is not None` (hardening only: removes a blocking call from the event loop).
**Verify:** golden test; suite; coverage not lower. **PR:** `refactor: remove unused state and a
blocking call`.

### R-20 Reorganise and shrink the DNS tests
**Tier:** T2 (Sonnet). **Depends on:** R-03, R-05a, R-12 (they delete tests in the same files).
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
**Verify:** the number of collected tests does not fall (`pytest --collect-only -q | tail -1`
before and after; parametrize cases count individually); coverage not lower; golden test green.
**Do not:** delete a test because it looks redundant; every test removed must have an identical
twin. **PR:** `test: split DNS tests by class and share fixtures`.

---

## Phase 3: New capability

### R-19 Configuration layer (D-9, D-11), delivered as two PRs
**Split:** PR 9a `fix:` covers steps 4 (tri-state flags) and 8 (the regression tests for the bug) only. PR 9b `feat!:` covers the rest (environment variables, `.envrc.example`, opt-in external IP, README). Do 9a first.
**Tier:** T2 (Sonnet), spec below is complete. **Depends on:** R-03, and run it **before R-13** so
`--format` is added to the table once. **Files:** `classes/config_resolver.py`,
`classes/environment_manager.py`, `.envrc.example` (new), `.gitignore`, `README.md`,
`tests/test_config_resolver.py`, `config.json` (comments only if absent; see step 6).
**Context:** options can today come from the CLI or the `config` block of `config.json`. There is
a real bug: `store_true` flags default to `False`, but the merge only fills values that are `None`,
so `evidence`, `verbose` and `extreme` in `config.json` are silently ignored (`config.json` sets
`"evidence": true`; the effective value is `False`; confirmed 2026-10-16). The maintainer runs
other projects with direnv loading a git-ignored `.envrc`; this tool should work the same way.
**Design:** the tool reads **environment variables only**. direnv (or `set -a; source .envrc`, or
a CI secret store) is what loads the file; the tool never parses `.envrc` itself (it is a shell
script, and a Python parser for it would be wrong or a new dependency). Precedence, highest first:
CLI flag, `DNSRESOLVER_*` environment variable, `config.json` `config` block, built-in default.
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
**Verify:** golden test unchanged except for the new `external_ip: null` in the environment
fixture (update that one expected file and say so in the PR); suite and CI green; run
`python resolver.py --help` and confirm every option shows. Manually: with `direnv` installed,
`cp .envrc.example .envrc`, set `DNSRESOLVER_TIMEOUT=3`, confirm the logged "Effective
Configuration" shows 3.
**Do not:** add `python-dotenv` or any parser dependency; read `.envrc` from Python; store
secrets; change the meaning of any existing flag; remove `--config-file`.
**Also note for the maintainer (not part of this item):** the committed `config.json` defaults are
`timeout: 1` and `max_threads: 2`, while the README says the concurrency default is 50. A 1 second
timeout can classify slow answers as unresolved. Decide the intended defaults separately.
**PRs:** 9a `fix: apply boolean options from config.json`; 9b `feat!: configure every option from the environment (direnv)`.

### R-13 Markdown run report (D-3, D-4, D-7)
**Tier:** T2 (Sonnet) after T3 sketches the table. **Depends on:** R-09, R-19. **Additive**, minor.
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
**Verify:** golden test extended with the expected `run-report.md`; a test that `--format json`
writes no report; a test that the JSON documents are byte-identical with either flag. Record in the
PR the size of `run-report.md` against `allocator-targets-v1.json` for the golden fixture (bytes
and `bytes/4` as a rough token proxy); the report must be materially smaller (target: at most 50%
of the JSON bytes for the actionable section).
**Do not:** add a Markdown parser, change any JSON schema, or put anything in the report that is
not in the JSON documents.
**PR:** `feat: add a compact Markdown run report`.

---

## Phase 4: Scale and CI

### R-14 Benchmark harness
**Tier:** T2. **Depends on:** R-07. **Replaces** archived items 8 and 12 (measure first).
**Spec:** `bench/bench_matcher.py` (not run by pytest): build a deterministic synthetic catalogue
of about 55,000 prefixes (seeded RNG, mixed /16 to /28, IPv4 and IPv6, shaped like AWS plus Azure),
generate N addresses (N = 1,000; 10,000; 100,000) with a realistic repeat rate (a few CDN addresses
shared by many hostnames), and time `perform_csp_checks` per address and in total. Also measure
how long the event loop is blocked (record the maximum time between iterations of a 1 ms
`asyncio.sleep` ticker running alongside). Print a small Markdown table. Store a baseline in
`bench/BASELINE.md` with the machine description.
**Done when:** the harness runs in under a minute at N = 10,000 and the baseline is committed.
No source changes. **PR:** `test: add a matcher benchmark harness`.

### R-15 Matcher speed-up (conditional on R-14)
**Tier:** T2 build, T3 review. **Depends on:** R-09, R-14. **Run this item only if** R-14 shows more
than 100 ms of event-loop blocking per address or more than 60 s for 10,000 distinct addresses;
otherwise record the numbers in `AGENTS.md` section 7 (replacing "reasoned, not measured") and close.
**Spec:** (1) memoise match results per address (`functools.lru_cache` on a function of
`(ip, provider-set)` is enough); (2) if still over budget, index prefixes per family in sorted
order by network address and `bisect`, handling overlapping prefixes (all matching prefixes must
still be returned: overlap and multi-attribution are required, PR 169).
**Verify:** golden test byte-identical; a property test comparing the indexed matcher with the old
linear scan on random addresses over the benchmark catalogue (the linear scan stays in the test as
the oracle); R-14 numbers before and after in the PR. **PR:** `perf: index provider prefixes`.

### R-16a CI coverage floor and scope
**Tier:** T1. In `.github/workflows/ci.yml`, change the test step to
`pytest --cov=classes --cov=imports --cov-fail-under=95 --cov-report=term-missing`. Run it locally
first; if the real figure is below 95, set the floor to the current whole-number figure and say so.
Update `AGENTS.md` section 8 ("enforced by CI").

### R-16b Lock runtime dependencies (D-8)
**Tier:** T2. Use the `deps-integrity` skill's Python route: `pip-compile --generate-hashes`
for `requirements.txt`, install with `--require-hashes` in CI, add a scheduled `pip-audit` step.
Keep Dependabot enabled.

---

## Phase 5: External

### R-17 Validate the real allocator consumer end to end
**Owner:** maintainer (cross-repository). Carried forward from archived item 11: the allocator
ingests a current `allocator-targets-v1.json` unchanged; GCP and Azure route only to
provider-aware implementations or are rejected; a synthetic authorised fixture proves no provider
is misrouted. The Markdown report is not an input to the allocator.

### R-18 Release
**Owner:** main session, after R-04 to R-13 (and D-10). This repo has no release-please config (v2.0.0 was cut by hand), so first decide with the maintainer whether to set it up via the `release` skill or release manually, D-10;
never `git tag` by hand. Expect v3.0.0: Lambda removal is a removed entry point, and the
environment JSON changes if D-9 is accepted. Update `docs/ALLOCATOR-CONTRACT.md` only if a
contract changed (none is planned).

---

## Ideas, not scheduled

Not part of the sequence above. Each is written to the same standard as a scheduled item so it can
be promoted without rework. Promotion needs a maintainer decision, because both touch the
secondary (takeover) side, where D-2 currently says "harden only".

### I-1 Authoritative cross-check
**Status:** unscheduled. **Tier if promoted:** T3 designs the module and its output, then T2
(Sonnet) builds it. **Origin:** `helper/find_authoritative_ns.py`, deleted in R-05b (D-6).
**Promote when:** real runs show stale-cache false candidates (a dangling or NS finding that
disappears on re-run) or a split-horizon or lame-delegation case that the recursive resolver
hides. Until then it is unproven value.
**Context:** every query today goes through a recursive resolver (`--nameservers` or the system
one), which caches. For dangling-CNAME and NS-takeover findings a cached answer can be stale in
either direction: a record removed minutes ago still resolves (missed candidate), or a negative
answer outlives the fix (false candidate). Asking the zone's own authoritative servers returns the
current truth. Disagreement between the two is itself a finding: stale cache, split-horizon DNS,
or a lame delegation (a delegated nameserver that does not answer or does not exist).
**Why the old script was not the answer:** it assumed the registrable domain is the last two
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
**Steps for the builder (after the design is approved):**
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
**Verify:** golden test unchanged when the flag is off; full suite, local CI and coverage not
lower; the real-domain run agrees with `dig +norecurse @<authoritative server>`.
**Do not:** add a public-suffix dependency, send HTTP, put findings in the actionable feed, or
make the check default-on.

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
