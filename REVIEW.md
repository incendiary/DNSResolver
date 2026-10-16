# DNSResolver: Holistic Review and Ponytail Audit

> Reviewed at commit `86275b9` (v2.0.0 plus 10 unreleased commits), 2026-10-16.
> Method: `review-codebase` (8 phases), then `ponytail-audit` calibrated to the intent in
> [`AGENTS.md`](AGENTS.md), with the Karpathy goal-and-verify framing.
> Supersedes the 2026-07 review, preserved unchanged (including its correction section) at
> [`docs/roadmap/REVIEW-2026-07.md`](docs/roadmap/REVIEW-2026-07.md). The plan that follows from
> this document is [`ROADMAP.md`](ROADMAP.md).

## Executive summary

The tool does what it is for and the recent work (provider-aware attribution, fail-closed
catalogues, schema'd contracts) is sound. The suite is 320 tests at 95% coverage, lint is clean, CI
is green and SHA-pinned. The principal weakness is structural, not functional: **the program uses
its own pipe-delimited text files as an internal message bus.** Every run writes records as text,
then three separate modules (`allocator_contract`, `run_contract`, `run_summary`) read the files
back and re-parse them to build the JSON contracts and the end-of-run summary. That round trip is
the source of most avoidable code, most `ValueError("Malformed ...")` paths, and the reason a
Markdown output (which the maintainer wants) would currently mean a fourth parser.

Second, about 1,750 lines of source and tests (plus about 900 lines of documentation) can go
without changing a byte of output: the shelved Lambda stack, dead helpers, a 49-line class that
repacks data the catalogue objects already hold, and duplicated atomic-write helpers.

Third, the only scale risk is real and cheap to size: matching costs at least 8.4 ms per distinct
address (synthetic benchmark, 55,000 prefixes), runs synchronously inside the event loop, and is
not memoised across domains. It is deferred in the old plan as "unmeasured"; the plan now
measures it first.

**Overall health: A-.** Nothing here is urgent. The work is simplification and one new output view.

## Intent used to calibrate the audit

From `AGENTS.md`: the tool produces cloud-address targets for a separate allocation pipeline
(primary) and retains takeover observations for a different consumer (secondary). It never
claims, allocates, or makes HTTP requests. Output files are contracts. Maintainer decisions
recorded in this review (2026-10-16):

| # | Decision | Effect on the audit |
|---|---|---|
| D-1 | Lambda is shelved: **delete candidate** | Whole stack is listed as a cut |
| D-2 | Takeover side: **harden only** | Not slimmed; only correctness and blocking-call fixes proposed |
| D-3 | **JSON stays canonical; Markdown is a rendered view, default on**, JSON an alternative | New `--format` item; no parser for Markdown, ever |
| D-4 | Consumers are **both a program and an agent/human** | Token cost matters for the Markdown view only |
| D-5 | Plan lives in `ROADMAP.md`, history archived | Done in this change |

## Phase 1: Architecture

| Module | Responsibility | Concern |
|---|---|---|
| `resolver.py` | CLI entry and the shared `run()` pipeline | Unpacks three catalogues into six lists to repack them (`resolver.py:119`) |
| `classes/dns_handler.py` | A and AAAA resolution, dnspython second opinion | Sound; fixed in PR 161 |
| `classes/takeover_detector.py` | Dangling CNAME and NS takeover | Writes `NS_TAKEOVER` from two code paths; secondary, hardening only |
| `classes/wildcard_detector.py` | Per-zone wildcard verdicts | `is_wildcard_resolution` has no production caller |
| `imports/cloud_ip_ranges.py` | Fetch, validate, cache provider catalogues | 408 lines; carries migration and compatibility shims (see audit) |
| `imports/cloud_service_provider_checks.py` | Match addresses to prefixes, write pipe records | Linear scan; `hasattr` state on `env_manager` |
| `classes/allocator_contract.py` | Re-parse `csp_matches` pipe lines into JSON | Round trip |
| `classes/run_contract.py` | Re-parse three pipe files into observations and manifest | Round trip |
| `classes/run_summary.py` | Re-parse the same files again for the console summary | Round trip, third copy |
| `lambda_handler.py`, `classes/lambda_environment_manager.py` | Shelved Lambda entry | Dead weight (D-1) |

**Data flow.** domains file, then per-domain async task, then resolution, then takeover and
wildcard checks, then `perform_csp_checks` appends pipe lines to files. At end of run those files
are read back three times. The files are both the output contract and the internal bus; that
coupling is the root of Findings F-1 and F-2.

## Phase 2: Risk inventory

Scores 1 to 5 (5 critical). Ponytail findings are in Phase 8 and are not repeated here.

| # | Category | Finding | Score | Location |
|---|---|---|---|---|
| F-1 | Reliability | A formatting change to a pipe line (or the free-text `DNS resolution error for ...` prefix) makes a completed run raise `ValueError("Malformed ...")` after all DNS work is done, turning a good run into `failed` with no actionable output | 3 | `classes/run_contract.py:74`, `classes/allocator_contract.py:84` |
| F-2 | Maintainability | Three parsers of one format; a fourth is implied by Markdown output | 3 | as above plus `classes/run_summary.py:7` |
| F-3 | Scalability | Prefix match is a linear scan per address per family, synchronous inside async tasks (blocks DNS concurrency), no cross-domain memo for repeated CDN addresses | 4 | `imports/cloud_service_provider_checks.py:96` |
| F-4 | Privacy/opsec | Every start calls a third-party service (`ifconfig.io`) with a 10 s timeout and records the result; surprising for a passive tool, slow offline | 3 | `classes/environment_manager.py:27` |
| F-5 | Dependency | Runtime deps use `>=` floors with no lockfile or hashes, while outputs are contracts; Dependabot rewrites floors weekly | 3 | `requirements.txt` |
| F-6 | CI | No coverage floor (AGENTS.md says "only goes up", nothing enforces it); CI measures `--cov=.` (includes tests) not `classes` and `imports`; no `pip-audit` | 3 | `.github/workflows/ci.yml:39` |
| F-7 | Test | No end-to-end golden-output test. `tests/test_resolver.py` has 3 tests about control flow. Refactoring output code is currently gated only by unit tests, which AGENTS.md section 8 says do not catch the defects that matter | 4 | `tests/` |
| F-8 | Docs | About 3,100 lines of Markdown against 2,650 lines of source; delivered PR plans and a handover duplicate `AGENTS.md`; three docs cite a removed path (`~/.claude/skills/local-ci/`) | 2 | `docs/roadmap/PR-*.md`, `HANDOVER.md` |
| F-9 | Reliability | `EvidenceCollector.check_tools_availability` runs blocking `subprocess.run(["which", ...])` inside the event loop on every flagged domain | 2 | `classes/evidence_collector.py` |
| F-10 | Reliability | Boolean options in `config.json` are silently ignored: `store_true` flags default to `False`, the merge only fills `None`. `config.json` sets `"evidence": true`; effective value is `False` (verified 2026-10-16). Configuration is also not settable from the environment | 3 | `classes/config_resolver.py:113` |

Python-specific checklist: no `eval`/`exec`/`pickle`/`shell=True`; subprocess uses exec form;
`requests` and `urlopen` calls have timeouts; no bare `except:`; no mutable defaults found. Clean.

## Phase 3: Predicted failures (score 3 or more)

**PF-1 (F-3): event-loop stall on a large list.** Trigger: a list of tens of thousands of hosts
resolving into cloud ranges. Each distinct address costs at least 8.4 ms of blocking CPU per
family (synthetic: 55,000 /24 prefixes, `any(ip in n for n in nets)`; the real loop adds a
memoised `parse_network` call per prefix, so the true figure is higher). At 100,000 distinct
addresses that is at least 14 minutes of single-threaded blocking, during which no DNS reply is
processed. Timeline: appears at roughly 10^4 addresses and grows linearly. Minimum fix: memoise
per address. Full fix: indexed matcher (existing deferred item). Both are gated on a benchmark
first (ROADMAP R-14).

**PF-2 (F-1): late failure on format drift.** Trigger: any future edit to a record format, or a
resolver error string containing an unexpected shape. Effect: all DNS work completes, then
`publish_allocator_targets` raises and the run is marked failed. Timeline: the next time anyone
changes a record. Fix: records stay structured in memory (R-09).

**PF-3 (F-7): silent contract break during refactor.** Trigger: any of the planned cuts. Effect:
output differs subtly and unit tests still pass. Fix: build the golden test first (R-03).

**PF-4 (F-5): non-reproducible run.** Trigger: a dependency minor release changes resolver
behaviour between two runs. Effect: the same input produces different output with no code change.
Fix: lock with hashes (R-16, decision D-8).

## Phase 4: Test coverage gaps

| Path | Why critical | Test type needed |
|---|---|---|
| `run()` end to end | Only place pipe files, JSON contracts and summary are proven consistent | Golden: mocked DNS and catalogues, byte-exact comparison of every output file |
| `perform_csp_checks` repeat addresses | The same address across many hostnames | Unit plus benchmark |
| Markdown view (new) | Will be read by agents | Golden against the same fixture; size ratio vs JSON recorded |

Highest value additions: the golden run test, a benchmark harness, and a `--cov-fail-under`
gate. Existing tests largely assert outcomes rather than execution (good); test code is 4,852
lines against 2,652 of source, of which roughly 320 test lines cover code proposed for deletion.

## Phase 5: Dependency audit

| Package | Pin | Note |
|---|---|---|
| aiodns, aiofiles | `~=` | `aiofiles` only appends single lines; sync append is already used by `csp` writer (cut candidate) |
| dnspython | `>=2.9.0` | Deliberate second opinion; keep |
| requests, urllib3 | `>=` | Used only for the `ifconfig.io` probe; `urllib.request` is already used elsewhere (cut candidates) |
| tqdm | `>=` | Keep (progress) |
| boto3 | `>=` | Lambda only (cut with D-1) |
| ruff | `==0.17.0` | Pinned; pre-commit rev aligned in PR 203 |

No CVEs known at review time (no `pip-audit` run is wired into CI; see F-6). Net: 4 runtime
dependencies removable (`boto3`, `requests`, `urllib3`, `aiofiles`).

## Phase 6: CI/CD gaps

| Check | State |
|---|---|
| Tests on every PR | Yes (job `test`) |
| Lint and format | Yes (ruff) |
| Secret scan | Yes (gitleaks, trufflehog), SHA-pinned |
| Action pinning | Yes |
| Scheduled drift run | Yes (weekly) plus Dependabot |
| Coverage floor | **No** (F-6) |
| Dependency vulnerability scan | **No** |
| Local gate | Pre-push and pre-commit hooks were pointing at a removed path; repaired 2026-10-16 and verified (5 of 5 steps green) |

Snippet for the coverage gap (R-16):

```yaml
      - name: Test (pytest)
        run: pytest --cov=classes --cov=imports --cov-fail-under=95 --cov-report=term-missing
```

## Phase 7: Summary of action items

See [`ROADMAP.md`](ROADMAP.md), items R-01 to R-19, each written to be executed by a named model
tier with explicit steps, verification commands, and stop conditions.

## Phase 8: Ponytail audit

Intent applied: DNS-only, contracts frozen, no claiming. Correctness, security and performance
are out of scope for this phase (they are in Phases 2 and 3). Every `delete:` was grepped across
source, tests, docs and workflows; symbols used only by their own tests are marked as such.
Ranked by lines removed. Line counts are approximate.

1. `delete:` Lambda stack: `lambda_handler.py` (108), `classes/lambda_environment_manager.py`
   (120), `tests/test_lambda_handler.py` (199), `tests/test_lambda_environment_manager.py` (122),
   `docs/LAMBDA.md` (192), `requirements-lambda.txt`, the extra install in `ci.yml`, README
   sections. Shared `run()` stays. Replacement: nothing (restorable from tag `v2.0.0`).
   **-746 lines, -1 dep (`boto3`).**
2. `reuse:` three re-parsers of the same pipe files. Keep structured records in memory (one small
   dataclass), render pipe lines, JSON, summary and Markdown from them. Targets:
   `classes/allocator_contract.py` (`_lines`, `_parse_target`), `classes/run_contract.py:158`
   (`_lines`, the `startswith` ladder), `classes/run_summary.py:7`. Also deletes the "Malformed ..."
   `ValueError` paths that exist only because of re-parsing. **About -200 lines.**
3. `delete:` docs that describe delivered work: `docs/roadmap/PR-A` to `PR-H` (about 670 lines) and
   `docs/roadmap/README.md`; `HANDOVER.md` (575) largely duplicates `AGENTS.md` and
   `docs/roadmap/AGENT-GUIDE.md`. History keeps all of it. **About -900 lines of docs.**
4. `delete:` dead code, each grepped (source callers: none): `is_wildcard_resolution`
   (`classes/wildcard_detector.py:129`, tests only), `FileDoesNotExistError`, `NotAnIntegerError`,
   `InvalidNameserversError` (`classes/custom_exceptions.py`, plus `tests/test_custom_exceptions.py`),
   `get_random_nameserver` and `get_config_file` (`classes/environment_manager.py:100,103`),
   and `helper/find_authoritative_ns.py` (174 lines, referenced nowhere; **needs maintainer
   confirmation**, D-6). **About -250 lines.**
5. `yagni:` `classes/csp_ip_addresses.py` (49 lines, six getters, six constructor arguments).
   `ProviderCatalogue` already holds `ipv4_ranges`, `ipv6_ranges` and `metadata`. Pass the
   `{provider: catalogue}` dict; `get_vendor_ips`/`merge_matches` collapse into one loop.
   Also removes `ProviderCatalogue.__iter__` (`imports/cloud_ip_ranges.py:50`, "compatibility with
   the existing matcher boundary") and the unpack in `resolver.py:119`. **About -110 lines.**
6. `shrink:` `imports/cloud_ip_ranges.py`: legacy scalar-snapshot migration (`:127`; snapshots
   expire within 14 days, so it has been dead since August); `fetch_ip_ranges` /
   `fetch_ip_ranges_for_azure` one-line wrappers (`:209`, `:213`); `extreme` range dumps inside the
   parsers (`:176`, `:203`) duplicating the dump in `resolver.py`; two copies of the IPv4/IPv6
   validation loop; two near-identical `ProviderCatalogue` constructions; two identical
   multi-exception tuples. **About -60 lines.**
7. `reuse:` `_remove_output` defined twice (`classes/allocator_contract.py:77`,
   `classes/run_contract.py:187`), atomic JSON write twice, `_lines` three times, `CONTRACT_VERSION`
   twice, `_timestamp` twice (`resolver.py:232`, `imports/cloud_ip_ranges.py:70`).
   Import from one place. **About -50 lines.**
8. `native:` `requests` and `urllib3` exist only for the `ifconfig.io` probe
   (`classes/environment_manager.py:9,29`); `urllib.request.urlopen` is already used in
   `imports/cloud_ip_ranges.py`. `aiofiles` appends one line per call; the CSP writer already uses
   plain `open(..., "a")`. **-3 deps, about -15 lines.**
9. `yagni:` `classes/domain_processing_context.py` (21 lines): `dangling_domains` is collected,
   returned, and ignored by `resolver.py` (`_dangling`). Remove the set, the setter and the third
   return value. **About -25 lines plus test edits.**
10. `shrink:` `hasattr(env_manager, "_csp_written_lines")` lazy init
    (`imports/cloud_service_provider_checks.py:25`): initialise in `EnvironmentManager.__init__`.
    `stdlib:` `subprocess.run(["which", ...])` in `classes/evidence_collector.py` is
    `shutil.which(...)`. **About -12 lines.**

11. `reuse:` tests (added after a second pass over `tests/`, 4,852 lines). The three files
    `tests/test_dns_handler.py` (414), `test_dns_handler_extended.py` (238) and
    `test_dns_handler_resolution.py` (337) are 43 tests on two classes, and most of them
    (`check_dangling_cname_async`, `check_ns_takeover`, `handle_takeover_checks`, evidence) exercise
    `TakeoverDetector`, not `DNSHandler`. Each file re-declares near-identical fixtures (six
    between them) that `tests/conftest.py` could hold once. Split by class under test into
    `test_dns_handler.py` and `test_takeover_detector.py`, share fixtures. Estimate **-150 lines**,
    from fixture and mock-setup duplication. `delete:` tutorial prose in test headers
    (`tests/test_csp_ip_addresses.py`, `tests/test_dns_handler.py`: "a good place to start if
    you've never written tests", async primers), about -40 lines. `shrink:` only 13 `parametrize`
    uses across 23 files; the near-identical error-case tests in `test_wildcard_detector.py` (21
    tests, 285 lines) and `test_cloud_service_provider_checks.py` (33 tests, 578 lines) are
    parametrize candidates. This last estimate (about -150 lines) is from test names and structure,
    not a body-by-body read; treat it as a hypothesis for the agent to confirm.
    About -340 lines in total, on top of the roughly 510 test lines that disappear with items 1,
    4 and 5.

Considered and kept: the 90-entry `config.json` pattern table (D-2), dnspython as a second
resolver (PR 161 fixed real unreliability), `DomainCategoriser` (10 lines, one caller, but tested
and cheap), the three-state wildcard verdicts (documented hard-won behaviour), `OutputManager`
(61 lines, earns its keep).

`net: about -1,750 lines of source and tests, about -900 lines of documentation, -4 runtime
dependencies possible.`

## Addendum: `helper/find_authoritative_ns.py` (decision D-6)

Intent (from its docstring): walk the delegation from the root servers down to the zone and print
the authoritative name servers for a subdomain, so an operator could pass them as `--nameservers`
and bypass recursive-resolver caches. Assessment: it does not serve the primary job (a cached
recursive answer is adequate for mapping a hostname to a cloud prefix), the secondary NS-takeover
check already lives in `takeover_detector`, and the script is not wired in: no caller, no tests,
absent from the README, unchanged since the initial release. It also has a defect: it takes the
last two labels as the registrable domain, which is wrong for multi-label suffixes such as
`example.co.uk`, and it resolves nameserver addresses through the system resolver rather than the
delegation chain. Integrating it properly would mean per-zone authoritative querying with
public-suffix handling, which is a new feature, not a fix. Recommendation: delete (R-05b); if
authoritative-fresh answers become a requirement, design that as its own item.

## What this review deliberately did not do

It did not run the tool against live DNS or providers: nothing in the proposed work changes
resolution or classification, and every cut is gated on a byte-exact golden test (R-03) rather
than on unit coverage. Items that do change observable behaviour (R-13 Markdown, R-15 matcher) say
so and carry their own live-run gate.
