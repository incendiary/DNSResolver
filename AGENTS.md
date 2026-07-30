# AGENTS.md — orientation for AI agents working on DNSResolver

Read this before changing anything. It records what the tool is *for*, which is not
obvious from the code, plus the conventions and traps that have already cost time here.

Companion documents: [`REVIEW.md`](REVIEW.md) (findings), [`ROADMAP.md`](ROADMAP.md) (planned
work), [`docs/roadmap/AGENT-GUIDE.md`](docs/roadmap/AGENT-GUIDE.md) (per-task working rules).

---

## 1. What this tool is for

DNSResolver is passive DNS reconnaissance for offensive security. It takes a flat list of
candidate domains and **produces targets**. It has two jobs of equal weight:

**Job 1 — dangling CNAME / subdomain takeover candidates.** A CNAME pointing at a service
name nobody owns any more. Well-covered ground; other tools do this too.

**Job 2 — A records resolving into claimable cloud IP space.** This is the differentiator
and the part that is easy to under-value when reading the code.

### Why Job 2 is the interesting one

With a dangling CNAME you can *read the intent from DNS* — the target names a service
(`foo.s3.amazonaws.com`) and you can reason about whether it is claimable.

With a bare A record you cannot. `1.2.3.4` says nothing. If that address is an AWS Elastic
IP that the owner released, whoever allocates it next controls what is served for that
hostname — but **DNS gives you no signal that this is the case**. The only way to find out
is to churn IP allocation in that provider and region until you are handed the address.

So the tool's job is to answer: *which A records land in cloud ranges worth grinding, and
where?* That makes provider + region + service the essential payload, not decoration.

### This tool does not claim anything

It **identifies and hands off targets**. The allocation grinding is a separate tool. That
boundary is deliberate:

- Do not add claiming, allocation, or any cloud-provider API calls here.
- Do not encode per-mechanism heuristics about what is "claimable". Surface the provider's
  own published metadata faithfully and let the operator judge.
- The output files are therefore **machine-readable interfaces**, not prose reports. Treat
  their formats as contracts — see §4.

### Scope boundary (firm)

DNS only. **No HTTP/HTTPS requests, no TLS inspection, no port scanning, no screenshots.**
Confirming a takeover needs an HTTP fetch; that belongs to a different tool. This keeps
DNSResolver passive, dependency-light, and safe to run broadly. Do not cross this line even
when it would resolve an ambiguity — several known limitations exist *because* of it, and
they are accepted trade-offs, not bugs. See §7.

---

## 2. Architecture

```
resolver.py            CLI entry point ────┐
lambda_handler.py      Lambda entry point ─┴─► run(env_manager)  — shared async pipeline
```

| Module | Responsibility |
|---|---|
| `classes/environment_manager.py` | CLI environment: argparse glue, logging, domain file I/O. `fetch_external_ip()` is a module-level seam so the class can be built without a network. |
| `classes/lambda_environment_manager.py` | Lambda environment: env vars, stdout logging, `/tmp` I/O |
| `classes/config_resolver.py` | Parses CLI args, merges `config.json`. CLI always wins. |
| `classes/output_manager.py` | Builds the timestamped output tree; async writes via `aiofiles` |
| `classes/dns_handler.py` | Async resolution. Queries **A and AAAA concurrently**; a domain is unresolved only when *both* fail. aiodns primary, dnspython second opinion. |
| `classes/takeover_detector.py` | Dangling CNAME + NS takeover, depth-limited CNAME chain following |
| `classes/wildcard_detector.py` | Per-zone wildcard detection via random-label probes, cached per zone |
| `classes/domain_categoriser.py` | Regex classification of CNAME targets against `config.json`. **First match wins** — order is specific → general. |
| `classes/csp_ip_addresses.py` | Holds fetched provider ranges **and their region/service metadata** |
| `imports/cloud_ip_ranges.py` | Fetches AWS/GCP/Azure published ranges. Azure uses a three-stage fallback (live scrape → local cache → pinned URL). |
| `imports/cloud_service_provider_checks.py` | Matches resolved IPs to provider ranges; writes the handoff records |
| `imports/domain_processor.py` | Per-domain orchestration |
| `classes/run_summary.py` | End-of-run operator summary |

Concurrency is `asyncio.gather` under a `Semaphore` (`--max-threads`). Failed domains are
collected and retried up to `--retries` times.

---

## 3. Two correctness rules that were learned the hard way

Both were shipped bugs. Do not reintroduce them.

**A takeover candidate requires an actual CNAME.** A name that simply does not exist
(NXDOMAIN, no CNAME) has nothing dangling to claim. It must be reported as *unresolved*,
never as a candidate. An earlier version flagged every dead name, and a live run of 15 hosts
reported 9 candidates, all false. On a real enumeration — where most guessed names do not
exist — that noise buries the findings the tool exists to surface.

**`self_referential` only applies at recursion depth > 0.** The check compares the current
name against the original, which is trivially true on entry. Gating on depth is what makes
it mean "a CNAME chain looped back", which is the only case it should describe.

---

## 4. Output contracts

Everything lands in a timestamped directory under `--output-dir`. **These are interfaces
consumed by other tooling — changing a format is a breaking change.**

| File | Format |
|---|---|
| `resolution_results_*.txt` | `domain\|ip1\|ip2\|…` — IPv4 first, then IPv6. Prefixed `WILDCARD\|` when the name resolved only via a zone wildcard. |
| `takeover_candidates_*.txt` | `DANGLING\|origin\|target\|category\|recommendation\|evidence` and `NS_TAKEOVER\|origin\|domain` |
| `csp_matches_*.txt` | Cloud handoff records — see below |
| `unresolved_results_*.txt` | Domains that failed all retries |
| `environment_results_*.json` | Run metadata (command, external IP, Docker status) |
| `evidence/dns/` | `dig`/`nslookup` capture per flagged domain, when `--evidence` is set |

The prefix convention (`WILDCARD|`, `DANGLING|`, `NS_TAKEOVER|`) is the house style for
tagging a line's type while keeping untagged lines backward compatible. Follow it.

---

## 5. Environment and tooling

**`python3` on the maintainer's machine is a broken pyenv shim.** Always use an explicit
interpreter:

```bash
/opt/homebrew/bin/python3.12 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt -r requirements-lambda.txt
```

Install **both** requirements files. `requirements-lambda.txt` supplies `boto3`; without it
the Lambda tests fail with `ModuleNotFoundError` — an environment gap, not a code bug. CI
installs both.

**Before pushing**, run CI locally. A fail-closed `pre-push` hook enforces this; the
`pre-commit` slot chains gitleaks and ruff.

```bash
bash ~/.claude/skills/local-ci/local-ci.sh --workflow ci.yml
.venv/bin/pytest --cov=classes --cov=imports
```

---

## 6. Conventions and traps

- **Never run `git tag`.** Tags are created only when a release is cut. A tag for an
  unreleased version breaks the version-sync baseline test on *every other branch*.
- **Do not bump `VERSION` per PR.** Version centrally, once per batch, at release time.
  Parallel branches each bumping it conflict on every merge.
- **`VERSION` and `version.py` must agree**, and a baseline test enforces it.
- **Secret scanning is live and strict.** A gitleaks rule flags the maintainer's employer
  name. Never put real client or employer names in code, comments, commits, or docs — refer
  to "a client domain" or use `example.com`. This repository is public.
- **No GitHub pingback syntax.** Never write `owner/repo#123` for another repository; use a
  full URL in backticks or plain prose.
- **Branch protection** requires the status checks `test`, `gitleaks`, `trufflehog` — these
  are *job* names. Do not set required contexts to workflow names; that silently blocks
  every PR forever.
- Conventional commit titles (`feat:`, `fix:`, `docs:`, `chore:`, `test:`), squash merge,
  one logical change per PR.

---

## 7. Known limitations (accepted, not bugs)

- **Resolution covers A and AAAA only.** Hosts reachable solely by other record types read
  as unresolved.
- **Classification is first-match-wins.** An unmatched CNAME target is reported `unknown`
  rather than guessed at.
- **Wildcard detection cannot separate a real host from a catch-all** when the host shares
  the wildcard's addresses. Shared hosting is the common case: a live site and a fabricated
  name under the same platform return byte-identical DNS. Distinguishing them needs an HTTP
  request, which §1 rules out. The flag means *"resolution proves nothing in this zone"*,
  not *"this host does not exist"*.
- **Performance at scale is reasoned, not measured.** Known cliffs were removed (per-IP CIDR
  parsing, O(n²) dedupe) but no benchmark has been run against a large list.

---

## 8. Testing standards

- **No test may perform a real DNS query or HTTP request.** Mock `aiodns`, `dns.resolver`,
  `requests`, `urlopen`. Follow the patterns in `tests/conftest.py` and
  `tests/test_dns_handler.py`.
- **Assert outcomes, not execution.** A test that only proves code "ran without raising" is
  worse than no test, because it reads as coverage. Assert the classification string, the
  precedence result, the graceful return value.
- **Coverage only goes up.** Currently ~95%.
- **Every bug fix gets a regression test.**

### The verification lesson

This is worth internalising. During a recent hardening pass, coverage rose from 85% to 95%
and caught **none** of the defects that mattered. All three were found elsewhere:

- two by **running the tool against real DNS** (the false takeover candidates, and a wildcard
  feature that passed all 16 of its unit tests while being completely non-functional on real
  dual-stack zones);
- one by **attempting a real merge** (the branch-protection misconfiguration).

Unit tests confirm the logic you thought of. They cannot tell you the premise was wrong. For
changes to resolution or classification, **run the tool against real domains** before
believing it works.

---

## 9. Recently landed

Region and service metadata capture is **done**. All three providers publish it and the code
previously discarded it at parse time:

| Provider | Publishes | Now captured as |
|---|---|---|
| AWS | `ip_prefix`, `region`, `service` | region, service |
| GCP | `ipv4Prefix`/`ipv6Prefix`, `service`, `scope` | scope → region, service |
| Azure | `addressPrefixes`, `region`, `systemService` | region, systemService → service |

Fetchers return `(ipv4, ipv6, metadata)` where metadata maps CIDR → `(region, service)`.
`CSPIPAddresses` carries it and exposes `describe(cidr)`. Each matched address is written as
one handoff record:

```
domain|ip|provider|region|service|prefix
```

Why it mattered: over half of AWS's ~10,500 prefixes carry the generic `AMAZON` tag, so
"it is an AWS IP" was close to no information. A live run against AWS-fronted hosts now
reports `CLOUDFRONT` and `GLOBALACCELERATOR` rather than a flat provider tally — telling an
operator at a glance that these are CDN edges, not EC2 addresses in a region, and so not
worth pursuing.

Fields are taken verbatim from the provider; where none is published they read `unknown`
rather than being inferred. The tool does not judge what is claimable — §1 applies.
