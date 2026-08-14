# DNSResolver

DNSResolver is a passive DNS reconnaissance tool for offensive security. Given a flat list of
candidate domains it **produces targets**, doing two jobs of equal weight:

**1. Dangling CNAME and NS takeover candidates.** CNAMEs pointing at service names nobody owns
any more, and domains whose nameservers no longer resolve.

**2. A records resolving into cloud IP space.** The less obvious half, and the reason this tool
exists alongside the many that do job 1.

A dangling CNAME names a service, so its intent can be read straight from DNS. A bare A record
cannot. If that address is a cloud IP the owner released, whoever allocates it next controls what
is served for that hostname — and **DNS gives no signal that this is the case**. Finding out means
churning allocation in that provider and region until the address comes back to you.

So DNSResolver answers: *which A records land in cloud ranges worth pursuing, and where?* Each
match carries the provider's own published region, service and network border group, because an
address is only actionable if you know where it is allocated from and what it belongs to.

It also:

- Flags **wildcard DNS** zones, so catch-all answers are not mistaken for real hosts
- Collects forensic evidence (dig/nslookup output) for flagged domains

Domain processing runs concurrently using `asyncio`, making it practical for large domain lists.

**This tool identifies targets — it does not claim them.** Acting on a finding is a separate
tool's job. That is why the output files are machine-readable records rather than prose reports,
and why DNSResolver reports what each provider publishes without judging what is worth pursuing.

The tool is intentionally DNS-focused. It does not make active HTTP/HTTPS connections, probe TCP ports, validate TLS certificates, or take screenshots. These were deliberately excluded to keep the tool passive, dependency-light, and scoped to DNS reconnaissance.

**Scope boundary.** DNSResolver is deliberately passive and DNS-only. Confirming a takeover (HTTP/HTTPS fingerprinting, TLS inspection, port probing, screenshots) is **out of scope by design** — if that capability is needed it belongs in a separate tool, not here. Keeping this project DNS-only keeps it dependency-light, fast, and safe to run broadly.

## Demonstration

![DNSResolver Demo](Media/simplerun.gif)

## Installation

```bash
git clone https://github.com/incendiary/DNSResolver.git
cd DNSResolver
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python resolver.py <domains_file> [options]
```

`domains_file` — path to a plain-text file with one domain per line.

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--output-dir` | `-o` | Directory to save results (default: `output`) |
| `--config-file` | | Path to config JSON (default: `config.json`) |
| `--verbose` | `-v` | Enable verbose logging |
| `--extreme` | `-e` | Enable extreme logging (includes full IP range dumps, implies `-v`) |
| `--nameservers` | | Comma-separated custom resolvers, e.g. `8.8.8.8,1.1.1.1` |
| `--max-threads` | `-mt` | Max concurrent domain tasks (default: 50) |
| `--timeout` | `-t` | DNS query timeout in seconds |
| `--retries` | | Retry attempts for failed domains (default from config) |
| `--evidence` | | Save dig/nslookup output for flagged domains |
| `--version` | | Print version and exit |

### Example

```bash
python resolver.py domains.txt -o results --evidence -v --nameservers 8.8.8.8,1.1.1.1 --timeout 5 --retries 2
```

### Building a domain list from certificate transparency

DNSResolver takes a flat list of domains as input — it does not enumerate subdomains itself. A quick
way to build one passively is from certificate transparency logs, using the bundled helper:

```bash
helper/crtsh_domains.sh example.com > domains.txt
python resolver.py domains.txt -o results --evidence -v --nameservers 8.8.8.8,1.1.1.1 --timeout 5 --retries 2
```

The helper queries [crt.sh](https://crt.sh), keeps only valid hostnames (certificate common names are
also returned and are not always hostnames), strips wildcard prefixes, and de-duplicates. crt.sh is
frequently slow or briefly unavailable, so it retries and fails with a clear message rather than
emitting a partial list.

For broader coverage, combine it with active enumeration and de-duplicate:

```bash
helper/crtsh_domains.sh example.com >  domains.txt
subfinder -d example.com -silent    >> domains.txt
sort -u -o domains.txt domains.txt
```

## Output

> **Formats changed in v2.0.0.** `csp_matches_*.txt` moved from prose to structured fields,
> `resolution_results_*.txt` and `csp_matches_*.txt` may carry a `WILDCARD_ZONE|` prefix, and
> `takeover_candidates_*.txt` gained hop count and chain path. Anything parsing v1 output needs
> updating. These files are consumed by other tooling, so their formats are treated as contracts.

Each run creates a timestamped subdirectory under the output directory containing:

| File | Contents |
|------|----------|
| `resolution_results_*.txt` | Successfully resolved domains and their IPv4/IPv6 addresses, pipe-delimited (`domain\|ip1\|ip2`). Prefixed `WILDCARD\|` (confirmed catch-all) or `WILDCARD_ZONE\|` (zone answers for anything, unverifiable) — see [Wildcard DNS detection](#wildcard-dns-detection) |
| `unresolved_results_*.txt` | Domains that could not be resolved after all retries |
| `takeover_candidates_*.txt` | `DANGLING\|origin\|target\|category\|recommendation\|evidence\|hops\|chain` — the chain records the full CNAME path (`a -> b -> c`), so the claimable hop is visible without re-resolving. Plus `NS_TAKEOVER\|` lines for unresolvable nameservers |
| `csp_matches_*.txt` | One handoff record per provider-published attribution: `domain\|ip\|provider\|region\|service\|prefix\|border_group`. One address can produce several records. Prefixed `WILDCARD\|` when the resolution was a catch-all. See [Cloud IP attribution](#cloud-ip-attribution) |
| `allocator-targets-v1.json` | Versioned provider-aware allocator handoff. Groups service, prefix, and border-group metadata per provider/hostname/address/region and excludes wildcard observations; one address may produce multiple records when a provider publishes multiple regions. |
| `environment_results_*.json` | Run metadata (command, external IP, Docker status) |
| `provider_catalogues.json` | AWS, GCP, and Azure catalogue status, source, retrieval time, snapshot identifier, and any failure reason |
| `{provider}_ip_ranges.json` | Validated provider ranges and provenance used by this run, from either a live source or a fresh cache |
| `evidence/dns/` | dig or nslookup output per flagged domain (when `--evidence` is set) |

Required output failures terminate the run instead of being logged and ignored.
`allocator-targets-v1.json` is cleared when a run starts and published with an
atomic replace only after processing succeeds, so a partial run cannot leave an
older actionable document looking current. Non-actionable partial files may
remain for diagnosis.

## AWS Lambda deployment

DNSResolver can run as an S3-triggered Lambda. The full deployment walkthrough (ECR image, IAM, triggers) lives in [`docs/LAMBDA.md`](docs/LAMBDA.md). Note: the maintained Lambda packaging is produced in a separate project; the handler here is the reference entry point.

## Architecture

```
resolver.py              — CLI entry point → run(env_manager)
lambda_handler.py        — Lambda entry point → run(env_manager)
    └── run()            — shared async pipeline (retry loop, concurrency cap)
├── EnvironmentManager       — CLI: argparse, config, logging, local file I/O
├── LambdaEnvironmentManager — Lambda: env vars, stdout logging, /tmp file I/O
├── DNSHandler               — async DNS resolution (aiodns primary, dnspython fallback)
│   ├── TakeoverDetector     — dangling CNAME detection, NS takeover checks, depth-limited CNAME chain following
│   ├── WildcardDetector     — per-zone wildcard DNS detection, cached probe results
│   └── EvidenceCollector    — async subprocess evidence capture (dig/nslookup)
├── DomainProcessingContext  — per-domain state (domain name, resolver, CSP IPs)
├── CSPIPAddresses           — value object holding fetched AWS/GCP/Azure IP ranges
├── DomainCategoriser        — regex-based classification of dangling CNAME targets
└── domain_processor.py     — orchestrates DNS → CSP checks per domain
```

Domain processing uses `asyncio.gather` with a `Semaphore` cap (`--max-threads`) to run many domains concurrently without exhausting file descriptors or triggering DNS rate limits. Failed domains are collected after each pass and retried up to `--retries` times.

`--timeout` applies to both the primary aiodns resolver and the dnspython fallback.
When multiple nameservers are configured, the complete list is supplied to both
resolver libraries so a failed resolver does not strand the entire run. A domain is written
to the unresolved output only after both resolvers fail on the final configured attempt.

## Cloud IP attribution

The current text files are the v2 CLI output. The versioned JSON handoff planned
for provider-aware allocators is defined separately in the
[allocator contract](docs/ALLOCATOR-CONTRACT.md); its schemas, examples, and
documentation field tables are validated together in CI.

Matching a resolved address to a cloud provider is only half an answer. `AWS` alone says
little: of roughly 10,500 published AWS prefixes, over half carry the generic `AMAZON` tag,
and the ones that matter operationally — `EC2` in a named region — look identical unless the
provider's own metadata is kept.

Each attribution is therefore written as a record carrying the provider's published region and
service. Providers can publish the same prefix under multiple services or regions, and an address
can fall within overlapping prefixes, so one address may produce several records:

```
domain|ip|provider|region|service|prefix|border_group
```

```
example.com|13.35.163.22|aws|GLOBAL|CLOUDFRONT|13.35.0.0/16|GLOBAL
example.com|3.11.53.7|aws|eu-west-2|EC2|3.8.0.0/14|eu-west-2
```

`border_group` is AWS's network border group: the boundary an Elastic IP is actually allocated
and advertised from. It usually mirrors the region, but differs for Local Zones and Wavelength —
which is precisely where the distinction matters. GCP and Azure publish no equivalent and it
reads `unknown` for them.

Records from a catch-all zone carry the same marker as the resolution output — `WILDCARD|` or
`WILDCARD_ZONE|`. In such a zone an address cannot be attributed to the domain rather than to the
hosting platform, so both are reported for completeness and excluded from the summary's target
counts.

The difference is the point: the first is a CDN edge address, the second an EC2 address in a
specific region. Both are "AWS"; only one is a meaningful target.

The end-of-run summary groups matches the same way:

```
  CSP matches — AWS: 6  GCP: 0  Azure: 0
    by region and service:
         4  aws  GLOBAL  CLOUDFRONT
         2  aws  GLOBAL  GLOBALACCELERATOR
```

Metadata is taken verbatim from each provider (AWS `region`/`service`, GCP `scope`/`service`,
Azure `region`/`systemService`). Where a provider publishes none, the fields read `unknown`
rather than being inferred. DNSResolver does not judge which addresses are worth pursuing —
it reports what the provider states and leaves that decision to the operator.

## Wildcard DNS detection

A zone serving a wildcard record (`*.example.com`) answers for **every** name beneath it. Against an
enumerated subdomain list that means thousands of "resolved" domains whose resolution proves
nothing, burying the findings that matter.

DNSResolver detects this automatically. For each zone it queries a couple of random labels that are
almost certainly not real (`<random-hex>.example.com`). If they resolve, the zone answers for
anything, and the addresses returned are recorded as the zone's wildcard set. Any domain resolving
*only* to addresses in that set is written with a `WILDCARD|` prefix:

```
WILDCARD|nonexistent-zz9x7q.github.io|185.199.108.153|185.199.109.153|...
www.example.com|203.0.113.10
```

The end-of-run summary reports the count separately:

```
  Resolved             :      4
    of which wildcard  :      2  (catch-all zone — resolution proves nothing)
```

Two verdicts are reported, because only one of the two questions is reliably answerable:

| Marker | Meaning |
|---|---|
| `WILDCARD` | Every address matched ones the probe observed — a confirmed catch-all answer. |
| `WILDCARD_ZONE` | The zone answers for anything, but these addresses were not among those sampled. Could be a catch-all served from a pool larger than the probe saw, or a genuine host — DNS cannot tell. |
| *(none)* | The zone does not answer for random names. Nothing is claimed. |

Whether a **zone** is wildcarded is always knowable, by probing random labels. Whether a
**particular answer** came from that wildcard often is not: a large rotating fleet serves
addresses a couple of probes never see. Reporting only the address-level test made such a
catch-all look like a clean result, so both facts are now reported separately.

Other notes:

- Results are cached per zone, so a scan costs one probe round per zone, not one per domain. Zones
  with no wildcard are probed once and then left completely untouched.
- Both IPv4 and IPv6 are probed, so a dual-stack catch-all is matched correctly.
- Cloud matches inside a catch-all zone carry the same marker and are excluded from target counts:
  an address there cannot be attributed to the domain rather than to the hosting platform.

## Configuration

`config.json` sets defaults for timeout, retries, output directory, and domain categorisation patterns used for classifying dangling CNAME targets (e.g. AWS S3, GitHub Pages, Heroku). CLI flags always override config file values.

## Cloud provider catalogue fetching

AWS, GCP, and Azure are all required inputs. Each live JSON request is retried up to three times,
then its structure and every CIDR are validated. A successful response is saved under
`<output-dir>/.provider_catalog_cache/` with its source URL, UTC retrieval time, and a SHA-256
snapshot identifier. AWS and GCP snapshots remain usable for 24 hours; Azure snapshots remain
usable for 14 days because Microsoft publishes that catalogue weekly.

If a live source fails, DNSResolver uses a still-fresh validated snapshot and marks that provider
`cached`. A missing, malformed, or stale snapshot makes the provider `failed`. Because a partial
provider set can turn real targets into false zero matches, DNSResolver then exits before reading
or resolving any domains. It writes the exact states and failure reasons to
`provider_catalogues.json`; it never silently skips a provider.

Microsoft's current Azure JSON URL is discovered from its confirmation page. If URL discovery
fails, DNSResolver tries `AZURE_PINNED_URL`; a successful pinned fetch is still a live, validated
catalogue. If both the current and pinned paths fail, the same freshness and fail-closed rules
apply.

### Keeping the Azure pinned URL current

`AZURE_PINNED_URL` is a module-level constant in `imports/cloud_ip_ranges.py`. When Microsoft
rotates the weekly file, update it:

```bash
# Find the current URL
python3 -c "
from urllib.request import urlopen; import re
with urlopen('https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519') as r:
    m = re.search(r'https://download\.microsoft\.com/download/[^\"]+\.json', r.read().decode())
    print(m.group(0) if m else 'not found')
"
```

Then update `AZURE_PINNED_URL` in `imports/cloud_ip_ranges.py` and commit.

Delete the corresponding file under `<output-dir>/.provider_catalog_cache/` only when deliberately
forcing a live refresh.

## Using with other tools

DNSResolver takes a flat domain list as input. The following external tools are useful for building that list before running a scan.

### Subdomain enumeration

**subfinder** (passive, fast):
```bash
subfinder -d example.com -silent | sort -u > domains.txt
python resolver.py domains.txt -o results --evidence -v
```

**amass** (active + passive, broader coverage):
```bash
amass enum -passive -d example.com -o domains.txt
python resolver.py domains.txt -o results --evidence -v
```

Multiple root domains can be combined into a single input file:
```bash
subfinder -d example.com -silent > domains.txt
subfinder -d related-company.com -silent >> domains.txt
sort -u -o domains.txt domains.txt
python resolver.py domains.txt -o results --evidence -v
```

### TLD and permutation variants

**dnstwist** generates typosquatting variants and TLD permutations (`example.com`, `example.com.sg`, `examp1e.com`, etc.) and filters to only registered ones:
```bash
dnstwist --registered example.com | awk 'NR>1 {print $2}' | sort -u > variants.txt
python resolver.py variants.txt -o results --evidence -v
```

### Finding related root domains

Corporate subsidiaries and related organisations often share infrastructure signals that can be used to build a broader root domain list before enumeration:

| Signal | How |
|--------|-----|
| Same SSL organisation name | Search [crt.sh](https://crt.sh) by org: `https://crt.sh/?o=Example+Corp` |
| Same ASN / IP block | `shodan search org:"Example Corp"` or [BGPView](https://bgpview.io) |
| Same Whois registrant | `whois example.com` — check registrant org/email |
| Broad OSINT | [SpiderFoot](https://github.com/smicallef/spiderfoot) automates the above signals |

Once related root domains are identified, enumerate subdomains for each and combine into a single input file as shown above.

## Roadmap

Active and completed work is tracked in **[ROADMAP.md](ROADMAP.md)**, with the findings that drive it
in [REVIEW.md](REVIEW.md) and per-item execution plans under [`docs/roadmap/`](docs/roadmap/).

Recent releases: consolidated output files, an actionable end-of-run summary, correct handling of
self-referential and non-existent CNAMEs, IPv6 (AAAA) resolution, and wildcard DNS detection.

## Known limitations

- **Resolution covers A and AAAA records.** Hosts reachable only via other record types are reported
  as unresolved.
- **Dangling-CNAME classification is first-match-wins** over the patterns in `config.json`, which are
  ordered specific to general. A target matching no pattern is reported as `unknown` rather than
  guessed at.
- **Inside a catch-all zone, a real host cannot be distinguished from the wildcard.** Every name
  resolves, so resolution carries no information either way. This is reported rather than guessed:
  `WILDCARD` marks a confirmed catch-all answer, `WILDCARD_ZONE` marks a zone that answers for
  anything where these particular addresses were not among those sampled. Separating a real host
  from a catch-all needs an HTTP request, which is out of scope.
- **A takeover candidate is only recorded when a CNAME actually exists.** A name that simply does not
  resolve is reported as unresolved, not as a candidate — there is nothing to claim.

## For AI agents

Working on this codebase with an AI agent? Two documents carry what the code does not say:

- **[`AGENTS.md`](AGENTS.md)** — what the tool is for, architecture, output contracts, and the
  conventions and traps that have already cost time here.
- **[`HANDOVER.md`](HANDOVER.md)** — a self-contained brief for an agent picking the project up
  cold, including the delivery standards and review method written out in full.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes
4. Push and open a Pull Request

> **Note:** Claude Code (claude-sonnet-4-6) has been used to help uplift this project for public release — security hardening, dependency audits, tooling, and documentation. Things should work, but in some cases the changes haven't been fully verified end-to-end. PRs and fixes are very welcome.
