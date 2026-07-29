# DNSResolver

DNSResolver is a Python-based security tool for bulk DNS resolution and cloud infrastructure analysis. Given a list of domains it:

- Resolves DNS records and matches resolved IPs against known IP ranges for **AWS, GCP, and Azure**
- Detects **dangling CNAME** records pointing to unclaimed cloud resources (potential subdomain takeover)
- Detects **NS takeover** opportunities where nameservers are unresolvable
- Flags **wildcard DNS** zones so catch-all answers are not mistaken for real hosts
- Collects forensic evidence (dig/nslookup output) for flagged domains

All domain processing runs concurrently using `asyncio`, making it practical for large domain lists.

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

Each run creates a timestamped subdirectory under the output directory containing:

| File | Contents |
|------|----------|
| `resolution_results_*.txt` | Successfully resolved domains and their IPv4/IPv6 addresses, pipe-delimited (`domain\|ip1\|ip2`). Lines prefixed `WILDCARD\|` resolved only via a zone wildcard — see [Wildcard DNS detection](#wildcard-dns-detection) |
| `unresolved_results_*.txt` | Domains that could not be resolved after all retries |
| `takeover_candidates_*.txt` | Takeover candidates — `DANGLING\|` lines (dangling CNAMEs with category, recommendation, evidence) and `NS_TAKEOVER\|` lines (unresolvable nameservers) |
| `csp_matches_*.txt` | Domains resolving to cloud provider IP ranges (AWS, GCP, Azure — one line per match) |
| `environment_results_*.json` | Run metadata (command, external IP, Docker status) |
| `evidence/dns/` | dig or nslookup output per flagged domain (when `--evidence` is set) |

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

## Wildcard DNS detection

A zone serving a wildcard record (`*.example.com`) answers for **every** name beneath it. Against an
enumerated subdomain list that means thousands of "resolved" domains that are not real hosts, burying
the findings that matter.

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
    of which wildcard  :      2  (catch-all DNS — not real hosts)
```

Notes:

- A host resolving to any address **outside** the wildcard set is treated as real and is not flagged,
  even if it also shares one with the wildcard.
- Results are cached per zone, so a scan costs one probe round per zone, not one per domain. Zones
  with no wildcard are probed once and then left completely untouched.
- Both IPv4 and IPv6 are probed, so a dual-stack catch-all is matched correctly.
- Detection is DNS-only and cannot distinguish a real host from a wildcard when the host genuinely
  shares the wildcard's addresses — GitHub Pages sites are a common example, as they all resolve to
  the same set. Confirming those requires active probing, which is deliberately out of scope.

## Configuration

`config.json` sets defaults for timeout, retries, output directory, and domain categorisation patterns used for classifying dangling CNAME targets (e.g. AWS S3, GitHub Pages, Heroku). CLI flags always override config file values.

## Azure IP range fetching

Microsoft publishes Azure IP ranges via a confirmation page that redirects to a weekly-updated JSON file. The download URL changes every week, making a direct scrape fragile. DNSResolver uses a three-stage fallback chain so a broken confirmation page never silently disables Azure matching:

| Stage | Source | Behaviour |
|-------|--------|-----------|
| 1 | Microsoft confirmation page (live scrape) | Attempted first on every run. On success the result is written to `.azure_ip_cache.json` for future fallback. |
| 2 | `.azure_ip_cache.json` (local cache) | Used automatically if the scrape fails. A warning is printed. |
| 3 | `AZURE_PINNED_URL` (hardcoded fallback) | Used if no cache exists. Points to the latest known-good file at the time of the last release. A warning is printed. |
| — | Exhausted | If all three sources fail, a clear error is printed and Azure matching is skipped for the run. |

### Keeping the pinned URL current

`AZURE_PINNED_URL` is a module-level constant at the top of `imports/cloud_ip_ranges.py`. When Microsoft rotates the weekly file and the cache ages, update it:

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

### Cache file

`.azure_ip_cache.json` is written to the working directory on every successful fetch and is excluded from version control via `.gitignore`. Delete it to force a fresh fetch on the next run.

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
- **Wildcard detection cannot separate a real host from a catch-all** when the host genuinely shares
  the wildcard's addresses (GitHub Pages is the common case). Confirming those requires active
  probing, which is out of scope.
- **A takeover candidate is only recorded when a CNAME actually exists.** A name that simply does not
  resolve is reported as unresolved, not as a candidate — there is nothing to claim.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes
4. Push and open a Pull Request

> **Note:** Claude Code (claude-sonnet-4-6) has been used to help uplift this project for public release — security hardening, dependency audits, tooling, and documentation. Things should work, but in some cases the changes haven't been fully verified end-to-end. PRs and fixes are very welcome.
