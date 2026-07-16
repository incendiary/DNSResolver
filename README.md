# DNSResolver

DNSResolver is a Python-based security tool for bulk DNS resolution and cloud infrastructure analysis. Given a list of domains it:

- Resolves DNS records and matches resolved IPs against known IP ranges for **AWS, GCP, and Azure**
- Detects **dangling CNAME** records pointing to unclaimed cloud resources (potential subdomain takeover)
- Detects **NS takeover** opportunities where nameservers are unresolvable
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

DNSResolver takes a flat list of domains as input — it does not enumerate subdomains itself. A quick way to build one passively is to query certificate transparency logs via [crt.sh](https://crt.sh):

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | python3 -c "import json,sys; names=set(); [names.update(e['name_value'].split('\n')) for e in json.load(sys.stdin)]; [print(n.lstrip('*.')) for n in sorted(names)]" \
  | sort -u > domains.txt

python resolver.py domains.txt -o results --evidence -v --nameservers 8.8.8.8,1.1.1.1 --timeout 5 --retries 2
```

Replace `example.com` with the root domain you are assessing. For more comprehensive subdomain discovery, tools such as `subfinder` or `amass` can be used to generate the input list.

## Output

Each run creates a timestamped subdirectory under the output directory containing:

| File | Contents |
|------|----------|
| `resolution_results_*.txt` | Successfully resolved domains and their DNS records |
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
│   └── EvidenceCollector    — async subprocess evidence capture (dig/nslookup)
├── DomainProcessingContext  — per-domain state (domain name, resolver, CSP IPs)
├── CSPIPAddresses           — value object holding fetched AWS/GCP/Azure IP ranges
├── DomainCategoriser        — regex-based classification of dangling CNAME targets
└── domain_processor.py     — orchestrates DNS → CSP checks per domain
```

Domain processing uses `asyncio.gather` with a `Semaphore` cap (`--max-threads`) to run many domains concurrently without exhausting file descriptors or triggering DNS rate limits. Failed domains are collected after each pass and retried up to `--retries` times.

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

| Issue | Status | Description |
|-------|--------|-------------|
| [#36](https://github.com/incendiary/DNSResolver/issues/36) | ✅ | Progress bar stability — log output routed through `tqdm.write()` |
| [#37](https://github.com/incendiary/DNSResolver/issues/37) | ✅ | AWS Lambda / S3 support — `lambda_handler.py` entrypoint with S3 I/O |
| [#41](https://github.com/incendiary/DNSResolver/issues/41) | ✅ | Refactor `EnvironmentManager` — `ConfigResolver` + `OutputManager` split; trivial getters replaced with direct attribute access |
| [#42](https://github.com/incendiary/DNSResolver/issues/42) | ✅ | Enforce code style with Black, isort, flake8, and pre-commit hooks |
| [#43](https://github.com/incendiary/DNSResolver/issues/43) | ✅ | Refactor `DNSHandler` — split resolution, takeover detection, and categorisation into focused classes |
| [#48](https://github.com/incendiary/DNSResolver/issues/48) | ✅ | End-of-run summary — at-a-glance verdict with prominently flagged takeover candidates |
| [#50](https://github.com/incendiary/DNSResolver/issues/50) | ✅ | Code review and refactoring pass — surgical changes, simplicity-first, no speculative abstractions |
| [#52](https://github.com/incendiary/DNSResolver/issues/52) | ✅ | Refine run summary — elevate classified takeover candidates |
| [#54](https://github.com/incendiary/DNSResolver/issues/54) | ✅ | Expand domain categorisation patterns — add 11 missing takeover services |
| [#56](https://github.com/incendiary/DNSResolver/issues/56) | ✅ | Formal git history secret scan |
| [#57](https://github.com/incendiary/DNSResolver/issues/57) | ✅ | Dependency audit — pip-audit against all requirements files |
| [#60](https://github.com/incendiary/DNSResolver/issues/60) | ✅ | GitHub Actions CI — flake8 + pytest on Python 3.12 for all PRs and pushes to main |
| [#61](https://github.com/incendiary/DNSResolver/issues/61) | ✅ | pre-commit: gitleaks hook; CVE-fixed black revision |
| [#63](https://github.com/incendiary/DNSResolver/issues/63) | ✅ | Dead code removal — unreachable guards in `cloud_service_provider_checks` and `config_resolver` |
| [#64](https://github.com/incendiary/DNSResolver/issues/64) | ✅ | Deduplicate GCP / AWS IP range fetch into a shared helper |
| [#65](https://github.com/incendiary/DNSResolver/issues/65) | ✅ | Strip what-not-why docstrings from `cloud_ip_ranges.py` |
| [#66](https://github.com/incendiary/DNSResolver/issues/66) | ✅ | Branch protection — require CI status check to pass before merge |
| [#72](https://github.com/incendiary/DNSResolver/issues/72) | ✅ | Bug: double retry loop — domains retried retries² times |
| [#73](https://github.com/incendiary/DNSResolver/issues/73) | ✅ | Bug: unbounded CNAME recursion — depth limit added |
| [#74](https://github.com/incendiary/DNSResolver/issues/74) | ✅ | Bug: concurrent write race in `log_and_write` — investigated, not a real bug in asyncio cooperative model |
| [#75](https://github.com/incendiary/DNSResolver/issues/75) | ✅ | Bug: `asyncio.get_event_loop()` deprecated — replaced with `get_running_loop()` |
| [#76](https://github.com/incendiary/DNSResolver/issues/76) | ✅ | Dead code: `is_dangling_record_async` defined but never called — removed |
| [#79](https://github.com/incendiary/DNSResolver/issues/79) | ✅ | Bug: Azure IP range fetch brittle — three-stage fallback chain added |
| [#80](https://github.com/incendiary/DNSResolver/issues/80) | ✅ | Bug: dangling CNAMEs to AWS ELB classified as unknown — `aws_elb` pattern added |
| [#82](https://github.com/incendiary/DNSResolver/issues/82) | ✅ v1.10.0 | Consolidate output files: 7 text files → 4 — `csp_matches_*.txt` and `takeover_candidates_*.txt` |
| [#85](https://github.com/incendiary/DNSResolver/issues/85) | ✅ v1.10.1 | Run summary: all takeover candidates shown with CNAME target, risk, and recommended action |
| [#87](https://github.com/incendiary/DNSResolver/issues/87) | ✅ v1.10.2 | Version string — printed at startup and in run summary; `--version` flag added |
| [#89](https://github.com/incendiary/DNSResolver/issues/89) | ✅ v1.10.3 | Self-referential CNAMEs classified as `self_referential` (misconfiguration) not takeover candidates |
| [#91](https://github.com/incendiary/DNSResolver/issues/91) | ✅ v1.10.4 | README: fix venv path, add `--version` to options table, update architecture diagram, clean roadmap |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes
4. Push and open a Pull Request

> **Note:** Claude Code (claude-sonnet-4-6) has been used to help uplift this project for public release — security hardening, dependency audits, tooling, and documentation. Things should work, but in some cases the changes haven't been fully verified end-to-end. PRs and fixes are very welcome.
