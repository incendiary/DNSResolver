# DNSResolver

DNSResolver is a Python-based security tool for bulk DNS resolution and cloud infrastructure analysis. Given a list of domains it:

- Resolves DNS records and matches resolved IPs against known IP ranges for **AWS, GCP, and Azure**
- Detects **dangling CNAME** records pointing to unclaimed cloud resources (potential subdomain takeover)
- Detects **NS takeover** opportunities where nameservers are unresolvable
- Collects forensic evidence (dig/nslookup output) for flagged domains

All domain processing runs concurrently using `asyncio`, making it practical for large domain lists.

> **v1.1.0 scope change:** Service connectivity checks (HTTP probing, TLS/SSL certificate validation, TCP port scanning, and Selenium screenshots) have been removed. These features introduced a heavy browser dependency, made active connections to every resolved domain, and were out of scope for a DNS-focused tool. The core mission is DNS resolution, cloud IP matching, and subdomain takeover detection.

## Demonstration

![DNSResolver Demo](Media/simplerun.gif)

## Installation

```bash
git clone https://github.com/incendiary/DNSResolver.git
cd DNSResolver
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
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
| `dangling_cname_results_*.txt` | Domains with dangling CNAMEs — category, recommendation, and evidence link |
| `ns_takeover_results_*.txt` | Domains with potentially unresolvable nameservers |
| `gcp_results_*.txt` | Domains resolving to GCP IP ranges |
| `aws_results_*.txt` | Domains resolving to AWS IP ranges |
| `azure_results_*.txt` | Domains resolving to Azure IP ranges |
| `environment_results_*.json` | Run metadata (command, external IP, Docker status) |
| `evidence/dns/` | dig or nslookup output per flagged domain (when `--evidence` is set) |

## Architecture

```
resolver.py          — asyncio entry point, retry loop, concurrency cap
├── EnvironmentManager   — argument parsing, config, logging, output setup
├── DNSHandler           — async DNS resolution (aiodns primary, dnspython fallback)
│   └── EvidenceCollector — async subprocess evidence capture (dig/nslookup)
├── DomainProcessingContext — per-domain state (domain name, resolver, CSP IPs)
├── CSPIPAddresses       — value object holding fetched AWS/GCP/Azure IP ranges
└── domain_processor.py  — orchestrates DNS → CSP checks per domain
```

Domain processing uses `asyncio.gather` with a `Semaphore` cap (`--max-threads`) to run many domains concurrently without exhausting file descriptors or triggering DNS rate limits. Failed domains are collected after each pass and retried up to `--retries` times.

## Configuration

`config.json` sets defaults for timeout, retries, output directory, and domain categorisation patterns used for classifying dangling CNAME targets (e.g. AWS S3, GitHub Pages, Heroku). CLI flags always override config file values.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes
4. Push and open a Pull Request
