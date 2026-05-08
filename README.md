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

## AWS Lambda deployment

DNSResolver can run as a Lambda function triggered by an S3 PutObject event. Upload a domains file to the input bucket to start a run; results are written back to S3 when it completes.

### Design decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Packaging | Container image | `pycares` bundles a native C extension — container images avoid the manylinux wheel compatibility issues that affect Lambda layers |
| Architecture | arm64 (Graviton) | ~20% cheaper than x86_64 for equivalent workloads; change `FROM` line in Dockerfile for x86_64 |
| Runtime | Python 3.12 | Latest Lambda-supported version |
| Logging | stdout only | Lambda captures stdout to CloudWatch automatically; no log file is written |
| Evidence collection | Disabled | `dig` and `nslookup` are not available in the Lambda runtime |
| Intermediate storage | `/tmp` | Lambda provides up to 10 GB of ephemeral storage; results are uploaded to S3 at the end of the run |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OUTPUT_BUCKET` | input bucket | S3 bucket for results |
| `OUTPUT_PREFIX` | `results/` | S3 key prefix for results |
| `NAMESERVERS` | system resolvers | Comma-separated custom resolvers, e.g. `8.8.8.8,1.1.1.1` |
| `MAX_THREADS` | `50` | Concurrent domain tasks |
| `TIMEOUT` | from `config.json` | DNS query timeout in seconds |
| `RETRIES` | from `config.json` | Retry attempts for failed domains |
| `VERBOSE` | `false` | Set to `true` for verbose CloudWatch logging |

### IAM permissions

The Lambda execution role needs:
- `s3:GetObject` on the input bucket
- `s3:PutObject` on the output bucket

### Build and deploy

```bash
# Build (cross-compile for arm64 from an x86 machine if needed)
docker build --platform linux/arm64 -t dnsresolver-lambda .

# Push to ECR
aws ecr get-login-password --region <region> \
  | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
docker tag dnsresolver-lambda <account>.dkr.ecr.<region>.amazonaws.com/dnsresolver-lambda:latest
docker push <account>.dkr.ecr.<region>.amazonaws.com/dnsresolver-lambda:latest
```

### Trigger configuration

Configure an S3 event notification on the input bucket for `s3:ObjectCreated:*` events, filtered to the prefix where you drop domain files (e.g. `domains/`). The Lambda handler reads the bucket and key from the event record automatically.

### Pipeline integration

```
EventBridge (daily cron)
    → ECS Fargate task (subfinder/amass enumeration)
        → S3: domains/domains.txt          ← triggers Lambda
            → Lambda (DNSResolver)
                → S3: results/<timestamp>/
                    → downstream Lambda (claim dangling resources)
```

## Architecture

```
resolver.py              — CLI entry point → run(env_manager)
lambda_handler.py        — Lambda entry point → run(env_manager)
    └── run()            — shared async pipeline (retry loop, concurrency cap)
├── EnvironmentManager       — CLI: argparse, config, logging, local file I/O
├── LambdaEnvironmentManager — Lambda: env vars, stdout logging, /tmp file I/O
├── DNSHandler               — async DNS resolution (aiodns primary, dnspython fallback)
│   └── EvidenceCollector     — async subprocess evidence capture (dig/nslookup)
├── DomainProcessingContext   — per-domain state (domain name, resolver, CSP IPs)
├── CSPIPAddresses            — value object holding fetched AWS/GCP/Azure IP ranges
└── domain_processor.py  — orchestrates DNS → CSP checks per domain
```

Domain processing uses `asyncio.gather` with a `Semaphore` cap (`--max-threads`) to run many domains concurrently without exhausting file descriptors or triggering DNS rate limits. Failed domains are collected after each pass and retried up to `--retries` times.

## Configuration

`config.json` sets defaults for timeout, retries, output directory, and domain categorisation patterns used for classifying dangling CNAME targets (e.g. AWS S3, GitHub Pages, Heroku). CLI flags always override config file values.

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

| Issue | Description |
|-------|-------------|
| [#36](https://github.com/incendiary/DNSResolver/issues/36) | **Progress bar stability** — route log output through `tqdm.write()` so the progress bar stays locked to the bottom of the terminal during verbose runs |
| [#37](https://github.com/incendiary/DNSResolver/issues/37) | **AWS Lambda / S3 support** — abstract the I/O layer and add a `lambda_handler.py` entrypoint so DNSResolver can run inside a Lambda pipeline (domains in from S3, results out to S3) without duplicating any resolution logic |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes
4. Push and open a Pull Request
