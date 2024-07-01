### Project Overview

The `DNSResolver` project is a script that performs DNS resolution for a list of domains, optionally using custom resolvers, and handles timeouts and failures. The main functionalities include:
1. Reading domains from an input file.
2. Using the system DNS resolver or a list of custom resolvers provided via a CSV file or command-line input.
3. Writing successful resolutions to an output file.
4. Writing failed resolutions (due to timeouts) to a timeout file.

### Suggested README in Markdown

Here's a suggested README for your project:

```markdown
# DNSResolver

DNSResolver is a script designed to perform DNS resolution for a list of domains. It supports using the system DNS resolver or custom resolvers provided by the user. The script handles timeouts and retries, ensuring robust domain resolution.

## Features

- Read domains from an input file.
- Use system DNS resolver or custom resolvers provided via a CSV file or command-line input.
- Retry DNS resolution for domains that timeout.
- Write successful resolutions to an output file.
- Write failed resolutions to a timeout file after exhausting retries.

## Installation

Clone the repository:

```bash
git clone https://github.com/incendiary/DNSResolver.git
cd DNSResolver
```

## Usage

```bash
python dns_resolver.py -i input_file.txt -o output_file.txt -t timeout_file.txt [-r resolver1,resolver2,...] [-c custom_resolvers.csv] [--retries N]
```

- `-i`: Path to the input file containing domains.
- `-o`: Path to the output file for successful resolutions.
- `-t`: Path to the timeout file for failed resolutions after retries.
- `-r`: Comma-separated list of custom resolvers (optional).
- `-c`: Path to a CSV file containing custom resolvers (optional).
- `--retries`: Number of retry attempts for timeouts (optional, default is 3).

## Example

```bash
python dns_resolver.py -i domains.txt -o resolved.txt -t timeouts.txt -r 8.8.8.8,8.8.4.4 --retries 5
```

This command resolves domains from `domains.txt`, writes successful resolutions to `resolved.txt`, retries up to 5 times for timeouts, and writes unresolved domains after retries to `timeouts.txt`.
