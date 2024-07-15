Sure, here's a markdown-formatted `README.md` for your DNSResolver project. This file includes an overview, installation
instructions, usage, and a link to a demonstration video.

```markdown
# DNSResolver

DNSResolver is a Python-based tool designed to perform DNS resolution and check resolved IP addresses against known IP
ranges of major Cloud Service Providers (CSP) such as AWS, GCP, and Azure. It includes functionalities for domain
processing, logging, and evidence collection.

## Features

- DNS resolution for given domains
- IP range checking against known CSPs (AWS, GCP, Azure)
- Logging of results
- Evidence collection for resolved IPs

## Installation

To get started with DNSResolver, follow these steps:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/incendiary/DNSResolver.git
   cd DNSResolver
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

## Usage

DNSResolver can be run with various options to perform DNS resolution and check against CSP IP ranges.

### Basic Usage

```bash
python resolver.py -d domains.txt -o output
```

- `-d`: Path to the file containing the list of domains to be resolved.
- `-o`: Output directory where results will be saved.

### Advanced Options

- `-c`: Configuration file path (default: `config.json`).
- `-v`: Enable verbose logging.
- `-e`: Enable extreme logging.
- `-n`: Custom nameservers for DNS resolution.
- `-t`: Timeout for DNS queries.
- `-r`: Number of retries for DNS queries.
- `--evidence`: Enable evidence collection for resolved IPs.

### Example

```bash
python resolver.py -d domains.txt -o output --evidence -v -n 8.8.8.8,1.1.1.1 -t 2 -r 3
```

## Demonstration

For a quick demonstration of DNSResolver in action, watch the video below:

![DNSResolver Demo](Media/simplerun.gif)

## Contributing

We welcome contributions to DNSResolver. If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Create a new Pull Request.

