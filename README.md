# DNSResolver

DNSResolver is a script designed to perform DNS resolution for a list of domains. It supports using the system DNS resolver or custom resolvers provided by the user. The script handles timeouts and retries, ensuring robust domain resolution.

## Features

- Read domains from an input file.
- Use system DNS resolver or custom resolvers provided via a CSV file or command-line input.
- Retry DNS resolution for domains that timeout.
- Write successful resolutions to an output file.
- Write failed resolutions to a timeout file after exhausting retries.


## Usage

Parameters:

- domains_file: Path to a file containing list of domains to be resolved.


Options:
- -o, --output-dir: Directory to save output files (default is output).
- -v, --verbose: Enable verbose mode to display more detailed information.
- -e, --extreme: Enable extreme mode to display extensive information including IP ranges.
- -r, --resolvers: Comma-separated list of custom DNS resolvers overriding the system resolvers.
- -sc, --service-checks: Enable to perform Service Checks.
- -mt, --max-threads: Max number of threads to use for domain processing (default is 10).
- -t, --timeout: Timeout for DNS resolution process in seconds (default is 10 seconds).
