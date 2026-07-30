#!/usr/bin/env bash
#
# Build a domain list from certificate transparency logs via crt.sh.
#
# DNSResolver takes a flat domain list as input and does not enumerate
# subdomains itself. Certificate transparency is a passive way to build one.
#
# Usage:
#   helper/crtsh_domains.sh example.com > domains.txt
#   python resolver.py domains.txt -o results --evidence -v
#
# Notes:
#   - crt.sh is frequently slow or briefly unavailable; the script retries and
#     fails with a clear message rather than emitting a partial list.
#   - Wildcard entries (*.example.com) are reduced to the bare domain.
#   - For broader coverage, combine with subfinder or amass output:
#       helper/crtsh_domains.sh example.com >  domains.txt
#       subfinder -d example.com -silent    >> domains.txt
#       sort -u -o domains.txt domains.txt

set -euo pipefail

domain="${1:-}"
if [ -z "$domain" ]; then
    echo "usage: $(basename "$0") <root-domain>" >&2
    exit 2
fi

url="https://crt.sh/?q=%25.${domain}&output=json"

for attempt in 1 2 3; do
    response="$(curl -sS --max-time 90 "$url" 2>/dev/null || true)"

    # crt.sh returns an HTML error page (502/504) under load; JSON starts with '['
    case "$response" in
        \[*)
            printf '%s' "$response" | python3 -c '
import json, re, sys

# crt.sh returns certificate common names as well as hostnames, so entries like
# "as207960 test intermediate - example.com" appear. Keep only valid hostnames.
hostname = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,}$"
)

names = set()
for entry in json.load(sys.stdin):
    for name in entry.get("name_value", "").splitlines():
        name = name.strip().lstrip("*.").lower()
        if hostname.match(name):
            names.add(name)
for name in sorted(names):
    print(name)
'
            exit 0
            ;;
    esac

    [ "$attempt" -lt 3 ] && sleep 5
done

echo "crt.sh did not return JSON after 3 attempts (it is often briefly unavailable)." >&2
echo "Retry shortly, or use subfinder/amass to build the list instead." >&2
exit 1
