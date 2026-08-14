# External acceptance for cloud attribution

This is the handoff for an agent running on a host that can reach provider
catalogue endpoints over HTTPS and public DNS resolvers over UDP/TCP port 53.
It complements the mocked automated suite; it is deliberately not a pytest
test because repository tests must never make real DNS or HTTP requests.

## Copy/paste prompt

```text
Take over the live acceptance of DNSResolver cloud attribution. Work from the
current pull-request branch; do not modify code unless a failed acceptance check
identifies a reproducible defect. Do not push to main, tag a release, bump
VERSION, or use real client/employer names. Use only public example/test domains
and provider-owned service names.

Read HANDOVER.md and AGENTS.md before running anything. Then:

1. Record `git status --short --branch` and the exact commit SHA. Stop if the
   checkout contains unrelated changes.
2. Install both requirements files in Python 3.12 and run the repository's local
   gates exactly:
   `.venv/bin/ruff check .`
   `.venv/bin/ruff format --check .`
   `.venv/bin/pytest tests/baseline/ -v`
   `.venv/bin/pytest --cov=classes --cov=imports --cov-report=term-missing`
3. Run the focused attribution tests:
   `.venv/bin/pytest -q tests/test_allocator_contract.py tests/test_allocator_publisher.py tests/test_cloud_ip_ranges.py tests/test_cloud_service_provider_checks.py tests/test_csp_ip_addresses.py tests/test_resolver.py`
4. Run DNSResolver through its production CLI against a small file containing
   public, provider-owned names. Include `s3.amazonaws.com`, which previously
   resolved through the host's system resolver. Use a temporary config with no
   `nameservers` key for the system-resolver run; the checked-in config supplies
   explicit public resolvers and is not a system-resolver control.
5. Repeat the run with `--nameservers 1.1.1.1,8.8.8.8`. This explicit-resolver
   check is mandatory on your host because the originating agent's execution
   environment blocked direct public DNS. Capture whether UDP and TCP port 53
   work, rather than treating a timeout as a DNSResolver defect.
6. For every successful production run, verify:
   - `provider_catalogues.json` marks aws, gcp, and azure usable and records a
     source, retrieval time, and snapshot identifier;
   - `csp_matches_*.txt` retains every provider-published attribution for each
     matched address, including repeated services, overlapping prefixes, or
     multiple regions when present;
   - `allocator-targets-v1.json` validates against
     `contracts/allocator-targets-v1.schema.json`;
   - every JSON target has `actionability: actionable`, a provider in aws/gcp/
     azure, a non-empty provider-published region, and prefixes containing its IP;
   - no `WILDCARD` or `WILDCARD_ZONE` observation enters the allocator document.
7. If the allocator checkout is available, feed the produced JSON to the real
   consumer. Confirm AWS is accepted unchanged. Confirm GCP and Azure are routed
   only to provider-aware implementations or are explicitly rejected; they must
   never be sent through the AWS allocation path.
8. Report results as four separate evidence classes: automated tests, live
   provider catalogue retrieval, system-resolver DNS, and explicit-public-
   resolver DNS. Include commands, exit codes, output paths, redacted excerpts,
   and the commit SHA. Do not describe a blocked or skipped check as passing.

Success means all automated checks pass, all three catalogues are usable, at
least one real DNS answer traverses the production pipeline into a schema-valid
allocator document, and the explicit public-resolver result is evidenced. Real
allocator compatibility is a separate result: passed, failed, or unavailable.
```

## Evidence expected back

- Commit SHA and clean/dirty status.
- Python and dependency versions.
- Test counts and coverage.
- Catalogue status for AWS, GCP, and Azure.
- System-resolver and explicit-resolver commands and exit codes.
- The relevant pipe records and corresponding allocator JSON records.
- JSON Schema validation result.
- Allocator-consumer result, or a precise statement that its checkout was not
  available.
- Any failure separated into product defect, network/environment limitation, or
  unavailable external dependency.

