# PR-F — New DNS features (MEDIUM)

**Model:** Opus · **Release:** v1.12.0 (minor) · **Read [`AGENT-GUIDE.md`](AGENT-GUIDE.md) first.**

## Why this exists (context)

These are genuinely new capabilities **within the firm DNS-only boundary** (no HTTP/TLS/ports). They
add new logic and new output semantics with subtle correctness (wildcard behaviour, IPv6, takeover
signatures). That is the low-verifiability / medium-large-blast-radius quadrant, hence **Opus**: the
model is the safety net because a test suite can't fully prove DNS-edge correctness.

Each feature below is independently valuable — you may ship them as separate commits within this PR,
or split F3 into its own follow-up if research runs long. Do **not** bundle unrelated changes.

## Tasks

### F1 — Wildcard-DNS detection

**Problem.** If a zone has a wildcard record (`*.example.com` → some IP), then *every* enumerated
subdomain "resolves", producing large volumes of false-positive results and drowning real findings.
A red-team-grade tool should detect this and flag/annotate wildcard-driven resolutions.

**Approach (design before coding — this is why it's Opus):**
- Before/at the start of processing a root domain's subdomains, query a few random, almost-certainly
  non-existent labels (e.g. `<random-uuid>.example.com`) for A records.
- If they resolve, the zone is wildcarded; capture the wildcard IP set.
- Annotate or separate resolutions whose IPs match the wildcard set so users can distinguish "real
  host" from "wildcard catch-all". Decide the output representation (a new column/flag on
  `resolution_results`, or a dedicated note) and document it. Keep it backward compatible where
  reasonable, or bump minor and document the format change.
- Consider that input is a flat domain list (the tool does not enumerate) — so wildcard detection must
  derive the parent zone from each domain, and cache per-zone results to avoid re-probing.

**Success criteria:** with a mocked resolver simulating a wildcard zone, random-label queries are
detected and matching resolutions are annotated/separated; non-wildcard zones are unaffected; behaviour
is documented in README + `docs/`. Tests mock all DNS.
**Effort:** L.

### F2 — Record AAAA (IPv6) resolutions

**Problem.** `DNSHandler.resolve_domain_async` queries only `A` records. A host with only `AAAA`
(IPv6) records is currently reported as **unresolved**, which is inaccurate. (The maintainer considers
IPv6 low priority for takeover, but correct resolution reporting still matters.)

**Approach.** After (or alongside) the `A` query, also query `AAAA`; include IPv6 addresses in
`final_ips` (the CSP matcher already handles v6 via `is_ip_version`). Ensure a host with only AAAA is
reported resolved, not unresolved. Preserve the existing multi-IP pipe-delimited output format
(`domain|ip1|ip2|...`), now possibly including v6 addresses. Keep the takeover path unchanged.

**Success criteria:** mocked AAAA-only host → reported resolved with its v6 IPs; mixed A+AAAA host →
both families captured; existing A-only tests still pass. CSP v6 matching still works.
**Effort:** M.

### F3 — Extend takeover signatures (research-driven)

**Problem.** `config.json` has 60 `domain_categorisation` patterns. New takeover-prone services appear
over time; missing ones show as `unknown`.

**Approach.** Cross-reference a current public takeover fingerprint source (e.g. the community
"can-i-take-over-xyz" project — refer to it as `EdOverflow can-i-take-over-xyz`, **not** as a GitHub
shorthand, to avoid pingbacks) and add any well-established, currently-vulnerable services not already
covered. For each new pattern add: `regex`, `recommendation`, `evidence`. Keep the pattern order
specific → general (first match wins). Do not add speculative/unverified fingerprints.

**Success criteria:** new patterns have a test asserting a sample target string classifies to the new
category (not `unknown`); existing classifications unchanged; pattern count and additions noted in the
release.
**Effort:** M (bounded by research; timebox and ship what's verified).

## Release

Bump `VERSION`/`version.py` to `1.12.0` (minor — new capability). If F1's output format changes,
document it prominently in the release notes and README output table.
