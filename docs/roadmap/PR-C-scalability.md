# PR-C — Scalability (MEDIUM)

**Model:** Sonnet · **Release:** v1.11.1 (patch) · **Read [`AGENT-GUIDE.md`](AGENT-GUIDE.md) first.**

## Why this exists (context)

The README sells the tool as "practical for large domain lists." Two hot-path inefficiencies undercut
that at scale. Neither is a correctness bug today; both are performance cliffs that appear on
full-organisation enumerations. **The refactor must not change which IPs match which vendor** — this is
the "wrong but green" risk: a perf change that silently drops a match. Guard it with a correctness test.

## Tasks

### C1 — Pre-build CSP networks once, not per IP

**The problem.** `imports/cloud_service_provider_checks.py::match_ip_with_vendors` does, for every
resolved IP, for every vendor, for every CIDR string:
```python
if ip_obj in ipaddress.ip_network(ip_range):
```
`ipaddress.ip_network(ip_range)` re-parses the CIDR string **every time**. AWS publishes ~7,000
prefixes and Azure ~60,000. For N resolved IPs this is N × ~70,000 string-parses per run. The prefix
lists are fixed for the whole run.

**The fix (keep it simple).** Parse each vendor's ranges into `ip_network` objects **once**, when the
ranges are first available, and reuse them. Options, simplest first:
- Convert the vendor range lists to parsed-network lists a single time before the per-domain loop, and
  pass those through instead of raw strings; or
- Memoise parsing with `functools.lru_cache` on a helper `parse_network(cidr)` so each unique CIDR is
  parsed once.

Do not introduce a new dependency (no `pytricia`) in this PR — that is a possible future optimisation,
but the one-time-parse change captures most of the win with zero new deps and low risk. Preserve the
existing `ValueError` handling for malformed ranges (log and skip).

**Success criteria:**
- No behavioural change: add/extend a test with a **known** IP inside a **known** vendor CIDR and a
  known IP outside all ranges; assert the exact `{vendor: [ip]}` match result is identical before and
  after. (This is the anti-"wrong but green" gate.)
- A CIDR is parsed at most once per run (demonstrate via the memoised helper's `cache_info()`, or by
  structure — parsed list built once).
- Suite green; coverage ≥ prior.

**Files to change:** `imports/cloud_service_provider_checks.py`, `tests/test_cloud_service_provider_checks.py`.
**Effort:** M.

### C2 — Replace whole-file-read dedupe with an in-memory set

**The problem.** `log_and_write` (same file, ~line 88) dedupes by reading the **entire** CSP output
file on every write and doing a substring check:
```python
if os.path.exists(file_path):
    with open(file_path, "r", ...) as file:
        if message in file.read():
            return False
```
This is O(n²) over a run (each write re-reads all prior output) and the substring check can
false-dedupe (one line being a substring of another). It is also a **blocking** file read inside the
async event loop.

**The fix.** Track written CSP lines in an in-memory `set` for the lifetime of the run and check
membership instead of reading the file. The natural owner is the object that already spans the run —
prefer the `OutputManager` (it owns writes) or a small set carried on the env manager. Keep the actual
append write; just replace the *dedupe check*. Exact-line membership fixes both the O(n²) cost and the
substring false-positive.

**Success criteria:**
- Writing the same `(domain, vendor, ips)` line twice results in a single line in the file; a
  different line is not suppressed by being a substring of an existing one — assert both in a test.
- No full-file read remains in `log_and_write`.
- Suite green.

**Files to change:** `imports/cloud_service_provider_checks.py` (+ wherever the set is owned),
`tests/test_cloud_service_provider_checks.py`.
**Effort:** M.

## Notes for the implementer

- Both changes are in the same file and same nature (CSP-matching performance) → one PR.
- If C2's ownership question is unclear, keep it minimal: a module-level or run-scoped set threaded
  through the existing call signature is acceptable; do not over-engineer a caching layer.
- If you find the change rippling into many files or needing an interface change, stop and report —
  that is a sign to escalate the design decision rather than push a wide change.

## Release

Bump `VERSION`/`version.py` to `1.11.1`.
