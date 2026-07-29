# PR-B — Reliability hardening (HIGH)

**Model:** Sonnet · **Release:** v1.10.6 (patch) · **Read [`AGENT-GUIDE.md`](AGENT-GUIDE.md) first.**

## Why this exists (context)

Two independent reliability defects, both cheap to fix, both worth a regression test.

> **Model note:** B3 (below) is a subtle classification-logic fix with recursion involved — if the
> loop-detection turns out non-trivial, escalate B3 to Opus and split it into its own PR. B1/B2 stay
> Sonnet.

## Tasks

### B3 — Fix the self-referential CNAME misclassification (found by the live run)

**The bug (highest correctness impact in this PR).** `classes/takeover_detector.py`, in
`check_dangling_cname_async` (~line 139):
```python
if current_domain.rstrip(".") == original_domain.rstrip("."):
    category = "self_referential"
    recommendation = "Remove or correct the CNAME — the domain points to itself ..."
```
This function is first entered with `current_domain == original_domain` (depth 0, from
`handle_takeover_checks`). So for **any** domain that has no CNAME, no A/AAAA/MX, and no NS — i.e. a
plain dead/NXDOMAIN name — the branch is trivially true and the domain is labelled `self_referential`
"points to itself", which is factually wrong (it has no CNAME at all).

**Evidence.** The authorised live run (2026-07-15) flagged 9/9 non-resolving hosts as
`self_referential`. `dig +short @8.8.8.8 <host> A` and `... CNAME` return nothing for all of them —
they are NXDOMAIN with no CNAME, not self-referential.

**Intended behaviour (#89).** `self_referential` should fire **only** when a CNAME chain actually
loops back to the original domain (e.g. `x.example.com` CNAME → `x.example.com`), which can only be
observed after following at least one CNAME (`depth > 0`).

**The fix.**
- Gate the self-referential branch on **`depth > 0`** AND `current == original`. At depth 0 (no CNAME
  followed), fall through to normal `DomainCategoriser` classification.
- Be careful with true self-looping CNAMEs: following a self CNAME recurses until `MAX_CNAME_DEPTH`
  and returns `False` today. If you want the self-referential label to actually trigger for a real
  loop, detect the loop explicitly — track visited names in the recursion and, when the next target
  is already visited (or equals the original), stop and classify as `self_referential`. Keep this
  minimal; do not rewrite the whole function.
- Preserve all existing non-self-referential behaviour.

**Success criteria (assert real outcomes — this is a "wrong but green" sensitive area):**
- New test: a domain that is NXDOMAIN with **no CNAME** → written category is **not**
  `self_referential` (it should be the normal `DomainCategoriser` result, e.g. `unknown`). This is
  the regression lock for the live-run bug.
- New test: a domain whose CNAME points back to itself (mock the resolver to return a self CNAME) →
  category **is** `self_referential`.
- Existing takeover tests still pass unchanged.
- Re-run the equivalent of the live scenario (mocked) and confirm dead hosts are no longer labelled
  self-referential.

**Files to change:** `classes/takeover_detector.py`, `tests/test_dns_handler.py` (or a dedicated
`tests/test_takeover_detector.py`).
**Effort:** M (subtle — see model note; escalate to Opus if loop-detection grows).

### B1 — Remove the `sys.exit(1)` from the Azure fetch

**The bug.** `imports/cloud_ip_ranges.py`, function `fetch_ip_ranges_for_azure` (around line 46-48):
```python
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the IP ranges: {e}")
        sys.exit(1)
```
This kills the **entire process** on any network hiccup contacting the Azure download host. That is
catastrophic during a long scan: all resolution and takeover results gathered so far are lost. Worse,
this function is called *inside the three-stage fallback chain* that exists specifically to survive
Azure being unreachable (`fetch_azure_ip_ranges` calls it for both the scraped URL and the pinned
fallback). So the "resilient" path can itself hard-exit.

The sibling function `fetch_ip_ranges` (used for AWS/GCP) already does the right thing: it prints and
returns `[], []`. Make Azure match.

**The fix.** Replace `sys.exit(1)` with `return [], []`. The callers already handle `([], [])`
(they try the next fallback stage, then skip Azure with a clear message). Confirm `sys` is still used
elsewhere in the file before removing the import — it **is** used by other paths, so **keep the
import** unless a lint check says it's now unused (ruff will tell you).

**Success criteria:**
- `fetch_ip_ranges_for_azure` never calls `sys.exit`. Grep confirms: `grep -n "sys.exit" imports/cloud_ip_ranges.py` shows no hit inside that function.
- New unit test: patch `requests.get` to raise `requests.exceptions.RequestException`; assert the
  function returns `([], [])` and does **not** raise `SystemExit`. (This is the regression lock; it
  also belongs to PR-D's coverage goal — write it here.)
- Full suite green; coverage ≥ prior.

**Files to change:** `imports/cloud_ip_ranges.py`, `tests/test_cloud_ip_ranges.py`.
**Effort:** S.

### B2 — Remove the orphan `timeout` output file

**The bug.** `classes/output_manager.py` `_build_output_files` still creates:
```python
                "timeout": os.path.join(d, f"timeout_results_{timestamp}.txt"),
```
Nothing ever writes to the `"timeout"` key (verified: no writer references
`output_files["standard"]["timeout"]`). The consolidation in issue #82 (7 files → 4) left this behind.
Result: every run produces an empty `timeout_results_*.txt`, which contradicts the README's documented
4-file output and confuses users triaging results.

**The fix.** Remove the `"timeout"` entry from the dict. Do **not** touch the `"timeout"` *config
value* in `config_resolver`/`lambda_environment_manager` — that is the DNS query timeout setting, an
unrelated concept. Only the output-file entry goes.

**Success criteria:**
- A fresh run produces exactly: `resolution_results_*.txt`, `unresolved_results_*.txt`,
  `csp_matches_*.txt`, `takeover_candidates_*.txt`, `environment_results_*.json` (+ `evidence/dns/`
  when `--evidence`). No `timeout_results_*.txt`.
- Existing `tests/` still pass; if any test asserts the `"timeout"` key exists, update it to reflect
  the removal (search: `grep -rn "timeout_results\|\"timeout\"" tests/`).
- README output table already omits `timeout` — no README change needed; verify it stays accurate.

**Files to change:** `classes/output_manager.py`, possibly a test asserting output keys.
**Effort:** XS.

## Release

Bump `VERSION`/`version.py` to `1.10.6`. All three fixes are same-nature (correctness / run-time
robustness), so they ship together as one patch. Lead the release notes with B3 (the self-referential
misclassification) as it has the most operator impact. If B3 is split out to its own Opus PR, ship
B1+B2 as `1.10.6` and B3 as `1.10.7`.
