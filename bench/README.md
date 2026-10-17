# Matcher benchmark

Times the real `perform_csp_checks` against a deterministic synthetic catalogue (about 55,000
prefixes, seed 14, generated in memory; no network, no provider data). It is not collected by
pytest (`testpaths = tests`).

```bash
.venv/bin/python bench/bench_matcher.py            # N = 1,000 and 10,000 (about 90 s)
.venv/bin/python bench/bench_matcher.py --n 1000   # one size
.venv/bin/python bench/bench_matcher.py --large    # adds N = 100,000 (about 15 min)
```

Output is a Markdown table; paste it into `BASELINE.md` with the machine and commit.
Hostnames are checked one at a time, yielding to the loop between calls, so the stall column is the
longest single synchronous call (plus the one-off prefix-parse warm-up on the first call).
