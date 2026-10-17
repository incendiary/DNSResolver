# Matcher baseline

Measured with `bench/bench_matcher.py` on commit `9de9dcf` (before any speed-up).

Machine: macOS-27.0.1-arm64-arm-64bit, arm64, Python 3.12.15, 10 CPUs.
Catalogue: 54,940 synthetic prefixes (aws, azure, gcp; IPv4 /16 to /28, IPv6 /32 to /64), seed 14.
Workload: 20% of hostnames share 5 CDN addresses; of the rest, half match a prefix.

| Hostnames | Distinct addresses | Total (s) | Mean per distinct address (ms) | Max event-loop stall (ms) | Records |
|---|---|---|---|---|---|
| 1000 | 779 | 9.15 | 11.74 | 173.4 | 641 |
| 10000 | 7981 | 84.51 | 10.59 | 161.0 | 6336 |

N = 100,000 was not run (about 15 minutes at this rate).

Repeat run at N = 10,000: 84.15 s, 10.54 ms per distinct address, 160.9 ms stall (0.4% apart).

Reading the numbers:

- Steady state is about 9 to 10 ms per address, synchronous in the event loop. The first call
  adds a one-off 136 ms to parse every prefix (`parse_network` is memoised), which is the 160 to
  173 ms maximum stall; every later call stalls about 10 ms.
- Repeated addresses are not memoised: the 20% CDN share costs the full scan each time, so the
  per-hostname cost (8.45 ms) is below the per-distinct-address figure only because of that repeat.
- R-15 thresholds: more than 100 ms stall per address is exceeded only by the one-off warm-up
  (steady state is about 10 ms, under it); more than 60 s for 10,000 distinct addresses is
  exceeded (about 106 s extrapolated from 7,981 distinct at 84.5 s; 10,000 hostnames took 84.5 s).

## After R-15 (matcher speed-up)

Same machine, catalogue, seed and workload as above. Records are identical to the baseline at
every size shared (641 at N = 1,000; 6,336 at N = 10,000).

| Hostnames | Distinct | Before: total (s) / mean (ms) | Memoised, `da015ef`: total (s) / mean (ms) | Indexed (R-15 second commit): total (s) / mean (ms) | Indexed max stall (ms) |
|---|---|---|---|---|---|
| 1000 | 779 | 9.15 / 11.74 | 7.21 / 9.26 | 0.39 / 0.50 | 176.7 |
| 10000 | 7981 | 84.51 / 10.59 | 71.66 / 8.98 | 1.32 / 0.17 | 182.8 |
| 100000 | 79891 | not run | not run | 11.22 / 0.14 | 311.7 |

Memoisation alone left both thresholds exceeded (about 9 ms per distinct address; 71.7 s for
7,981 distinct addresses), so the prefixes are indexed: one dict per prefix length keyed by the
masked network address, probed once per length present. The remaining stall is the one-off parse
and index of all prefixes on the first call; steady state is well under 1 ms per address.
