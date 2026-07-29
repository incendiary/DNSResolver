# DNSResolver execution plans

Detailed, self-contained plans for each roadmap PR. Written so an agent (or human) can execute one
group independently without re-reading the whole review.

## Start here
1. **[AGENT-GUIDE.md](AGENT-GUIDE.md)** — mandatory. Environment setup, branch/commit rules, the local
   CI gate, testing rules, definition of done. Read before touching any PR.
2. Pick your PR plan below. Do them in priority order (see [../../ROADMAP.md](../../ROADMAP.md)).

## Plans

| PR | Priority | Model | What | Plan |
|----|----------|-------|------|------|
| A | 🔴 CRITICAL | Sonnet | Green the CI (tag test + tag fetch, pin ruff, local-CI habit) | [PR-A-ci-reliability.md](PR-A-ci-reliability.md) |
| B | 🟠 HIGH | Sonnet | Azure `sys.exit` removal; orphan `timeout` file removal | [PR-B-reliability.md](PR-B-reliability.md) |
| D | 🟠 HIGH | Sonnet→Haiku | Coverage 85%→≥90%; make `EnvironmentManager` testable | [PR-D-coverage.md](PR-D-coverage.md) |
| C | 🟡 MEDIUM | Sonnet | CSP matching perf: pre-build networks, drop O(n²) dedupe | [PR-C-scalability.md](PR-C-scalability.md) |
| E | 🟡 MEDIUM | Sonnet | Move Lambda docs out; document active-probing boundary | [PR-E-scope-cleanup.md](PR-E-scope-cleanup.md) |
| F | 🟡 MEDIUM | Opus | New DNS features: wildcard detection, AAAA, more signatures | [PR-F-dns-features.md](PR-F-dns-features.md) |
| G | 🟢 LOW | Haiku | Docs polish: roadmap link, crt.sh helper, limitations | [PR-G-docs.md](PR-G-docs.md) |
| H | 🟢 LOW | Haiku | Merge 10 dependabot PRs; prune stale branches | [PR-H-dependencies.md](PR-H-dependencies.md) |

## Context documents
- [../../REVIEW.md](../../REVIEW.md) — the holistic review these plans derive from (findings, failure
  scenarios, coverage gaps, gap analysis).
- [../../ROADMAP.md](../../ROADMAP.md) — ordered roadmap, model-tier justification, release grouping.

## Dependency order
```
PR-A (green CI)  ──►  PR-H (dependabot backlog needs green CI)
      │
      └─►  PR-B, PR-D (independent HIGH work)  ──►  PR-C, PR-E, PR-F (MEDIUM)  ──►  PR-G (polish, folds in)
```
