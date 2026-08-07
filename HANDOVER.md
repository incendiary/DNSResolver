# HANDOVER — brief for the next agent

You are taking over DNSResolver from a previous AI agent (Claude). This document is
self-contained: it assumes you have **no access to the tooling or skill library** the previous
agent used, so every method it refers to is written out here rather than named.

Your job, in order:

1. Pull down the repository and orient yourself (§1–§2).
2. Review what was done and form your own view of it (§3).
3. **Run a goal-clarification interview with the maintainer** — ask a lot of questions before
   proposing anything (§4). This matters more than it sounds; see the warning below.
4. Work to the project's delivery standards (§5–§7).
5. Produce your own plan and get it agreed (§8).

> ### Read this before anything else
>
> The previous agent conducted a full, rigorous codebase review of this project **against the
> wrong goal**. It was internally consistent, evidence-backed, thorough — and wrong, because it
> had misread what the tool is for. That error survived for most of the engagement and was only
> caught when the maintainer stated the purpose explicitly.
>
> **Rigour applied to a wrong premise produces confident, well-supported, wrong conclusions.**
>
> Do not skip §4. Do not infer the goal from the code, and do not infer it from this document
> alone. Ask.

---

## 1. Get the repository

```bash
git clone git@github.com:incendiary/DNSResolver.git
cd DNSResolver
```

**Interpreter note.** On the maintainer's machine `python3` is a broken pyenv shim pointing at a
missing version. Use an explicit interpreter:

```bash
/opt/homebrew/bin/python3.12 -m venv .venv        # any working Python 3.12 is fine
.venv/bin/pip install -r requirements-dev.txt -r requirements-lambda.txt
```

Install **both** requirements files. `requirements-lambda.txt` supplies `boto3`; without it the
Lambda tests fail with `ModuleNotFoundError`. That is an environment gap, not a code bug. CI
installs both.

Verify your environment reproduces the current state:

```bash
.venv/bin/pytest --cov=classes --cov=imports -q     # expect 268 passed, ~95% coverage
.venv/bin/ruff check .                              # expect clean
.venv/bin/ruff format --check .                     # expect clean
```

If those numbers differ, stop and work out why before changing anything.

---

## 2. Current state (as at v2.0.0, 2026-08-07)

| | |
|---|---|
| Latest release | **v2.0.0** |
| `main` | green, all checks passing |
| Tests | 268 passing |
| Coverage | ~95% |
| Open issues | **0** (37 closed) |
| Open PRs | **2**, both dependabot (`#156` boto3, `#157` ruff) |
| Remote branches | `main` plus the two dependabot branches — no orphaned work |

**All previous work is merged into `main`.** No sprint branches are left dangling; every branch
the previous agent created was squash-merged and deleted. There is nothing hidden to recover.

### Documents to read, in this order

| File | What it is |
|---|---|
| **`AGENTS.md`** | What the tool is for, architecture, output contracts, conventions, traps. **Start here.** |
| `README.md` | User-facing documentation |
| `REVIEW.md` | The 8-phase codebase review — **read its Correction section at the end first**, because the body was written against a misread goal |
| `ROADMAP.md` | Plan and its status, plus what remains open |
| `docs/roadmap/AGENT-GUIDE.md` | Per-task working rules used during delivery |
| `docs/roadmap/PR-*.md` | Individual execution plans (historical; all delivered) |
| `CONTRIBUTING.md` | Contribution basics |

### Verify the state yourself rather than trusting this table

```bash
gh pr list --state open
gh issue list --state all --limit 50
gh release list --limit 5
git branch -r
gh run list --branch main --limit 5
gh api repos/incendiary/DNSResolver/branches/main/protection/required_status_checks --jq '.contexts'
git log --oneline -30
```

You were asked to review remote branches and issues as part of your assessment. Do that from
the live repository, not from this document — it will age.

---

## 3. What the previous agent did, and where to be sceptical

### Delivered

Starting point was: CI red for weeks, 12 stalled PRs, 144 tests, 85% coverage, v1.10.4.

- **Fixed CI.** A baseline test asserted a git tag existed; CI checks out without tags, so it
  could never pass there — and it passed locally, so running CI locally did not reveal it.
- **Fixed branch protection.** Required status checks were named after *workflows* (`CI`,
  `Secret Scan`) while GitHub reports *job* names (`test`, `gitleaks`, `trufflehog`). Those
  contexts could never be reported, so **every PR was permanently unmergeable**. This, not the
  red build, was the real cause of the PR backlog.
- **Correctness fixes:** non-existent domains no longer reported as takeover candidates;
  `self_referential` gated to real CNAME loops; Azure fetch no longer calls `sys.exit(1)`
  mid-run; orphan output file removed.
- **Coverage 85% → 95%**, largely by extracting a network call out of a constructor so the class
  could be built offline.
- **Features:** IPv6 (AAAA) resolution; wildcard DNS detection; 30 further takeover fingerprints
  (60 → 90); CNAME chain depth and path; cloud region/service/border-group capture.
- **v2.0.0**, major because three output contracts changed shape.

### Be sceptical about

- **The framing error.** `REVIEW.md`'s body treats cloud attribution as a supporting attribute.
  It is one of two co-equal products. The correction is appended at the end of that file; the
  body is left intact deliberately so the mistake is visible rather than tidied away.
- **Performance is unverified.** Known cliffs were removed (per-IP CIDR parsing, an O(n²)
  dedupe) but **no benchmark has ever been run**. The README claims the tool is "practical for
  large domain lists". That claim is reasoned, not demonstrated. It is the most load-bearing
  unverified statement in the project.
- **Wildcard detection is probabilistic.** Random-label probes sample a zone. Against a large
  rotating fleet they see only part of it. This is handled by reporting two verdicts rather than
  one (see `AGENTS.md` §7), but the underlying uncertainty remains.
- **Test suite blind spots.** Coverage rose ten points while catching **none** of the defects
  that mattered. All were found by running the tool against real DNS, or by attempting a real
  merge. Treat green tests as necessary, not sufficient.
- **Downstream breakage.** Output formats changed in v2.0.0. A separate tool consumes these
  files and has not been updated. Confirm with the maintainer whether that has happened.

---

## 4. The goal-clarification interview — do this before proposing work

The maintainer has asked for a structured review conducted *with* them, not handed to them. The
method below is a three-layer framework the previous agent used; it is reproduced in full because
you will not have it otherwise.

### Layer 1 — Specification (do this first, always)

The purpose is to prevent the most expensive failure mode: **building the wrong thing
precisely.** Ask, and do not proceed until you have real answers to at least the first two:

**1. What does success look like?**
- What is the output, and who receives it?
- What do they do with it next?
- What separates "good" from merely "acceptable" here?

**2. What are the constraints?**
- Format, tooling, audience, time.
- What must *not* be in the output?
- What is non-negotiable?

**3. What is the scope?**
- Is this the whole task or one part of it?
- What is explicitly out of scope?

**4. What context is needed?**
- What should be read or understood first?
- Is there an example that represents the right bar?

**5. Do not lock in the obvious.** Before committing, propose alternatives — including ones with
longer-lasting impact than the current framing. The maintainer is receptive to this and has
redirected work more than once when it was raised.

Then decompose into discrete, independently verifiable items:

```
Spec N: [TITLE]
  Goal:      what this produces
  Input:     what it needs
  Output:    the exact deliverable
  Done when: a testable condition — not "looks good"
```

And define 5–6 success criteria **before** starting, each with a stated verification method.
Criteria written after the work exists are biased toward the work that exists.

### Layer 2 — Verification (after work exists)

Evaluate output against the Layer 1 criteria. Two rules earned the hard way here:

- **Ground claims in external signal**, not in reasoning about the code. Run it. Against real
  DNS, on real domains.
- **Watch for "wrong but green"** — output that satisfies the check while being wrong. In this
  project a wildcard feature passed all sixteen of its unit tests while being completely
  non-functional against real dual-stack zones. Tests confirm the logic you thought of; they
  cannot tell you the premise was wrong.

### Layer 3 — Environment (afterwards)

Capture what recurs — conventions, traps, project context — into durable documents so the next
session starts faster. `AGENTS.md` is that artefact here; extend it rather than starting a new
one.

### Questions specific to this project

Beyond the generic frame, these are genuinely open and worth putting to the maintainer:

- Are the two jobs (takeover candidates, cloud reclaim targets) still co-equal, or has priority
  shifted?
- What does the downstream consuming tool actually need that it does not get today?
- Is performance at scale worth proving, and what would count as proof? What list size is real?
- Is the DNS-only boundary still firm?
- What does "done" look like for this project overall — is it feature-complete, or still growing?
- Who else uses it, and what breaks for them if output formats change again?

---

## 4b. The codebase review method (8 phases)

The previous agent used a structured review method. It is reproduced here because you will not
have it, and because the maintainer has asked for this kind of review. **Run it against a goal
you have confirmed in §4, not against the one you infer.** That is the whole lesson of this
project.

Work the phases in order. A null finding is still a finding — record it.

**Phase 1 — Architecture map.** Identify the layers. List each module with a one-line purpose.
Note any module without a single clear responsibility. Trace the data flow: where input enters,
how it moves, where it leaves. Output as a table of module / responsibility / concerns.

**Phase 2 — Risk inventory.** Classify every risk and score it 1–5.

| Category | Look for |
|---|---|
| Security | Injection, auth bypass, secret exposure, dependency CVEs |
| Scalability | Unbounded loops, per-item work that should be per-run, in-memory state |
| Reliability | Uncaught exceptions, missing retries, hard exits, no fallback on external calls |
| Maintainability | Long functions, deep nesting, missing tests on critical paths |
| Dependency | Unpinned versions, abandoned packages, single-purpose deps |

Output a table: number / category / finding / score / file:line.

**Phase 3 — Predictive failure analysis.** For every risk scoring 3 or above, write: what
observably happens; the trigger condition; whether it fails today, at 10× load, or on the next
upgrade; the minimum fix; and the full fix. Be concrete — an error message or a corrupted output,
not "may cause problems".

**Phase 4 — Test coverage gaps.** List critical paths with no coverage. Flag tests that assert so
broadly they would pass even if the logic were wrong. Rank the three highest-value additions by
the risk score of what they leave uncovered.

**Phase 5 — Dependency audit.** For each dependency: pinned, ranged or floating; date of last
upstream release; known CVEs (`pip-audit -r requirements.txt`). Note any dependency doing one
small thing that could be inlined.

**Phase 6 — CI/CD gaps.** Does the pipeline run tests on every PR? Lint and format? Scan for
secrets? Pin action versions? Run on a schedule to catch environment drift? Flag every "no" and
write the YAML that would fix it.

**Phase 7 — Feature-versus-goals gap analysis.** Map current capability against the *stated*
goal, and say plainly where it falls short. **This is the phase that went wrong here.** It was
completed rigorously against a goal that had been misread, and returned a confident "meets its
goals" for a component that was, judged correctly, unfinished. Confirm the goal in §4 before
writing this phase, and state which goal you are measuring against.

**Phase 8 — Write it up.** Executive summary (3–5 sentences: top risk, most urgent fix, overall
health), then the phase outputs, then an action roadmap. Each action item must be executable by
someone who has not read the review:

```
### RA-N: <short imperative title>
Context:          what the problem is and where, in 1–2 sentences
Success criteria: exactly how to verify it is done
Files to change:  explicit paths
Effort:           XS / S / M / L / XL
```

Write findings to `REVIEW.md` and action items to `ROADMAP.md`. **Do not overwrite the existing
correction section in `REVIEW.md`** — it is deliberate evidence that a thorough review can be
wrong, and it is more useful to you than a clean document would be.


---

## 5. DevOps standards — how work must be delivered

These are the maintainer's standing practices. Follow them exactly.

### Branching and PRs

- **Branch from latest `main`:** `git fetch origin && git checkout -b <type>/<name> origin/main`
- Prefixes: `fix/`, `feat/`, `docs/`, `ci/`, `chore/`, `test/`
- **One logical change per PR.** Not "fix bug and also refactor".
- **Conventional commit titles:** `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `ci:`
- **Squash merge to `main`.** History stays linear.
- **Never rebase a branch that has been pushed.** Use `git merge main` to catch up — rebasing a
  published branch drops commits under a squash-merge workflow.
- Every commit message ends with a `Co-Authored-By:` trailer identifying the agent.
- **Never push directly to `main`.** Branch protection blocks it, and it is a hard rule regardless.

### Merge requirements

Branch protection on `main` requires these status checks, which are **job** names and not
workflow names:

```
test, gitleaks, trufflehog
```

If you ever change workflow structure, verify these still report. Getting this wrong silently
blocks every PR in the repository — it already happened once here.

### Versioning and releases

- `VERSION` (repo root) is the single source of truth; `version.py` mirrors it; a baseline test
  enforces they agree.
- **Do not bump `VERSION` in individual PRs.** Version once per batch, at release time. Parallel
  branches each bumping it conflict on every merge.
- **Never run `git tag` during normal work.** Tags are created only when a release is cut. A tag
  for an unreleased version breaks the version-sync baseline test on every other branch.
- Semantics: patch = related fixes; minor = new capability; **major = a broken interface
  contract.** The output files count as interface contracts — that is why v2.0.0 was major.
- Releases: tag `vX.Y.Z`, then publish a GitHub release with substantive notes.

### Before every push

CI must be run locally first. The previous agent had a script for this; you may not. The
equivalent is to run exactly what `.github/workflows/ci.yml` runs:

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pytest tests/baseline/ -v
.venv/bin/pytest --cov=. --cov-report=term-missing
```

Read `.github/workflows/ci.yml` yourself and mirror it — do not trust this list to stay current.

**A known blind spot:** local runs have git tags present; CI checks out without them. A
tag-dependent test can pass locally and fail in CI. After pushing, always confirm the real run:

```bash
gh run list --branch <your-branch> --limit 1
gh pr checks <PR-number>
```

### Secret scanning — strict, and it will block you

`gitleaks` and `trufflehog` run in CI, and a `pre-commit` hook runs gitleaks locally. There is a
custom rule matching the maintainer's **employer name**. This repository is public.

- Never put real client, employer, or engagement-specific names into code, comments, commit
  messages, or documentation. Use `example.com` or "a client domain".
- This already blocked a commit during the previous engagement — the planning documents contained
  the employer name from live-run evidence. That is what the rule is for.

### Cross-repository references

Never write `owner/repo#123` shorthand for another repository — it creates cross-repository
pingbacks. Use a full URL in backticks, or plain prose.

### Testing standards

- **No test may make a real DNS query or HTTP request.** Mock `aiodns`, `dns.resolver`,
  `requests`, `urlopen`. Follow the patterns in `tests/conftest.py` and `tests/test_dns_handler.py`.
- **Assert outcomes, not execution.** A test proving code "ran without raising" is worse than no
  test, because it reads as coverage.
- **Coverage only goes up.** It is ~95%.
- **Every bug fix gets a regression test.**
- **Run the tool against real DNS** before believing a change to resolution or classification
  works. This is where every real defect in this project was found.

---

## 6. Model selection (if you delegate to sub-agents)

The previous agent used a framework worth reproducing. Choose on two axes:

**Verifiability** — can a machine prove correctness cheaply (tests, types, lint)? If yes, a
weaker model is safe because wrong is visible and cheap. If no, model strength *is* the safety net.

**Blast radius** — additive and isolated, or destructive and wide?

| | High verifiability | Low verifiability |
|---|---|---|
| **Small blast radius** | Weakest model fine | Mid-tier |
| **Large blast radius** | Mid-tier | **Strongest model required** |

The dangerous quadrant is low verifiability plus large blast radius. Also watch for tasks where a
weak model can make a test pass by quietly weakening it — test migration is the classic case.

Practical rule used here: strongest models for DNS semantics and classification logic; mid-tier
for mechanical refactors with strong test gates; weakest for docs and dependency bumps.

---

## 7. Traps that have already cost time here

- Broken `python3` shim — use an explicit interpreter.
- Forgetting `requirements-lambda.txt` — Lambda tests then fail on missing `boto3`.
- Creating a git tag — breaks the baseline test everywhere.
- Bumping `VERSION` per PR — guarantees merge conflicts.
- Branch protection contexts naming workflows instead of jobs — blocks all merges silently.
- A green local CI run is not proof CI is green (tags).
- Employer or client names anywhere — blocked by secret scanning, and correctly so.
- Dependabot branches whose base predates a CI fix cannot be updated with `gh pr update-branch`;
  comment `@dependabot recreate` instead.
- Trusting coverage. It rose ten points here while catching none of the real defects.

---

## 8. What to produce

After your review and the interview, produce **your own plan**. Do not simply continue the
previous agent's roadmap — it was written against a premise that turned out to be wrong, and
you should satisfy yourself about the current one.

The plan should state:

- The goal, in the maintainer's terms, written back to them for confirmation.
- Discrete work items, each independently verifiable, each with a testable "done when".
- Success criteria defined **before** work starts, with verification methods.
- Model tier per item if you are delegating, with reasoning.
- What you are explicitly *not* doing, and why.

Two items are already known to be open, from `ROADMAP.md`:

- [ ] **Performance at scale is unmeasured.** No benchmark against a large list, though the
      README claims the tool is practical for them.
- [ ] **The downstream consumer needs updating** for the v2.0.0 output formats.

Neither is necessarily your priority. Confirm with the maintainer.

A third is open and blocking: **TruffleHog fails on push events** — see §10. That one needs
settling before it blocks other merges.

### Immediate housekeeping

Two dependabot PRs are open (`#156` boto3, `#157` ruff). They are mechanical, gated by CI, and
safe to merge once green — but confirm before merging, and note that the ruff bump can introduce
new lint rules that fail on untouched code.

---

## 9. A closing note on method

The single most useful thing the previous engagement produced was not a feature. It was the
discovery that a careful, evidence-backed review had been measuring the wrong thing for its
entire duration, and that neither the test suite nor the review process could detect it.

Three separate times, the defect that mattered was invisible to a green test suite:

- a wildcard feature that passed all its unit tests while being non-functional against real
  dual-stack zones — found by running it;
- takeover candidates that were pure false positives — found by running it;
- branch protection that made every PR unmergeable — found by attempting a real merge.

Whatever else you do: **run the thing, against reality, and ask the maintainer what they
actually want before you decide what "better" means.**

---

## 10. Known open item — TruffleHog failing on push events

**Status: unresolved, handed to you deliberately. Investigate before merging anything that
depends on it.**

The `secret-scan.yml` workflow runs two jobs, `gitleaks` and `trufflehog`, and both are required
status checks. On the branch that added this document, `trufflehog` **failed on the push event
while passing on the pull_request event**, blocking the merge.

### What is known

- The failure reports `Found verified Lob result` **seven times**, then exits 183.
  "Verified" means TruffleHog believes it validated the credential against Lob's API.
- Every previous push-event scan on `main` passed — this is new to that branch.
- Only three Markdown files changed on it: `HANDOVER.md`, `AGENTS.md`, `README.md`.
- Grepping the added lines for key-shaped strings — long hex runs, `live_*`, `test_*`, `sk_*` —
  found **nothing**.
- The failing run scanned `unit_kind: dir`, 369 chunks / ~500 KB. The passing PR-scoped run
  scanned the diff.

### Likely explanations, in order

1. **A TruffleHog false positive.** The Lob detector is known to be loose, and "verified" can
   fire on patterns that happen to satisfy a permissive endpoint. Seven hits with no key-shaped
   string in the diff points this way.
2. **Differing scan scope between events.** Push and pull_request runs cover different ranges;
   the push run may be reaching content the PR run never inspects.
3. **Something genuinely present** that the greps above did not model. Least likely, but it is a
   secret scanner and it must be excluded, not assumed away.

### How to settle it

```bash
docker run --rm -v "$PWD:/repo" ghcr.io/trufflesecurity/trufflehog:latest \
  filesystem /repo --results=verified --json | jq '.DetectorName, .Raw' 
```

That prints what is actually matching. Compare against `.github/workflows/secret-scan.yml` to see
the exact invocation and scope CI uses.

**Do not resolve this by bypassing the check, by merging with admin rights, or by removing
TruffleHog from the required contexts.** It is a security control on a public repository. Either
prove the finding is a false positive and suppress it narrowly with a documented reason, or
remove whatever is genuinely matching.

If it proves to be a false positive, the fix is a scoped exclusion — not disabling the scanner.

---

## 11. Additional context you will want

### The companion project

A separate tool consumes this one's output and performs the actual reclaim work. It is not in
this repository and the previous agent never saw it. Two consequences:

- Output formats are **contracts**, and v2.0.0 broke three of them. Confirm with the maintainer
  whether the consumer has been updated.
- Do not add claiming, allocation, or cloud-provider API calls here. That is the other tool's job,
  and the boundary is deliberate.

There is also a separate project that produces the Lambda packaging. This repository keeps
`lambda_handler.py` as a reference entry point only; the `Dockerfile` and ECR build workflow were
removed in v2.0.0 because they failed on every release tag for want of credentials this repo does
not hold.

### Testing against real infrastructure

The maintainer authorised live runs against a corporate domain during the previous engagement,
and those runs found defects the test suite did not. If you want to do the same:

- **Ask first.** Do not scan any third-party domain without explicit authorisation for that
  specific target.
- **Never write the target's name into the repository.** Secret scanning enforces this, and the
  repository is public. Use `example.com` in code, tests and documentation.
- Public wildcard zones are useful for testing detection without touching anyone's
  infrastructure: `github.io` is wildcarded with a stable address set, `herokuapp.com` is
  wildcarded with a large rotating fleet across regions. The second is the harder case and is
  what exposed the limits of address-level wildcard matching.

### How the previous engagement was run

Work was delivered in sprints: a roadmap of bundled PRs, each with a written plan under
`docs/roadmap/`, executed one branch per item, squash-merged, then released as a batch. Some
items were delegated to sub-agents with a model tier chosen per §6. Where sub-agents were used
they were given the plan file plus the standards in `docs/roadmap/AGENT-GUIDE.md`, and their work
was verified before merge rather than taken on trust — two of them reported facts about the
baseline that turned out to be wrong, and were right to flag the discrepancy rather than paper
over it.

You are not obliged to work that way. It is recorded so the existing artefacts make sense.

### Things deliberately not done

- **No benchmark.** Performance work was reasoned from the code, never measured.
- **No active probing.** The DNS-only boundary was held even where crossing it would have
  resolved an ambiguity — see the wildcard limitation in `AGENTS.md` §7.
- **No changes to the companion tool**, which is out of scope for this repository.
- **PR 104 was left alone** for most of the engagement because it was authored separately; it was
  reviewed on its merits and merged only at the end.
