# PR-E — Lambda / scope cleanup (MEDIUM)

**Model:** Sonnet · **Release:** v1.11.2 (patch) · **Read [`AGENT-GUIDE.md`](AGENT-GUIDE.md) first.**

## Why this exists (context)

Maintainer decision (2026-07-15): the AWS Lambda variant of this tool is **produced in a separate
project**, which ingests this repo. This repo should stay clean and CLI-focused. Also, the DNS-only
scope is firm — active probing (HTTP/TLS/ports/screenshots) belongs to a *different* future project,
and README readers should be told that explicitly so they know where the boundary is.

Currently the README carries ~160 lines of Lambda/ECR/IAM deployment walkthrough (roughly the
"AWS Lambda deployment" section through "Pipeline integration"). That is deployment detail for the
*other* project's concern and dominates the README of what is fundamentally a CLI tool.

> **Important — this is a judgement PR, not a delete-everything PR.** Do not remove `lambda_handler.py`
> or its tests on your own initiative. See E3: the code stays unless the maintainer says otherwise;
> only the *documentation weight* moves in E1.

## Tasks

### E1 — Move the Lambda deployment walkthrough out of the README

- Create `docs/LAMBDA.md`. Move the full "AWS Lambda deployment" walkthrough (design-decisions table,
  env vars, IAM, the numbered ECR/build/deploy/trigger steps, pipeline-integration diagram) verbatim
  into it. Preserve all content — this is a move, not a rewrite.
- In the README, replace that whole section with a short pointer, e.g.:
  > ### AWS Lambda deployment
  > DNSResolver can run as an S3-triggered Lambda. The full deployment walkthrough (ECR image, IAM,
  > triggers) lives in [`docs/LAMBDA.md`](docs/LAMBDA.md). Note: the maintained Lambda packaging is
  > produced in a separate project; the handler here is the reference entry point.
- Keep the README's high-level architecture diagram (it legitimately shows both entry points).

**Success criteria:** README is materially shorter; `docs/LAMBDA.md` contains the moved content with
no loss; all internal links resolve; baseline `test_no_unpinned_refs_in_docs` still passes (no
`@main`/`@master` introduced).
**Effort:** S.

### E2 — Document the active-probing boundary

Add a short, clearly-worded note near the top of the README (right after the existing "intentionally
DNS-focused" paragraph) making the boundary explicit. Use this wording:

> **Scope boundary.** DNSResolver is deliberately passive and DNS-only. Confirming a takeover
> (HTTP/HTTPS fingerprinting, TLS inspection, port probing, screenshots) is **out of scope by design**
> — if that capability is needed it belongs in a separate tool, not here. Keeping this project
> DNS-only keeps it dependency-light, fast, and safe to run broadly.

**No link, no placeholder.** There is **no companion project today** — the maintainer said only that he
would *rather spin one up* in future than widen this tool's scope. So:
- Do **not** write `see [SOME-URL]` or leave a placeholder — a link to something that doesn't exist
  misleads readers.
- Do **not** invent a URL.
- Do **not** promise a future project as if it were planned or committed. State the boundary and the
  rationale; that is all the reader needs.

If the maintainer later creates that project, adding the link is a one-line follow-up.

**Success criteria:** the note exists, reads clearly, states the boundary and why, and does not
reference or imply any project that does not exist.
**Effort:** XS.

### E3 — Capture the Lambda-code decision (do not act unilaterally)

The Lambda footprint in this repo is: `lambda_handler.py`, `classes/lambda_environment_manager.py`,
`requirements-lambda.txt`, `.github/workflows/ecr-build.yml`, `Dockerfile`, and their tests
(`tests/test_lambda_handler.py`, `tests/test_lambda_environment_manager.py`).

**Decision needed from the maintainer** (record the answer at the top of this file when known):
- **Option 1 — keep as reference (default).** The handler stays as a documented reference entry point;
  only the docs moved (E1). No code deleted. *Recommended* — it is well-tested (98% cov) and harmless.
- **Option 2 — extract fully.** Remove the Lambda code/workflow/deps from this repo entirely because
  the other project is the real home. This is a **large blast-radius** change (deletes files, drops
  `boto3`, changes CI install lines, removes tests) and must be its own dedicated PR with the
  maintainer's explicit go-ahead — not folded into E1/E2.

Until the maintainer chooses, implement **Option 1** and leave a note in the PR description asking for
the decision. Do not delete Lambda code in this PR.

**Success criteria:** the decision is documented; if Option 1, no Lambda code changed; if the
maintainer picks Option 2, it is split into a separate tracked PR.
**Effort:** XS (Option 1) / L (Option 2, separate PR).

## Release

Bump `VERSION`/`version.py` to `1.11.2` for the docs move (E1/E2). Option 2, if chosen, is a separate
minor/major depending on whether dropping the Lambda entry point is considered a breaking change.
