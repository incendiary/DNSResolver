# PR-G — Docs & release polish (LOW)

**Model:** Haiku · **Release:** fold into the next release · **Read [`AGENT-GUIDE.md`](AGENT-GUIDE.md) first.**

## Why this exists (context)

Small, isolated, additive documentation/polish items. Mechanical and cheap to review — Haiku-safe. If
any item turns out to need a judgement call (e.g. what to say about a limitation), stop and ask rather
than guess.

## Tasks

### G1 — README roadmap → link to ROADMAP.md

The README currently duplicates a long roadmap table. Per devops-practices, the dedicated
[`ROADMAP.md`](../../ROADMAP.md) is now the source of truth. Replace the README `## Roadmap` **table**
with a brief 2–3 line summary and a link:
> ## Roadmap
> Active and shipped work is tracked in [ROADMAP.md](ROADMAP.md). Recent releases: v1.10.x output
> consolidation, actionable run summary, version string, self-referential CNAME handling.

Do **not** delete the historical detail — it already lives in GitHub Releases and `ROADMAP.md`'s
"Shipped" section. Just stop duplicating the growing table in the README.

**Success criteria:** README roadmap section is a short summary + working link; no broken links;
baseline `test_no_unpinned_refs_in_docs` passes.
**Effort:** XS.

### G2 — Add the crt.sh domain-list helper

The README documents a one-liner to build a domain list from certificate transparency. Make it a
committed, reusable script `helper/crtsh_domains.sh` that takes a root domain and writes a de-duplicated
domain list:
```bash
#!/usr/bin/env bash
# Usage: helper/crtsh_domains.sh example.com > domains.txt
set -euo pipefail
domain="${1:?usage: crtsh_domains.sh <root-domain>}"
curl -s "https://crt.sh/?q=%25.${domain}&output=json" \
  | python3 -c "import json,sys; n=set(); [n.update(e['name_value'].split(chr(10))) for e in json.load(sys.stdin)]; [print(x.lstrip('*.')) for x in sorted(n) if x]" \
  | sort -u
```
Make it executable (`chmod +x`). Reference it from the README's "Building a domain list" section.

**Success criteria:** script exists, is executable, `shellcheck helper/crtsh_domains.sh` is clean, and
the README references it. (Do not run it against live infrastructure as part of the test.)
**Effort:** XS.

### G3 — Document known limitations

Add a short "Known limitations" subsection to the README:
- Resolution currently follows A records (and, after PR-F2, AAAA). Other record-only hosts may read as
  unresolved. *(Update this line once PR-F2 lands.)*
- Dangling-CNAME classification is first-match-wins over `config.json` patterns — order matters;
  patterns are listed specific → general.

**Success criteria:** subsection exists, accurate to the code at time of writing.
**Effort:** XS.

## Release

No standalone release — fold these into whatever point release is being cut next (they are docs/polish).
Still bump nothing on their own; they ride along.
