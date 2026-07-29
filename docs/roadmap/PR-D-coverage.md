# PR-D — Coverage lift (HIGH)

**Model:** Sonnet for the seam + first tests; Haiku may extend once the harness asserts real outcomes.
**Release:** v1.11.0 (minor — adds a testability seam + test infra) · **Read [`AGENT-GUIDE.md`](AGENT-GUIDE.md) first.**

## Why this exists (context)

Overall coverage is 85%. The weak module is `classes/environment_manager.py` at **35%**. The reason
it is untestable is a design issue: its **constructor makes a live HTTP call** to `https://ifconfig.io/ip`
(`_populate_environment_info`, ~line 116). You cannot construct an `EnvironmentManager` in a unit test
without hitting the network, so almost none of it is covered.

The fix is a small, well-understood refactor (extract a seam) plus straightforward unit tests. Target:
overall coverage **≥ 90%**, and `environment_manager.py` **≥ 80%**.

> **Model-selection note (why the split):** extracting the seam without changing behaviour needs
> judgment → Sonnet. Once the seam exists and the first tests assert *real outcomes* (validation
> results, config precedence, graceful error handling), filling in the remaining mechanical cases is
> gate-checked and Haiku-safe. Do NOT let a weak model write the seam, and do NOT accept tests that
> only assert "it didn't raise" — that is the "wrong but green" trap this project explicitly guards against.

## Tasks

### D1 — Make `EnvironmentManager` constructible offline, then test it

**Seam options (pick the simplest that fits the existing style):**
- Preferred: extract the external-IP lookup into a module-level function
  `fetch_external_ip(timeout=10) -> str` and call it from `_populate_environment_info`. Tests patch
  `classes.environment_manager.fetch_external_ip`. This matches how the codebase already isolates I/O.
- Alternative: accept an optional injected callable in `__init__` defaulting to the real fetch.

Keep the change **surgical** — same behaviour when unpatched. Do not restructure the class.

**Then add `tests/test_environment_manager.py` covering (assert real outcomes):**
- `is_valid_domain`: valid (`a.example.com`), invalid (`not_a_domain`, `123`, empty, `-lead.com`,
  overly long label) — assert exact `True`/`False`.
- `clean_domains`: filters blanks and invalids, keeps valids — assert the exact filtered list.
- `load_patterns`: valid `config.json` → patterns dict populated; missing file → `{}`; malformed
  JSON → `{}` (no raise).
- `get_random_nameserver`: with nameservers set returns one of them; with `None` returns `None`.
- `set_domains`: reads a temp file, dedupes via `set`, validates.
- Construction with `fetch_external_ip` patched: no network, `environment_info` populated with the
  mocked IP, `run_in_docker` boolean present.

Use `monkeypatch`/`unittest.mock` and `tmp_path` fixtures. Follow patterns in existing tests.

**Success criteria:**
- `pytest --cov=classes.environment_manager` shows ≥ 80% for that module.
- Overall `pytest --cov=classes --cov=imports` shows ≥ 90%.
- No test performs real network I/O (grep your new test for `requests`/`ifconfig` — only mocks).

**Files to change:** `classes/environment_manager.py`, `tests/test_environment_manager.py` (new).
**Effort:** M.

### D2 — Close the smaller gaps

Add targeted tests (assert outcomes, not execution):
- `imports/cloud_ip_ranges.py` (84%): error paths return `([], [])` (this includes the B1 regression
  test if not already added), Azure cache hit/miss/pinned-fallback selection, non-200 status handling.
  Patch `requests.get` and `urllib.request.urlopen`.
- `classes/output_manager.py` (70%): output-dir creation, evidence-dir vs file-path branch in
  `_create`, and the write-error path (patch `aiofiles.open` to raise → logs, does not crash).
- `classes/config_resolver.py` (84%): CLI value overrides config value; config value fills an unset
  CLI arg; bad/missing config file tolerated; `--resolvers` alias maps to `nameservers`.

**Success criteria:** each listed module's coverage rises; overall ≥ 90%; suite green.
**Files to change:** `tests/test_cloud_ip_ranges.py`, `tests/test_output_manager.py` (new if absent),
`tests/test_config_resolver.py`.
**Effort:** M.

## Release

Bump `VERSION`/`version.py` to `1.11.0` (minor — new test infrastructure + a public-ish seam). This PR
depends on nothing but should land after PR-B so the B1 regression test has a home. If PR-B already
added it, D2 just verifies it's present.
