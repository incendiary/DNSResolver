# Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes
4. Push and open a Pull Request

## Before you push

Run the local CI parity command so lint/format/test failures show up before CI does:

```bash
bash ~/.claude/skills/github-actions-locally/github-actions-locally.sh --workflow ci.yml
```

**Known blind spot:** `tests/baseline/test_baseline.py::test_version_tag_exists_in_git` will pass
locally even when it would fail in CI, because your local clone has git tags and a shallow CI
checkout may not. Don't trust a green local baseline test as proof CI is green — check the actual
run instead:

```bash
gh run list --branch <your-branch> --limit 1
```

See [`docs/roadmap/AGENT-GUIDE.md`](docs/roadmap/AGENT-GUIDE.md) §3 for the full rationale.
