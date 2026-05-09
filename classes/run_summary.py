class RunSummary:
    def __init__(self, output_files, output_dir):
        self._files = output_files["standard"]
        self._output_dir = output_dir

    def _lines(self, key):
        path = self._files.get(key, "")
        try:
            with open(path, encoding="utf-8") as f:
                return [ln.strip() for ln in f if ln.strip()]
        except OSError:
            return []

    def print(self, total_input, failed_count):
        resolved_count = len(self._lines("resolved"))
        unresolved_count = len(self._lines("unresolved"))
        dangling = self._lines("dangling")
        ns_takeover = self._lines("ns_takeover")
        aws_count = len(self._lines("aws"))
        gcp_count = len(self._lines("gcp"))
        azure_count = len(self._lines("azure"))

        by_category = {}
        for line in dangling:
            parts = line.split("|")
            if len(parts) >= 5:
                orig, current, category, recommendation, evidence = parts[:5]
                by_category.setdefault(category, []).append(
                    (orig, current, recommendation, evidence)
                )

        bar = "=" * 64
        thin = "-" * 64
        total_candidates = len(dangling) + len(ns_takeover)

        print(f"\n{bar}")
        print("  DNSResolver — Run Summary")
        print(bar)
        print(f"  Input domains        : {total_input:>6,}")
        print(f"  Resolved             : {resolved_count:>6,}")
        print(f"  Unresolved errors    : {unresolved_count:>6,}")
        print(f"  Failed (all retries) : {failed_count:>6,}")
        print()
        print(
            f"  CSP matches — AWS: {aws_count}  GCP: {gcp_count}  Azure: {azure_count}"
        )
        print(thin)

        if total_candidates == 0:
            print("  No takeover candidates detected.")
        else:
            print(f"  [!] {total_candidates} TAKEOVER CANDIDATE(S) DETECTED [!]")

            if dangling:
                print()
                print(f"  Dangling CNAMEs ({len(dangling)})")
                for category, entries in sorted(by_category.items()):
                    print(f"    [{category}]")
                    for orig, current, rec, evidence in entries:
                        label = current if current != orig else orig
                        print(f"      {label}")
                        print(f"        Recommendation : {rec}")
                        print(f"        Evidence       : {evidence}")

            if ns_takeover:
                print()
                print(f"  NS Takeover candidates ({len(ns_takeover)})")
                for line in ns_takeover:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        print(f"    {parts[0]} -> NS: {parts[1]}")

        print(thin)
        print(f"  Output : {self._output_dir}")
        print(f"{bar}\n")
