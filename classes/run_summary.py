import os


class RunSummary:
    def __init__(self, output_files, output_dir):
        self._files = output_files["standard"]
        self._output_dir = output_dir

    def _lines(self, key):
        path = self._files.get(key)
        if not path:
            return []
        try:
            with open(path, encoding="utf-8") as f:
                return [ln.strip() for ln in f if ln.strip()]
        except OSError:
            return []

    def display(self, total_input, failed_count):
        resolved_count = len(self._lines("resolved"))
        unresolved_count = len(self._lines("unresolved"))

        takeover_lines = self._lines("takeover")
        dangling = [
            ln[len("DANGLING|"):] for ln in takeover_lines if ln.startswith("DANGLING|")
        ]
        ns_takeover = [
            ln[len("NS_TAKEOVER|"):] for ln in takeover_lines if ln.startswith("NS_TAKEOVER|")
        ]

        csp_lines = self._lines("csp")
        aws_count = sum(1 for ln in csp_lines if "resolved to aws IPs" in ln)
        gcp_count = sum(1 for ln in csp_lines if "resolved to gcp IPs" in ln)
        azure_count = sum(1 for ln in csp_lines if "resolved to azure IPs" in ln)

        classified = {}
        unclassified_count = 0
        for line in dangling:
            parts = line.split("|")
            if len(parts) >= 5:
                _orig, current, category, recommendation, evidence = parts[:5]
                if category == "unknown":
                    unclassified_count += 1
                else:
                    classified.setdefault(category, []).append(
                        (current, recommendation, evidence)
                    )

        classified_count = sum(len(v) for v in classified.values())
        total_candidates = classified_count + unclassified_count + len(ns_takeover)

        bar = "=" * 64
        thin = "-" * 64

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

            if classified_count:
                print()
                print(f"  Classified dangling CNAMEs ({classified_count})")
                for category, entries in sorted(classified.items()):
                    print(f"    [{category}]")
                    for current, rec, evidence in entries:
                        print(f"      {current}")
                        print(f"        Recommendation : {rec}")
                        print(f"        Evidence       : {evidence}")

            if ns_takeover:
                print()
                print(f"  NS Takeover candidates ({len(ns_takeover)})")
                for line in ns_takeover:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        print(f"    {parts[0]} -> NS: {parts[1]}")

            if unclassified_count:
                print()
                takeover_file = os.path.basename(
                    self._files.get("takeover", "takeover_candidates.txt")
                )
                print(
                    f"  Unclassified dangling CNAMEs : {unclassified_count}"
                    f"  (see {takeover_file})"
                )

        print(thin)
        print(f"  Output : {self._output_dir}")
        print(f"{bar}\n")
