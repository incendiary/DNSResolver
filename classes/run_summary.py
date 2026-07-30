class RunSummary:
    def __init__(self, output_files, output_dir, version=None):
        self._files = output_files["standard"]
        self._output_dir = output_dir
        self._version = version

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
        resolved_lines = self._lines("resolved")
        resolved_count = len(resolved_lines)
        wildcard_count = sum(1 for ln in resolved_lines if ln.startswith("WILDCARD|"))
        unresolved_count = len(self._lines("unresolved"))

        takeover_lines = self._lines("takeover")
        dangling = [
            ln[len("DANGLING|") :]
            for ln in takeover_lines
            if ln.startswith("DANGLING|")
        ]
        ns_takeover = [
            ln[len("NS_TAKEOVER|") :]
            for ln in takeover_lines
            if ln.startswith("NS_TAKEOVER|")
        ]

        # Handoff records: [WILDCARD|]domain|ip|provider|region|service|prefix|border
        csp_lines = self._lines("csp")
        csp_records = []
        csp_wildcard_count = 0
        for line in csp_lines:
            if line.startswith("WILDCARD|"):
                csp_wildcard_count += 1
                # Counted, but kept out of the target breakdown below: these are
                # the hosting platform's addresses, not claimable targets.
                continue
            fields = line.split("|")
            if len(fields) >= 6:
                csp_records.append(fields)

        aws_count = sum(1 for r in csp_records if r[2] == "aws")
        gcp_count = sum(1 for r in csp_records if r[2] == "gcp")
        azure_count = sum(1 for r in csp_records if r[2] == "azure")

        # Region and service are what an operator acts on, so surface the
        # breakdown rather than a bare provider tally.
        csp_breakdown = {}
        for record in csp_records:
            provider, region, service = record[2], record[3], record[4]
            csp_breakdown[(provider, region, service)] = (
                csp_breakdown.get((provider, region, service), 0) + 1
            )

        classified = {}
        unclassified = []
        for line in dangling:
            parts = line.split("|")
            if len(parts) >= 5:
                _orig, current, category, recommendation, evidence = parts[:5]
                if category == "unknown":
                    unclassified.append((_orig, current))
                else:
                    classified.setdefault(category, []).append(
                        (current, recommendation, evidence)
                    )

        classified_count = sum(len(v) for v in classified.values())
        unclassified_count = len(unclassified)
        total_candidates = classified_count + unclassified_count + len(ns_takeover)

        bar = "=" * 64
        thin = "-" * 64

        version_str = f" v{self._version}" if self._version else ""
        print(f"\n{bar}")
        print(f"  DNSResolver{version_str} — Run Summary")
        print(bar)
        print(f"  Input domains        : {total_input:>6,}")
        print(f"  Resolved             : {resolved_count:>6,}")
        if wildcard_count:
            print(
                f"    of which wildcard  : {wildcard_count:>6,}"
                "  (catch-all zone — resolution proves nothing)"
            )
        print(f"  Unresolved errors    : {unresolved_count:>6,}")
        print(f"  Failed (all retries) : {failed_count:>6,}")
        print()
        csp_target_count = aws_count + gcp_count + azure_count
        if csp_target_count == 0:
            print("  No cloud-hosted addresses found.")
        else:
            print(
                f"  [>] {csp_target_count} CLOUD-HOSTED ADDRESS(ES) — "
                "candidate reclaim targets"
            )
        print(
            f"  CSP matches — AWS: {aws_count}  GCP: {gcp_count}  Azure: {azure_count}"
        )
        if csp_wildcard_count:
            print(
                f"    excluded (wildcard) : {csp_wildcard_count:>4}"
                "  (hosting platform addresses, not targets)"
            )
        if csp_breakdown:
            print("    by region and service:")
            for (provider, region, service), count in sorted(
                csp_breakdown.items(), key=lambda kv: (-kv[1], kv[0])
            ):
                print(f"      {count:>4}  {provider}  {region}  {service}")
        print(thin)

        if total_candidates == 0:
            print("  No takeover candidates detected.")
        else:
            print(
                f"  [!] {total_candidates} TAKEOVER CANDIDATE(S) DETECTED — REVIEW IMMEDIATELY [!]"
            )

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
                        root, ns_host = parts[0], parts[1]
                        print(f"    {root} -> NS: {ns_host}")
                        print(
                            "          Why    : Nameserver does not resolve — registering it gives"
                        )
                        print(
                            f"                   an attacker DNS control over {root} and all its subdomains"
                        )

            if unclassified:
                print()
                print(
                    f"  Unclassified dangling CNAMEs ({unclassified_count}) — investigate manually"
                )
                for root_domain, cname_target in unclassified:
                    print(f"    [?] {root_domain}")
                    print(f"          CNAME target : {cname_target}")
                    print(
                        "          Risk         : Target does not resolve — if it can be claimed,"
                    )
                    print(
                        f"                         an attacker can serve content from {root_domain}"
                    )
                    print(
                        "          Action       : Verify this CNAME is intentional; remove it if not"
                    )

        print(thin)
        print(f"  Output : {self._output_dir}")
        print(f"{bar}\n")
