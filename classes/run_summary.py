from classes.records import CspMatch, Dangling, NsTakeover, Resolution, Unresolved


class RunSummary:
    def __init__(self, records, output_dir, version=None):
        self._records = records
        self._output_dir = output_dir
        self._version = version

    def _of(self, kind):
        return [r for r in self._records if isinstance(r, kind)]

    def display(self, total_input, failed_count):
        resolved = self._of(Resolution)
        resolved_count = len(resolved)
        wildcard_count = sum(1 for r in resolved if r.wildcard == "WILDCARD")
        wildcard_zone_count = sum(1 for r in resolved if r.wildcard == "WILDCARD_ZONE")
        unresolved_count = len(self._of(Unresolved))

        dangling = self._of(Dangling)
        ns_takeover = self._of(NsTakeover)

        # Wildcard matches are counted, but kept out of the target breakdown
        # below. In a zone that answers for anything, an address cannot be
        # attributed to the domain rather than the platform, including where the
        # probe simply did not sample that part of a rotating pool.
        csp_matches = self._of(CspMatch)
        csp_wildcard_count = sum(1 for m in csp_matches if m.wildcard)
        csp_records = [m for m in csp_matches if not m.wildcard]

        aws_count = sum(1 for m in csp_records if m.provider == "aws")
        gcp_count = sum(1 for m in csp_records if m.provider == "gcp")
        azure_count = sum(1 for m in csp_records if m.provider == "azure")

        # Region and service are what an operator acts on, so surface the
        # breakdown rather than a bare provider tally.
        csp_breakdown = {}
        for m in csp_records:
            key = (m.provider, m.region, m.service)
            csp_breakdown[key] = csp_breakdown.get(key, 0) + 1

        classified = {}
        unclassified = []
        for d in dangling:
            if d.category == "unknown":
                unclassified.append((d.origin, d.target, d.hops, d.chain))
            else:
                classified.setdefault(d.category, []).append(
                    (d.target, d.recommendation, d.evidence, d.hops, d.chain)
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
                f"    confirmed catch-all: {wildcard_count:>6,}"
                "  (matched the zone's wildcard answer)"
            )
        if wildcard_zone_count:
            print(
                f"    in catch-all zone  : {wildcard_zone_count:>6,}"
                "  (zone answers for anything — unverifiable)"
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
                "  (catch-all zones — cannot attribute to the domain)"
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
                    for current, rec, evidence, depth, chain in entries:
                        print(f"      {current}")
                        print(f"        Recommendation : {rec}")
                        print(f"        Evidence       : {evidence}")
                        if depth > 0 and chain:
                            print(
                                f"        Chain ({depth} hop{'s' if depth != 1 else ''})  : {chain}"
                            )

            if ns_takeover:
                print()
                print(f"  NS Takeover candidates ({len(ns_takeover)})")
                for ns in ns_takeover:
                    root = ns.origin
                    if ns.nameserver == "-":
                        print(f"    {root} -> NS: {ns.domain}")
                        print(
                            "          Why    : Name has NS records but no address records"
                        )
                        continue
                    print(f"    {root} -> NS: {ns.domain} (nameserver {ns.nameserver})")
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
                for root_domain, cname_target, depth, chain in unclassified:
                    print(f"    [?] {root_domain}")
                    print(f"          CNAME target : {cname_target}")
                    if depth > 0 and chain:
                        print(
                            f"          Chain ({depth} hop{'s' if depth != 1 else ''})  : {chain}"
                        )
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
