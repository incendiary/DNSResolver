import asyncio
import uuid

import aiodns

# Number of random labels probed per zone. More than one guards against a single
# lucky collision with a real host; all must resolve before a zone is called
# wildcarded.
PROBE_COUNT = 2


class WildcardDetector:
    """
    Detects wildcard DNS records so catch-all resolutions can be told apart from
    real hosts.

    A zone serving `*.example.com` resolves every name under it, so an enumerated
    list produces thousands of "resolved" domains that do not exist as hosts. Left
    unflagged, those bury the findings that matter.

    Detection probes random labels that are almost certainly not real. If they all
    resolve, the zone answers for anything and the addresses they return are the
    wildcard address set. Results are cached per zone, so a scan costs one probe
    per zone rather than one per domain.
    """

    def __init__(self, aiodns_resolver, env_manager, probe_count=PROBE_COUNT):
        self.aiodns_resolver = aiodns_resolver
        self.env_manager = env_manager
        self._probe_count = probe_count
        self._cache = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def parent_zone(domain):
        """
        The zone a wildcard would live in for this domain — the name with its
        leftmost label removed.

        `foo.example.com` -> `example.com`, catching `*.example.com`.
        `a.b.example.com` -> `b.example.com`, catching `*.b.example.com`.

        Returns None for a name with no subdomain (`example.com`), which cannot be
        covered by a wildcard in its own zone.
        """
        labels = domain.strip().rstrip(".").split(".")
        if len(labels) <= 2:
            return None
        return ".".join(labels[1:])

    async def wildcard_ips(self, domain):
        """The wildcard address set covering this domain; empty if none."""
        zone = self.parent_zone(domain)
        if zone is None:
            return frozenset()

        async with self._lock:
            if zone not in self._cache:
                self._cache[zone] = await self._probe_zone(zone)
            return self._cache[zone]

    async def _probe_zone(self, zone):
        addresses = set()
        for _ in range(self._probe_count):
            label = uuid.uuid4().hex
            probe = f"{label}.{zone}"
            try:
                answers = await self.aiodns_resolver.query(probe, "A")
            except aiodns.error.DNSError as e:
                # A random name failing to resolve is the normal case: no wildcard.
                self.env_manager.log_info(f"No wildcard for zone {zone} ({probe}): {e}")
                return frozenset()

            resolved = {answer.host for answer in answers}

            # Resolution records both address families, so the wildcard set must
            # too — otherwise a dual-stack catch-all never matches and goes
            # unflagged. A zone with no AAAA is normal and not an error.
            try:
                v6 = await self.aiodns_resolver.query(probe, "AAAA")
                resolved.update(answer.host for answer in v6)
            except aiodns.error.DNSError:
                pass

            if not resolved:
                return frozenset()
            addresses.update(resolved)

        self.env_manager.log_info(
            f"Wildcard DNS detected for zone {zone} -> {sorted(addresses)}"
        )
        return frozenset(addresses)

    async def is_wildcard_resolution(self, domain, resolved_ips):
        """
        True when every address for this domain comes from the zone wildcard, so
        the name resolves only because the zone answers for anything.

        A host resolving to addresses outside the wildcard set is real and is not
        flagged, even if it also shares one with the wildcard.
        """
        if not resolved_ips:
            return False
        wildcard = await self.wildcard_ips(domain)
        if not wildcard:
            return False
        return set(resolved_ips).issubset(wildcard)
