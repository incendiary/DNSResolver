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

    async def classify(self, domain, resolved_ips):
        """
        Report the two things DNS can actually establish about a resolution.

        Returns one of:

        `None`
            The zone does not answer for random names. The resolution stands on
            its own and nothing is claimed about it.

        `"WILDCARD"`
            Every address matches ones the probe observed. This resolution is a
            catch-all answer — the strongest statement available.

        `"WILDCARD_ZONE"`
            The zone answers for anything, but these addresses were not among
            those observed. Two causes are indistinguishable here: a catch-all
            served from a pool larger than the probe sampled, or a genuine host.
            Either way the resolution is not evidence the name exists, because
            everything in this zone resolves.

        Separating the two matters because the earlier single verdict conflated
        them. Testing addresses against a sampled set silently misses catch-alls
        behind large rotating fleets, and reporting only that test made a miss
        look like a clean result. The zone-level fact is always reliable; the
        address-level one is precise but incomplete. Both are reported so the
        consumer can weigh them rather than inherit a false binary.
        """
        wildcard = await self.wildcard_ips(domain)
        if not wildcard:
            return None
        if resolved_ips and set(resolved_ips).issubset(wildcard):
            return "WILDCARD"
        return "WILDCARD_ZONE"

    async def is_wildcard_resolution(self, domain, resolved_ips):
        """
        True only for a confirmed catch-all answer.

        Retained for callers that want the high-confidence signal alone; prefer
        `classify` where the zone-level fact also matters.
        """
        return await self.classify(domain, resolved_ips) == "WILDCARD"
