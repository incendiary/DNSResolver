"""Benchmark the real CSP matcher (perform_csp_checks) on a synthetic catalogue.

Standard library plus the repo's own modules. No network, no real provider data.
Run from the repository root: python bench/bench_matcher.py [--n N] [--large]
"""

import argparse
import asyncio
import ipaddress
import logging
import os
import platform
import random
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from classes.domain_processing_context import DomainProcessingContext  # noqa: E402
from imports.cloud_ip_ranges import ProviderCatalogue  # noqa: E402
from imports.cloud_service_provider_checks import perform_csp_checks  # noqa: E402

SIZES = {"aws": 30000, "azure": 15000, "gcp": 10000}  # about 55,000 prefixes
SEED = 14
CDN_ADDRESSES = 5  # shared by many hostnames
CDN_SHARE = 0.2  # fraction of hostnames that use a shared CDN address
MATCH_SHARE = 0.5  # fraction of the remaining hostnames that match a prefix


def _prefix(rng, v6):
    if v6:
        length = rng.randint(32, 64)
        base = (0x2 << 124) | rng.getrandbits(124)  # inside 2000::/4
        return ipaddress.IPv6Network((base, length), strict=False)
    length = rng.randint(16, 28)
    base = rng.randrange(1, 224) << 24 | rng.getrandbits(24)  # below 224.0.0.0
    return ipaddress.IPv4Network((base, length), strict=False)


def build_catalogues(rng):
    """Return ({provider: ProviderCatalogue}, [every ip_network])."""
    catalogues, nets = {}, []
    for name, size in SIZES.items():
        v4, v6, meta = [], [], {}
        for _ in range(size):
            net = _prefix(rng, rng.random() < 0.25)
            cidr = str(net)
            if cidr in meta:
                continue
            (v6 if net.version == 6 else v4).append(cidr)
            nets.append(net)
            region = f"region-{rng.randrange(30)}"
            service = rng.choice(["AMAZON", "EC2", "CLOUDFRONT", "AzureCloud", "GCE"])
            meta[cidr] = [(region, service, region if name == "aws" else "unknown")]
        catalogues[name] = ProviderCatalogue(
            provider=name,
            ipv4_ranges=v4,
            ipv6_ranges=v6,
            metadata=meta,
            status="live",
            usable=True,
            source_url="https://example.com",
            retrieved_at=None,
            snapshot_id=None,
        )
    return catalogues, nets


def _inside(rng, net):
    return str(net[rng.randrange(net.num_addresses)])


def build_workload(rng, nets, n):
    """n (hostname, address) pairs, and the number of distinct addresses."""
    cdn = [_inside(rng, rng.choice(nets)) for _ in range(CDN_ADDRESSES)]
    pairs = []
    for i in range(n):
        if rng.random() < CDN_SHARE:
            ip = rng.choice(cdn)
        elif rng.random() < MATCH_SHARE:
            ip = _inside(rng, rng.choice(nets))
        elif rng.random() < 0.8:  # 240.0.0.0/4: no prefix is generated there
            ip = str(ipaddress.IPv4Address(rng.randrange(1 << 32) | 0xF0000000))
        else:  # fc00::/7: no prefix is generated there
            ip = str(ipaddress.IPv6Address((0xFC << 120) | rng.getrandbits(120)))
        pairs.append((f"host{i}.example.com", ip))
    return pairs, len({ip for _, ip in pairs})


class _Env:
    """The slice of EnvironmentManager that perform_csp_checks touches."""

    def __init__(self, directory):
        self.records = []
        self._csp_written = set()
        csp = os.path.join(directory, "csp_matches.txt")
        self.output_files = {"standard": {"csp": csp}}
        self._log = logging.getLogger("bench")
        self._log.propagate = False
        self._log.handlers[:] = [
            logging.FileHandler(os.path.join(directory, "run.log"))
        ]
        self._log.setLevel(logging.INFO)

    def log_info(self, message, *args):
        self._log.info(message, *args)


async def measure(catalogues, pairs):
    stall = 0.0
    stop = False

    async def ticker():
        nonlocal stall
        last = time.perf_counter()
        while not stop:
            await asyncio.sleep(0.001)
            now = time.perf_counter()
            stall = max(stall, now - last)
            last = now

    with tempfile.TemporaryDirectory() as directory:
        env = _Env(directory)
        context = DomainProcessingContext(env, catalogues)
        task = asyncio.create_task(ticker())
        await asyncio.sleep(0.01)
        start = time.perf_counter()
        for host, ip in pairs:
            context.set_domain(host)
            perform_csp_checks(context, env, [ip])  # synchronous, as in run()
            await asyncio.sleep(0)  # yield between domains, as gather does
        total = time.perf_counter() - start
        stop = True
        await task
        records = len(env.records)
        env._log.handlers[0].close()
    return total, stall, records


def commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, help="run one size only")
    parser.add_argument("--large", action="store_true", help="also run N=100,000")
    args = parser.parse_args()
    sizes = [args.n] if args.n else [1000, 10000] + ([100000] if args.large else [])

    catalogues, nets = build_catalogues(random.Random(SEED))
    prefixes = sum(len(c.ipv4_ranges) + len(c.ipv6_ranges) for c in catalogues.values())

    rows = [
        "| Hostnames | Distinct addresses | Total (s) "
        "| Mean per distinct address (ms) | Max event-loop stall (ms) | Records |",
        "|---|---|---|---|---|---|",
    ]
    for n in sizes:
        pairs, distinct = build_workload(random.Random(SEED + n), nets, n)
        total, stall, records = asyncio.run(measure(catalogues, pairs))
        rows.append(
            f"| {n} | {distinct} | {total:.2f} | {total / distinct * 1000:.2f} "
            f"| {stall * 1000:.1f} | {records} |"
        )
    print(
        f"Prefixes: {prefixes}; seed {SEED}; commit {commit()}; "
        f"{platform.platform()}, {platform.machine()}, "
        f"Python {platform.python_version()}, {os.cpu_count()} CPUs\n"
    )
    print("\n".join(rows))


if __name__ == "__main__":
    main()
