"""Structured run records.

Each record is built once where a result is found, kept in memory for the
publishers and the run summary, and written to its pipe file through `.pipe()`.
The pipe lines are output contracts (AGENTS.md section 4): changing one is a
breaking change.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Resolution:
    """`[WILDCARD|WILDCARD_ZONE|]domain|ip1|ip2|...` in resolution_results."""

    domain: str
    ips: tuple
    wildcard: str = ""

    def pipe(self):
        prefix = f"{self.wildcard}|" if self.wildcard else ""
        return f"{prefix}{self.domain}|{'|'.join(self.ips)}"


@dataclass(frozen=True)
class CspMatch:
    """One provider attribution of one resolved address in csp_matches."""

    domain: str
    ip: str
    provider: str
    region: str
    service: str
    prefix: str
    border_group: str
    wildcard: str = ""

    def pipe(self):
        prefix = f"{self.wildcard}|" if self.wildcard else ""
        return (
            f"{prefix}{self.domain}|{self.ip}|{self.provider}|{self.region}"
            f"|{self.service}|{self.prefix}|{self.border_group}"
        )


@dataclass(frozen=True)
class Dangling:
    """`DANGLING|...` in takeover_candidates."""

    origin: str
    target: str
    category: str
    recommendation: str
    evidence: str
    hops: int
    chain: str

    def pipe(self):
        return (
            f"DANGLING|{self.origin}|{self.target}|{self.category}"
            f"|{self.recommendation}|{self.evidence}|{self.hops}|{self.chain}"
        )


@dataclass(frozen=True)
class NsTakeover:
    """`NS_TAKEOVER|origin|domain` in takeover_candidates."""

    origin: str
    domain: str

    def pipe(self):
        return f"NS_TAKEOVER|{self.origin}|{self.domain}"


@dataclass(frozen=True)
class Unresolved:
    """`DNS resolution error for domain: error[|additional]` in unresolved_results."""

    domain: str
    error: str
    additional: str = ""

    @property
    def reason(self):
        """Everything after `domain: `, including any `|additional` suffix."""
        return f"{self.error}|{self.additional}" if self.additional else self.error

    def pipe(self):
        return f"DNS resolution error for {self.domain}: {self.reason}"
