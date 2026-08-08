# DNSResolver allocator contract

This document defines the target interface between DNSResolver and a separate
cloud allocator. The JSON Schemas under [`contracts/`](../contracts/) are the
authority; examples and this document are checked against them in CI.

DNSResolver identifies targets. It never allocates an address and never calls a
cloud allocation API.

## Current consumer and compatibility

The current STRIKE CloudClaim consumer reads a top-level JSON array and uses the
fields `hostname`, `ip`, and `region`. It allocates AWS Elastic IP addresses only.
The v1 actionable-target document preserves those fields, so its AWS records can
be consumed without translation.

Every target also carries an explicit `provider`. A consumer **must** reject or
skip providers it does not implement. Treating a GCP scope or Azure region as an
AWS EC2 region is a contract violation. GCP and Azure allocation remain consumer
work; their records are included now so DNSResolver does not need another
breaking schema change when those allocators arrive.

The current pipe-delimited `csp_matches_*.txt` file is not this contract. A later
implementation change will publish the documents defined here while retaining
or deliberately migrating the legacy output.

## Documents

| Document | Schema | Purpose |
|---|---|---|
| Actionable targets | [`allocator-targets-v1.schema.json`](../contracts/allocator-targets-v1.schema.json) | Provider-aware input safe to hand to an allocator |
| DNS observations | [`dns-observations-v1.schema.json`](../contracts/dns-observations-v1.schema.json) | Wildcard, takeover, unresolved, and incomplete observations that must not trigger allocation |
| Run manifest | [`run-manifest-v1.schema.json`](../contracts/run-manifest-v1.schema.json) | Provider completeness, provenance, run status, and output locations |

## Actionable target fields

<!-- schema-fields: allocator-targets-v1 -->
| Field | Meaning |
|---|---|
| `contract_version` | Contract major/minor version; v1 records use `1.0` |
| `hostname` | Authorised DNS name that returned the address |
| `ip` | IPv4 or IPv6 address observed in DNS |
| `provider` | `aws`, `gcp`, or `azure` |
| `region` | Provider-published AWS region, GCP scope, or Azure region; never inferred |
| `services` | Every service classification published for matching prefixes |
| `prefixes` | Every provider prefix that matched the address |
| `network_border_groups` | Every published AWS border group; `unknown` where the provider has no equivalent |
| `dns_record_type` | `A` or `AAAA` |
| `actionability` | Always `actionable` in this document |
<!-- /schema-fields -->

The array form and the `hostname`, `ip`, and `region` names are the compatibility
surface used by the current AWS consumer. Consumers should deduplicate by the
combination of provider, hostname, and IP rather than assuming IP alone is unique.

See the checked [AWS compatibility example](../contracts/examples/allocator-targets-v1.aws.json)
and [multi-cloud example](../contracts/examples/allocator-targets-v1.multicloud.json).

## Observation fields

<!-- schema-fields: dns-observations-v1 -->
| Field | Meaning |
|---|---|
| `contract_version` | Contract major/minor version; v1 records use `1.0` |
| `hostname` | Authorised DNS name observed |
| `kind` | The uncertainty or secondary finding classification |
| `ips` | Any addresses retained as evidence |
| `reasons` | One or more machine-readable explanations for exclusion |
| `actionability` | Always `excluded` in this document |
<!-- /schema-fields -->

Wildcard and wildcard-zone results are observations, never allocator targets.
Dangling CNAME and NS findings are also secondary observations: a different
consumer may investigate them, but the address allocator must ignore them.

## Completion and fail-closed rules

<!-- schema-fields: run-manifest-v1 -->
| Field | Meaning |
|---|---|
| `contract_version` | Contract major/minor version; v1 manifests use `1.0` |
| `run_id` | Unique identifier for one invocation |
| `status` | `complete`, `incomplete`, or `failed` |
| `started_at` | UTC RFC 3339 start time |
| `completed_at` | UTC RFC 3339 completion time |
| `provider_catalogs` | AWS, GCP, and Azure catalogue status and provenance |
| `outputs` | Locations of actionable-target and observation documents |
<!-- /schema-fields -->

A manifest may be `complete` only when all three provider catalogues are usable.
A cached catalogue is usable only when it satisfies the freshness policy that
will be defined with provider-fetch implementation. An incomplete or failed run
must set `outputs.actionable_targets` to `null`; observations are still retained.

The checked examples show both a [complete run](../contracts/examples/run-manifest-v1.complete.json)
and an [incomplete, fail-closed run](../contracts/examples/run-manifest-v1.incomplete.json).

## Versioning

Adding an optional field is backward-compatible. Removing or renaming a field,
changing its meaning or type, adding a required field, or changing the top-level
document shape requires a new major contract version and coordinated consumer
validation before publication.
