# DNSResolver run: COMPLETE

- run: 00000000-0000-0000-0000-000000000001
- contract: 1.0
- started: 2026-01-01T00:00:00Z
- completed: 2026-01-01T00:00:05Z
- actionable targets: 10
- excluded observations: 5

## Actionable targets

### aws / eu-west-2

hostname | ip | services | prefix
--- | --- | --- | ---
aws.example.com | 198.18.0.10 | EC2 | 198.18.0.0/24
multi.example.com | 198.18.1.5 | EC2 | 198.18.1.0/24
v6.example.com | 2001:db8:a::1 | EC2 | 2001:db8:a::/48

### azure / uksouth

hostname | ip | services | prefix
--- | --- | --- | ---
azure.example.com | 203.0.113.30 | AzureCloud | 203.0.113.0/24

### azure / ukwest

hostname | ip | services | prefix
--- | --- | --- | ---
azure.example.com | 203.0.113.30 | AzureCloud | 203.0.113.0/24

### gcp / europe-west2

hostname | ip | services | prefix
--- | --- | --- | ---
gcp.example.com | 198.51.100.20 | Google Cloud | 198.51.100.0/24
gcp.example.com | 2001:db8:b::20 | Google Cloud | 2001:db8:b::/48
multi.example.com | 198.18.1.5 | Google Cloud | 198.18.1.0/25
shared-a.example.com | 198.51.100.77 | Google Cloud | 198.51.100.0/24
shared-b.example.com | 198.51.100.77 | Google Cloud | 198.51.100.0/24

## Excluded observations

kind | count
--- | ---
dangling_cname | 1
ns_takeover | 1
unresolved | 1
wildcard | 1
wildcard_zone | 1

### dangling_cname

- dangle.example.com

### ns_takeover

- nstake.example.com

### unresolved

- gone.example.com

### wildcard

- host1.wild.example.com

### wildcard_zone

- host2.rot.example.com

## Provider catalogues

- aws: complete, snapshot aws-1, retrieved 2026-01-01T00:00:00Z
- azure: complete, snapshot azure-1, retrieved 2026-01-01T00:00:00Z
- gcp: complete, snapshot gcp-1, retrieved 2026-01-01T00:00:00Z
