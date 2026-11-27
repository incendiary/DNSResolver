# DNSResolver Lambda package for CloudClaim

This optional Lambda entry point runs the existing DNS-only pipeline. The CLI,
JSON schemas and provider-attribution rules are unchanged. It takes a plain-text
domain list from a versioned S3 object and publishes the existing v1 JSON files.

## Build and deployment boundary

Run `./build-lambda-zip.sh` locally with Python 3.12 and `zip` available.
The script installs the hash-locked runtime dependencies as Linux x86_64 wheels
and writes the ignored `build/dnsresolver-lambda.zip`. It does not call AWS.
Use `PYTHON_BIN=/opt/homebrew/bin/python3.12` if `python3.12` is not on your path.

The module in `terraform/` accepts `name_prefix`, `bucket_name` and the absolute
`package_file` path. CloudClaim's single Terraform root will call this module;
Terraform uploads the ZIP and owns the Lambda, versioned private S3 bucket,
trigger, IAM role and log group. Do not apply this module separately for the
personal MVP. Build the ZIP before `terraform plan` or `terraform apply`.

## Run contract

Upload a UTF-8 file with one authorised hostname per line to
`s3://<bucket_name>/domains/<name>.txt`. The S3 notification includes its object
version; the handler rejects unversioned inputs and reads that exact version.
Each event record writes to `runs/<lambda-request-id>/<record-index>/` in the
same bucket. The handler uploads `run-manifest-v1.json` last, after the files it
references. CloudClaim must consume only a complete manifest and pin the
referenced target object's S3 version for its allocation cycle.

Lambda writes intermediate files under `/tmp`, disables command-line evidence
collection, and uses CloudWatch logs. The module sets a 15-minute timeout and
512 MB memory for the initial tens-of-domains demonstration; these are runtime
limits to check during the owner's AWS acceptance.

Local checks: `pytest -q tests/test_lambda_handler.py`, `ruff check .`,
`ruff format --check .`, `terraform fmt -check terraform`, and
`terraform -chdir=terraform validate` after `terraform init -backend=false`.
These checks do not establish a successful live DNS run in Lambda.
