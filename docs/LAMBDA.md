# AWS Lambda deployment

This document covers the full Lambda deployment walkthrough for DNSResolver, moved out of the main README for brevity. See the [README](../README.md) for CLI usage.

DNSResolver can run as a Lambda function triggered by an S3 PutObject event. Upload a domains file to the input bucket to start a run; results are written back to S3 when it completes.

> **Where the deployment machinery lives.** This repository keeps `lambda_handler.py` as the
> **reference entry point** only. The container image (`Dockerfile`) and the build-and-push pipeline
> are maintained in a **separate deployment project**, so this repo stays a clean CLI tool. The steps
> below are the reference procedure — run them from that project, which supplies the image definition.

### Design decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Packaging | Container image | `pycares` bundles a native C extension — container images avoid the manylinux wheel compatibility issues that affect Lambda layers |
| Architecture | arm64 (Graviton) | ~20% cheaper than x86_64 for equivalent workloads; change the `FROM` line in the deployment project's Dockerfile for x86_64 |
| Runtime | Python 3.12 | Latest Lambda-supported version |
| Logging | stdout only | Lambda captures stdout to CloudWatch automatically; no log file is written |
| Evidence collection | Disabled | `dig` and `nslookup` are not available in the Lambda runtime |
| Intermediate storage | `/tmp` | Lambda provides up to 10 GB of ephemeral storage; results are uploaded to S3 at the end of the run |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OUTPUT_BUCKET` | input bucket | S3 bucket for results |
| `OUTPUT_PREFIX` | `results/` | S3 key prefix for results |
| `NAMESERVERS` | system resolvers | Comma-separated custom resolvers, e.g. `8.8.8.8,1.1.1.1` |
| `MAX_THREADS` | `50` | Concurrent domain tasks |
| `TIMEOUT` | from `config.json` | DNS query timeout in seconds |
| `RETRIES` | from `config.json` | Retry attempts for failed domains |
| `VERBOSE` | `false` | Set to `true` for verbose CloudWatch logging |

### IAM permissions

The Lambda execution role needs:
- `s3:GetObject` on the input bucket
- `s3:PutObject` on the output bucket

### Step-by-step setup

Replace `<account>`, `<region>`, `<input-bucket>`, and `<output-bucket>` throughout.

**1. Create the ECR repository**
```bash
aws ecr create-repository \
  --repository-name dnsresolver-lambda \
  --region <region>
```

**2. Build and push the container image**

> Run from the deployment project, which holds the Dockerfile.
```bash
# Build for arm64 (cross-compile if you're on an x86 machine)
docker build --platform linux/arm64 -t dnsresolver-lambda .

# Authenticate and push
aws ecr get-login-password --region <region> \
  | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com

docker tag dnsresolver-lambda \
  <account>.dkr.ecr.<region>.amazonaws.com/dnsresolver-lambda:latest

docker push \
  <account>.dkr.ecr.<region>.amazonaws.com/dnsresolver-lambda:latest
```

**3. Create the IAM execution role**
```bash
# Create role
aws iam create-role \
  --role-name dnsresolver-lambda-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach basic Lambda execution policy (CloudWatch Logs)
aws iam attach-role-policy \
  --role-name dnsresolver-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Allow S3 access (adjust bucket ARNs as needed)
aws iam put-role-policy \
  --role-name dnsresolver-lambda-role \
  --policy-name dnsresolver-s3 \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::<input-bucket>/*"
      },
      {
        "Effect": "Allow",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::<output-bucket>/*"
      }
    ]
  }'
```

**4. Create the Lambda function**
```bash
aws lambda create-function \
  --function-name dnsresolver \
  --package-type Image \
  --code ImageUri=<account>.dkr.ecr.<region>.amazonaws.com/dnsresolver-lambda:latest \
  --role arn:aws:iam::<account>:role/dnsresolver-lambda-role \
  --architectures arm64 \
  --memory-size 512 \
  --timeout 900 \
  --environment 'Variables={
    OUTPUT_BUCKET=<output-bucket>,
    OUTPUT_PREFIX=results,
    NAMESERVERS=8.8.8.8,1.1.1.1,
    MAX_THREADS=50,
    RETRIES=2
  }'
```

> **Memory and timeout:** 512 MB is sufficient for most domain lists up to a few thousand entries. Increase memory for larger lists. Timeout is set to 900 seconds (Lambda maximum).

**5. Add the S3 trigger**

First, grant S3 permission to invoke the function:
```bash
aws lambda add-permission \
  --function-name dnsresolver \
  --statement-id s3-invoke \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn arn:aws:s3:::<input-bucket>
```

Then configure the bucket notification (replace `<input-bucket>`):
```bash
aws s3api put-bucket-notification-configuration \
  --bucket <input-bucket> \
  --notification-configuration '{
    "LambdaFunctionConfigurations": [{
      "LambdaFunctionArn": "arn:aws:lambda:<region>:<account>:function:dnsresolver",
      "Events": ["s3:ObjectCreated:*"],
      "Filter": {
        "Key": {"FilterRules": [{"Name": "prefix", "Value": "domains/"}]}
      }
    }]
  }'
```

Any file uploaded to `s3://<input-bucket>/domains/` will now trigger a run automatically.

**6. Run a scan**
```bash
aws s3 cp domains.txt s3://<input-bucket>/domains/domains.txt
# Results appear in s3://<output-bucket>/results/<timestamp>/ when complete
```

**7. Updating the function after a code change**

> Run from the deployment project, which holds the Dockerfile.
```bash
docker build --platform linux/arm64 -t dnsresolver-lambda . && \
docker push <account>.dkr.ecr.<region>.amazonaws.com/dnsresolver-lambda:latest && \
aws lambda update-function-code \
  --function-name dnsresolver \
  --image-uri <account>.dkr.ecr.<region>.amazonaws.com/dnsresolver-lambda:latest
```

### Trigger configuration

Configure an S3 event notification on the input bucket for `s3:ObjectCreated:*` events, filtered to the prefix where you drop domain files (e.g. `domains/`). The Lambda handler reads the bucket and key from the event record automatically.

### Pipeline integration

```
EventBridge (daily cron)
    → ECS Fargate task (subfinder/amass enumeration)
        → S3: domains/domains.txt          ← triggers Lambda
            → Lambda (DNSResolver)
                → S3: results/<timestamp>/
                    → downstream Lambda (claim dangling resources)
```

