# DNSResolver Lambda container image
#
# Architecture: arm64 (Graviton) — ~20% cheaper than x86_64 for equivalent workloads.
# Change to public.ecr.aws/lambda/python:3.12 for x86_64.
#
# pycares bundles a native C extension (libcares). Using a container image
# avoids the manylinux wheel compatibility issues that arise with Lambda layers.
#
# Build:
#   docker build --platform linux/arm64 -t dnsresolver-lambda .
#
# Push to ECR and deploy:
#   aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
#   docker tag dnsresolver-lambda <account>.dkr.ecr.<region>.amazonaws.com/dnsresolver-lambda:latest
#   docker push <account>.dkr.ecr.<region>.amazonaws.com/dnsresolver-lambda:latest

FROM public.ecr.aws/lambda/python:3.12-arm64

COPY requirements-lambda.txt ./
RUN pip install --no-cache-dir -r requirements-lambda.txt

COPY . .

CMD ["lambda_handler.handler"]
