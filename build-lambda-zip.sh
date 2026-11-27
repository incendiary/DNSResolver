#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${PYTHON_BIN:-python3.12}"
stage_dir="$(mktemp -d)"
trap 'rm -rf "$stage_dir"' EXIT

"$python_bin" -m pip install \
  --require-hashes \
  --platform manylinux_2_28_x86_64 \
  --platform manylinux2014_x86_64 \
  --python-version 3.12 \
  --implementation cp \
  --only-binary=:all: \
  --target "$stage_dir" \
  -r "$repo_dir/requirements.lock"

cp -R "$repo_dir/classes" "$repo_dir/imports" "$stage_dir/"
cp "$repo_dir/resolver.py" "$repo_dir/lambda_handler.py" \
  "$repo_dir/version.py" "$repo_dir/config.json" "$stage_dir/"
find "$stage_dir" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$stage_dir" -type f -name '*.pyc' -delete

mkdir -p "$repo_dir/build"
rm -f "$repo_dir/build/dnsresolver-lambda.zip"
(cd "$stage_dir" && zip -X -qr "$repo_dir/build/dnsresolver-lambda.zip" .)
