#!/usr/bin/env bash
# Build build/lanyard.zip: Lanyard code plus Linux (x86_64, Python 3.13) dependencies for AWS Lambda.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rm -rf build && mkdir -p build/pkg
uv export --no-dev --no-hashes --no-emit-project --format requirements-txt \
  | grep -vE '^(uvicorn|uvloop|watchfiles|websockets|httptools)' > build/requirements.txt
uv pip install -q --target build/pkg --python-platform x86_64-manylinux_2_28 --python-version 3.13 \
  --only-binary :all: -r build/requirements.txt
cp -r lanyard servers build/pkg/
find build/pkg -name __pycache__ -prune -exec rm -rf {} +
rm -f build/pkg/servers/sandbox/release_plan.md
rm -rf build/pkg/servers/sandbox/public
(cd build/pkg && zip -qr9 ../lanyard.zip . -x '*.pyc')
du -sh build/lanyard.zip
