#!/bin/bash
set -euo pipefail

HEX_FILE="${1:-/tmp/client_hello.hex}"
TARGET_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -f "${HEX_FILE}" ]; then
    echo "Usage: $0 <path-to-client-hello-hex>"
    echo "File not found: ${HEX_FILE}"
    exit 1
fi

echo "Injecting ClientHello from ${HEX_FILE} ..."
export KANOTLS_CLIENT_HELLO_PATH="${HEX_FILE}"

cd "${TARGET_DIR}"
cargo build --release
echo "Build complete with custom ClientHello template"
