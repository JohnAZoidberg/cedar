#!/bin/sh
# Build the cedar web UI into web/www (serve that directory over HTTPS, or
# from localhost, for WebUSB to be available).
#
# Needs the wasm32 target and a wasm-bindgen CLI matching the wasm-bindgen
# crate version in Cargo.lock:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version "$(web/build.sh --wasm-bindgen-version)" --locked
set -eu
cd "$(dirname "$0")/.."

# The wasm-bindgen crate version locked in Cargo.lock; the CLI must match it.
want=$(awk '$0 == "name = \"wasm-bindgen\"" { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)
if [ "${1:-}" = "--wasm-bindgen-version" ]; then
    echo "$want"
    exit 0
fi

have=$(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2 || true)
if [ "$have" != "$want" ]; then
    echo "error: need wasm-bindgen CLI $want (found: ${have:-none}). Install it with:" >&2
    echo "  cargo install wasm-bindgen-cli --version $want --locked" >&2
    exit 1
fi

cargo build -p cedar-web --release --target wasm32-unknown-unknown
wasm-bindgen --target web --no-typescript --out-dir web/www/pkg \
    target/wasm32-unknown-unknown/release/cedar_web.wasm

echo "Built web/www. Try it with: python3 -m http.server -d web/www 8000"
