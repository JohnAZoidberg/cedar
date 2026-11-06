#!/bin/sh
# Build the cedar web UI into web/www (serve that directory over HTTPS, or
# from localhost, for WebUSB to be available).
#
# Needs the wasm32 target and a wasm-bindgen CLI matching the wasm-bindgen
# crate version in Cargo.lock:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version <version from Cargo.lock> --locked
set -eu
cd "$(dirname "$0")/.."

cargo build -p cedar-web --release --target wasm32-unknown-unknown
wasm-bindgen --target web --no-typescript --out-dir web/www/pkg \
    target/wasm32-unknown-unknown/release/cedar_web.wasm

echo "Built web/www. Try it with: python3 -m http.server -d web/www 8000"
