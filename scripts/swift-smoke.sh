#!/usr/bin/env bash
# Compile and RUN the Swift bindings against the host (macOS) build of the
# library, so CI proves the Swift API works, not just that it compiles.
# Needs the output of scripts/build-ios.sh (bindings + headers) and macOS.
#
#   scripts/swift-smoke.sh [ios-build-dir]     (default: build/ios)
set -euo pipefail
cd "$(dirname "$0")/.."
IOS="${1:-build/ios}"
OUT=build/swift-smoke
rm -rf "$OUT" && mkdir -p "$OUT"

cargo build --release -p perseverus-sdk --lib     # host dylib (already built by build-ios.sh)

# A stand-in server that only answers GET /v1/meta, on this machine (the SDK
# only allows clearnet to localhost).
PORT=18431
python3 - "$PORT" <<'PY' &
import http.server, json, sys
META = {"api_version": "1.0", "min_client_version": "0.0.0",
        "server_pubkey_hex": "641946251b0dd34a770b6a567cc393c281ee15c28e2a44743e24a1aeb1f8d695",
        "current_month": 202610}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(META).encode() if self.path == "/v1/meta" else b'{"error":{"code":"not_found","message":"stand-in"}}'
        self.send_response(200 if self.path == "/v1/meta" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
sleep 1

swiftc -O -module-name PerseverusSwiftSmoke \
  -I "$IOS/headers" \
  -L target/release -lperseverus_sdk \
  "$IOS/swift/perseverus_sdk.swift" scripts/swift-smoke/main.swift \
  -o "$OUT/smoke"

DYLD_LIBRARY_PATH="$PWD/target/release" "$OUT/smoke" "http://127.0.0.1:$PORT"
