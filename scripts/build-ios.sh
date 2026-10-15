#!/usr/bin/env bash
# Build the SDK as an XCFramework for iOS (device + Apple-silicon simulator)
# and generate the Swift bindings. Run on macOS with Xcode installed.
#
#   scripts/build-ios.sh [out-dir]              (default: build/ios)
#
# Output:
#   <out>/PerseverusSDKFFI.xcframework   → add to the Xcode project (or a Swift package)
#   <out>/swift/perseverus_sdk.swift     → add to your Swift sources
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-build/ios}"
rm -rf "$OUT" && mkdir -p "$OUT/swift" "$OUT/headers"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo build --release -p perseverus-sdk --lib --target aarch64-apple-ios
cargo build --release -p perseverus-sdk --lib --target aarch64-apple-ios-sim

# Bindings are read from a host (macOS) build of the same library.
cargo build --release -p perseverus-sdk --lib
cargo run -q -p perseverus-sdk --features bindgen --bin uniffi-bindgen -- \
  generate --library target/release/libperseverus_sdk.dylib \
  --language swift --out-dir "$OUT/swift"

# The XCFramework carries the C header and a module map named module.modulemap.
mv "$OUT/swift/perseverus_sdkFFI.h" "$OUT/headers/"
mv "$OUT/swift/perseverus_sdkFFI.modulemap" "$OUT/headers/module.modulemap"

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libperseverus_sdk.a -headers "$OUT/headers" \
  -library target/aarch64-apple-ios-sim/release/libperseverus_sdk.a -headers "$OUT/headers" \
  -output "$OUT/PerseverusSDKFFI.xcframework"

test -s "$OUT/swift/perseverus_sdk.swift"
test -d "$OUT/PerseverusSDKFFI.xcframework"
echo "iOS build ready in $OUT"
