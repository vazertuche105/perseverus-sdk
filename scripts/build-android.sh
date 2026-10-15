#!/usr/bin/env bash
# Build the SDK's native library for Android and generate the Kotlin bindings.
#
#   scripts/build-android.sh [out-dir]          (default: build/android)
#
# Needs: Rust (rustup), the Android NDK (ANDROID_NDK_HOME set), and
# `cargo install cargo-ndk`. Output:
#   <out>/jniLibs/<abi>/libperseverus_sdk.so   → copy into src/main/jniLibs
#   <out>/kotlin/com/btcmedusa/perseverus/     → add to your Kotlin sources
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-build/android}"
ABIS=(arm64-v8a armeabi-v7a x86_64)

rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
targs=(); for a in "${ABIS[@]}"; do targs+=(-t "$a"); done
cargo ndk "${targs[@]}" -o "$OUT/jniLibs" build --release -p perseverus-sdk --lib

# Bindings are generated from any build of the library; use the arm64 one.
cargo run -q -p perseverus-sdk --features bindgen --bin uniffi-bindgen -- \
  generate --library target/aarch64-linux-android/release/libperseverus_sdk.so \
  --language kotlin --out-dir "$OUT/kotlin"

for a in "${ABIS[@]}"; do test -s "$OUT/jniLibs/$a/libperseverus_sdk.so"; done
test -s "$OUT/kotlin/com/btcmedusa/perseverus/perseverus_sdk.kt"
echo "Android build ready in $OUT"
