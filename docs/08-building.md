# 8. Building for Android, iOS and desktop

The SDK is a Rust library. Your app ships it as a native library plus generated bindings: Kotlin for Android and JVM, Swift for iOS. **Perseverus doesn't publish prebuilt binaries.** You build them from this repository, at a commit you choose, with the scripts below. The repository's CI runs the same scripts on every push, so they're kept working.

The library is pure Rust with no C dependencies and no TLS library. Production traffic is plain HTTP inside the Tor onion service, which Tor encrypts end to end. The only native toolchains you need are the Android NDK (for its linker) or Xcode.

## Common prerequisites

- Rust stable via [rustup](https://rustup.rs). The build scripts add the cross-compile targets themselves.
- A checkout of this repository. Pin a commit or tag in your build.

## Android

**Also needed:**
- The Android NDK. Set `ANDROID_NDK_HOME`, for example `$ANDROID_HOME/ndk/<version>`.
- `cargo install cargo-ndk`.

```bash
scripts/build-android.sh            # output in build/android
```

Output:
```
build/android/jniLibs/arm64-v8a/libperseverus_sdk.so
build/android/jniLibs/armeabi-v7a/libperseverus_sdk.so
build/android/jniLibs/x86_64/libperseverus_sdk.so
build/android/kotlin/com/btcmedusa/perseverus/perseverus_sdk.kt
```

**Add to your app module:**
1. Copy `jniLibs/*` into `src/main/jniLibs/`. Drop ABIs you don't ship; `x86_64` is only for emulators.
2. Add `perseverus_sdk.kt` to your Kotlin sources. Either regenerate it in your build, or commit it next to the pinned SDK commit.
3. Add JNA, which UniFFI's Kotlin code uses to call the library. Use the `aar` artifact on Android:
   ```kotlin
   dependencies {
       implementation("net.java.dev.jna:jna:5.17.0@aar")
   }
   ```
4. If you use R8/ProGuard, keep JNA and the bindings:
   ```
   -keep class com.sun.jna.** { *; }
   -keep class com.btcmedusa.perseverus.** { *; }
   ```
5. Bundle `pk.bin` in `assets/` (see [Setup](04-integration-guides.md#setup)).

Library size is a few MB per ABI in release mode.

## iOS

**Also needed:** macOS with Xcode.

```bash
scripts/build-ios.sh                # output in build/ios
```

Output:
```
build/ios/PerseverusSDKFFI.xcframework    (device arm64 + Apple-silicon simulator)
build/ios/swift/perseverus_sdk.swift
```

**Add to your app:**
1. Drag `PerseverusSDKFFI.xcframework` into the Xcode project, or wrap it in a binary target of a local Swift package.
2. Add `perseverus_sdk.swift` to the target's sources.
3. Bundle `pk.bin` as a resource and pass its path as `provingKeyPath`.

The Swift API mirrors the Kotlin one: `try Perseverus.connect(config:)`, `analyzeInputs(inputs:options:)`, and so on, with errors thrown as `PerseverusError`.

To run on an Intel-Mac simulator, add the `x86_64-apple-ios` target to the script and combine the two simulator libraries with `lipo` before `-create-xcframework`.

## Kotlin Multiplatform (Blueberry)

UniFFI generates **Kotlin/JVM** code (for Android) and **Swift** code (for iOS), not Kotlin/Native. In a KMP app, the usual pattern is a small `expect`/`actual` interface:
- `commonMain`: an interface with the calls you use, such as `analyzeInputs`, `buyTokens` and `redeem`, and plain data classes for results.
- `androidMain`: implemented with the generated Kotlin bindings.
- `iosMain`: implemented in Swift, or through a thin Swift wrapper exposed to Kotlin/Native.

Third-party generators that emit KMP bindings straight from UniFFI exist. They aren't tested with this SDK.

## Desktop JVM (and the sample)

```bash
cargo build --release -p perseverus-sdk --lib
cargo run -p perseverus-sdk --features bindgen --bin uniffi-bindgen -- \
  generate --library target/release/libperseverus_sdk.so --language kotlin --out-dir bindings/kotlin
```

On macOS the library is `libperseverus_sdk.dylib`. Put it on `jna.library.path` and use `net.java.dev.jna:jna:5.17.0`. `sdk/examples/kotlin-jvm` does all of this through Gradle.

## Optional: https endpoints

If you ever point the SDK at an `https://` server, for example your own proxy, build with the `rustls` feature to get pure-Rust TLS (still no OpenSSL):

```bash
cargo ndk ... build --release -p perseverus-sdk --lib --features rustls
```

## Updating

- Pin a commit or tag of this repository and rebuild when you update. Bindings and the native library must come from the **same** commit, because a mismatch fails at load time with a checksum error.
- The server announces `min_client_version` in `GET /v1/meta`. An SDK older than that throws `Unsupported` at `connect`.
- When the circuit version changes (`circuit.version` in `/v1/meta`), a new `assets/circuit-v<N>/pk.bin` will be added; bundle the one that matches.
