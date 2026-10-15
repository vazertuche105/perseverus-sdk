//! JNI surface for the Sparrow integration.
//!
//! This module is a *thin* adapter over [`IssuanceClient`] and
//! [`SpendClient`]. All real orchestration lives in the pure-Rust
//! clients; JNI only handles:
//!
//!   - argument marshalling (JNI types ↔ Rust types)
//!   - handle lifetime (opaque `jlong` pointers kept on the Java side
//!     and freed explicitly via `destroy*` calls)
//!   - panic firewall + error surfacing (every entry point runs inside
//!     `catch_unwind` and throws a `PerseverusException` on failure
//!     rather than unwinding into the JVM).
//!
//! ## Why opaque handles instead of `AutoCloseable` wrappers?
//!
//! Sparrow's existing native bindings use the same pattern (long
//! handles, explicit `close()` from Java), and mixing styles for one
//! new component would annoy whoever eventually reviews the Sparrow
//! fork. Keep it consistent.
//!
//! ## Threading
//!
//! Every handle holds its own `reqwest::blocking::Client` + pinned
//! Groth16 proving key; they're safe to call from any JVM thread but
//! NOT safe to call concurrently against the *same* handle unless the
//! underlying client types are `Sync` (they are today — `SpendClient`
//! contains only `Arc`/`Send`/`Sync` state). If that ever changes we
//! should revisit.
//!
//! ## Feature gate
//!
//! The module is compiled only when `--features jni` is on, so plain
//! `cargo build` still works on machines without a JDK on path.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use ark_ec::CurveGroup;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

type G1Projective = EdwardsProjective;
type G1Affine = EdwardsAffine;
use jni::objects::{JByteArray, JClass, JIntArray, JObjectArray, JString};
use jni::sys::{jbyteArray, jlong, jobjectArray};
use jni::JNIEnv;
use perseverus_core::issuance::IssuedPack;
use perseverus_core::poseidon::PoseidonField;
use rand::rngs::OsRng;

use crate::issuance_client::IssuanceClient;
use crate::spend_client::{SpendClient, last_batch_proof_timings_ms};

/// Compute current YYYYMM from system clock (no chrono dependency).
fn current_month_yyyymm() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs();
    // Days since epoch → approximate year/month.
    // 86400 = seconds per day. This is a simple civil-calendar conversion.
    let days = (secs / 86400) as i64;
    // Algorithm: convert days since 1970-01-01 to (year, month).
    // Adapted from Howard Hinnant's date algorithm.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32) * 100 + m
}

/// Add `n` months to a YYYYMM value with proper year rollover
/// (e.g. add_months_yyyymm(202611, 3) = 202702).
fn add_months_yyyymm(yyyymm: u32, n: u32) -> u32 {
    let year = yyyymm / 100;
    let month = yyyymm % 100; // 1..=12
    let total = year * 12 + month.saturating_sub(1) + n;
    (total / 12) * 100 + (total % 12 + 1)
}

// Pack blob (de)serialization lives in `crate::pack_blob` so the SDK can
// share the exact on-disk format with Sparrow.
use crate::pack_blob::{deserialize_issued_pack, serialize_issued_pack};

/// Fully-qualified Java class name of the checked exception thrown on
/// any error. Sparrow provides the class in
/// `com.sparrowwallet.perseverus.PerseverusException`.
const EXCEPTION_CLASS: &str = "com/sparrowwallet/perseverus/PerseverusException";

// ─────────────────────────────────────────────────────────────────────
// Generic JNI helpers
// ─────────────────────────────────────────────────────────────────────

/// Convert a Rust error into a thrown Java exception and return `None`.
/// Caller converts `None` into the appropriate JNI "nothing" value
/// (`0`, `JObject::null()`, etc.).
fn throw(env: &mut JNIEnv, msg: impl AsRef<str>) {
    // If throwing itself fails we can't do anything useful — just log
    // and drop. The JVM will notice pending-exception state on return.
    let mut msg = msg.as_ref().to_string();
    // A failed connection in Tor mode: say whether Tor is the problem.
    if msg.contains("error sending request") || msg.contains("error connecting") {
        if let Some(hint) = crate::transport::tor_hint() {
            msg = format!("{hint} ({msg})");
        }
    }
    let _ = env.throw_new(EXCEPTION_CLASS, msg);
}

/// Wrap a JNI entry point in `catch_unwind` so a Rust panic becomes a
/// Java exception instead of unwinding across the JNI boundary (which
/// is UB). `on_err` supplies the sentinel value returned when the
/// closure either errors or panics — typically `0` / `ptr::null_mut()`
/// depending on the JNI return type.
fn guarded<T, F: FnOnce(&mut JNIEnv) -> Result<T, String>>(
    env: &mut JNIEnv,
    on_err: T,
    f: F,
) -> T {
    let res = catch_unwind(AssertUnwindSafe(|| f(env)));
    match res {
        Ok(Ok(v)) => v,
        Ok(Err(msg)) => {
            throw(env, msg);
            on_err
        }
        Err(_panic) => {
            throw(env, "Rust panic crossed JNI boundary");
            on_err
        }
    }
}

/// Read a Java `String` into a Rust `String`. Surfaces decode errors
/// as `Err(msg)`.
fn jstring_to_rust(env: &mut JNIEnv, s: JString) -> Result<String, String> {
    env.get_string(&s)
        .map_err(|e| format!("invalid Java string: {}", e))
        .map(|js| js.to_string_lossy().into_owned())
}

/// Read a Java `byte[]` into a `Vec<u8>`.
fn jbytes_to_vec(env: &mut JNIEnv, bs: JByteArray) -> Result<Vec<u8>, String> {
    env.convert_byte_array(&bs)
        .map_err(|e| format!("invalid byte[]: {}", e))
}

/// Render a query result's tag into the string the Java `parseTag` understands.
///
///   * v3 KYC tags → `"Clean"`, `"Coinbase"`, `"CoinJoin"`, `"Unknown"`,
///     `"KycExchange(\"<name>\")"` (unchanged legacy contract).
///   * v5 v3-lean tags → `"V3LEAN:<6-hex>"` where the hex is the 24-bit tag
///     value; the Java side decodes the bits per SPEC.md §2a.
fn format_tag(tag: &crate::query::TagPayload) -> String {
    use crate::query::TagPayload;
    use perseverus_core::KycTag;
    match tag {
        TagPayload::Kyc(KycTag::Clean) => "Clean".to_string(),
        TagPayload::Kyc(KycTag::Coinbase) => "Coinbase".to_string(),
        TagPayload::Kyc(KycTag::CoinJoin) => "CoinJoin".to_string(),
        TagPayload::Kyc(KycTag::Unknown) => "Unknown".to_string(),
        TagPayload::Kyc(KycTag::KycExchange(name)) => format!("KycExchange(\"{}\")", name),
        TagPayload::V3Lean(t) => format!("V3LEAN:{:06x}", t & 0x00FF_FFFF),
    }
}

/// Pick the HTTP client for a server URL. Loopback targets get a direct client
/// with proxies explicitly disabled (so a Tor SOCKS proxy in the environment
/// doesn't try to route 127.0.0.1 through Tor, which refuses loopback). Real
/// hosts (e.g. `.onion`) get the transport-configured client so the proxy
/// still applies.
fn build_http_for(url: &str, timeout: std::time::Duration) -> Result<reqwest::blocking::Client, String> {
    let l = url.to_ascii_lowercase();
    let is_loopback = l.contains("127.0.0.1") || l.contains("//localhost") || l.contains("[::1]");
    if is_loopback {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(timeout)
            .build()
            .map_err(|e| format!("http client: {}", e))
    } else {
        crate::transport::build_client(timeout).map_err(|e| format!("transport: {}", e))
    }
}

/// Allocate a Java `byte[]` from a `&[u8]`. Pushes exception + returns
/// `null` on failure; callers must propagate the `Err`.
fn vec_to_jbytes(env: &mut JNIEnv, bytes: &[u8]) -> Result<jbyteArray, String> {
    env.byte_array_from_slice(bytes)
        .map(|ja| ja.into_raw())
        .map_err(|e| format!("alloc byte[] failed: {}", e))
}

// ─────────────────────────────────────────────────────────────────────
// Parsing helpers
// ─────────────────────────────────────────────────────────────────────

fn parse_pubkey_g1(hex_or_err: &str) -> Result<G1Projective, String> {
    let bytes = hex::decode(hex_or_err)
        .map_err(|e| format!("pubkey_g1 hex decode: {}", e))?;
    let affine = G1Affine::deserialize_compressed(&bytes[..])
        .map_err(|e| format!("pubkey_g1 deserialize: {}", e))?;
    Ok(affine.into())
}

// ─────────────────────────────────────────────────────────────────────
// Handle types
// ─────────────────────────────────────────────────────────────────────

/// Erased handle kept on the Java side. We store a `Box<T>` and pass
/// its raw pointer as a `jlong`. Java is responsible for calling the
/// matching `destroy*` exactly once.
fn into_handle<T>(v: T) -> jlong {
    Box::into_raw(Box::new(v)) as jlong
}

/// SAFETY: caller must guarantee `handle` was produced by a matching
/// `into_handle::<T>` and has not yet been freed.
unsafe fn handle_ref<'a, T>(handle: jlong) -> Option<&'a T> {
    (handle as *mut T).as_ref()
}

/// SAFETY: same as `handle_ref`, and the handle must not be aliased.
unsafe fn drop_handle<T>(handle: jlong) {
    if handle != 0 {
        drop(Box::from_raw(handle as *mut T));
    }
}

// ─────────────────────────────────────────────────────────────────────
// Transport configuration
// ─────────────────────────────────────────────────────────────────────

/// `Native.configureTransport(mode: String, ohttpRelayUrl: String): void`
///
/// Set the privacy transport mode for all subsequent HTTP calls made
/// by client-native (issuance, spend, query, httpGet). This is
/// completely independent of Sparrow's own Tor settings for Bitcoin
/// node connections.
///
/// `mode` is one of `"DIRECT"`, `"TOR"`, `"OHTTP"`, or `"AUTO"`.
///
/// For **TOR** mode, `ohttpRelayUrl` can optionally carry the SOCKS5
/// proxy address (e.g. `"socks5h://127.0.0.1:9050"`). If null or
/// empty, the default `socks5h://127.0.0.1:9050` is used. BTC Medusa's
/// Java layer is responsible for ensuring a Tor SOCKS proxy is
/// available at this address before switching to TOR mode.
///
/// For **OHTTP** mode, `ohttpRelayUrl` must contain the relay URL.
///
/// For **AUTO** mode, `ohttpRelayUrl` optionally carries the OHTTP
/// relay URL for the fallback chain: Tor → OHTTP → Direct. The
/// wallet tries Tor first; if the SOCKS5 proxy is unreachable, it
/// falls back to OHTTP; if no relay was configured or the relay is
/// down, it falls back to Direct as a last resort.
///
/// For **DIRECT** mode, `ohttpRelayUrl` is ignored.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_configureTransport(
    mut env: JNIEnv,
    _class: JClass,
    mode: JString,
    ohttp_relay_url: JString,
) {
    guarded(&mut env, (), |env| {
        let mode_str = jstring_to_rust(env, mode)?;
        // ohttpRelayUrl may be null from Java — handle gracefully.
        let param = if ohttp_relay_url.is_null() {
            None
        } else {
            let s = jstring_to_rust(env, ohttp_relay_url)?;
            if s.trim().is_empty() { None } else { Some(s) }
        };
        crate::transport::configure(
            &mode_str,
            param.as_deref(),
        )
    })
}

/// `Native.httpGet(url: String): String`
///
/// Perform an HTTP GET through the currently configured transport
/// (Direct, Tor SOCKS5, or OHTTP) and return the response body as a
/// UTF-8 string.
///
/// Used by `PerseverusPaymentManager.fetchFallbackPrice()` to privately
/// fetch the BTC price from the BTC Medusa server when the public
/// CoinGecko API is unavailable — routing through Tor ensures the
/// user's IP is never revealed to the server.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_httpGet(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
) -> jni::sys::jstring {
    guarded(&mut env, ptr::null_mut(), |env| {
        let url_str = jstring_to_rust(env, url)?;
        let body = crate::transport::http_get(&url_str)?;
        env.new_string(&body)
            .map(|s| s.into_raw())
            .map_err(|e| format!("jstring alloc: {}", e))
    })
}

/// `Native.httpPost(url: String, jsonBody: String): String`
///
/// Perform an HTTP POST with a JSON body through the currently
/// configured transport (Direct, Tor SOCKS5, or OHTTP) and return
/// the response body as a UTF-8 string.
///
/// Used by the Stripe payment flow to call `/stripe/checkout`,
/// `/stripe/redeem`, etc. on the Perseverus server. Routing through
/// Tor ensures the user's IP is never revealed to the server.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_httpPost(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
    json_body: JString,
) -> jni::sys::jstring {
    guarded(&mut env, ptr::null_mut(), |env| {
        let url_str = jstring_to_rust(env, url)?;
        let body_str = jstring_to_rust(env, json_body)?;
        let resp = crate::transport::http_post(&url_str, &body_str)?;
        env.new_string(&resp)
            .map(|s| s.into_raw())
            .map_err(|e| format!("jstring alloc: {}", e))
    })
}

/// `Native.httpPostIsolated(url: String, jsonBody: String): String`
///
/// Same as `httpPost` but over a FRESH, isolated Tor circuit (when in Tor
/// mode). Used for the BTC proof-of-payment `/subscribe` call so the
/// subscription is unlinkable from the payment broadcast circuit.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_httpPostIsolated(
    mut env: JNIEnv,
    _class: JClass,
    url: JString,
    json_body: JString,
) -> jni::sys::jstring {
    guarded(&mut env, ptr::null_mut(), |env| {
        let url_str = jstring_to_rust(env, url)?;
        let body_str = jstring_to_rust(env, json_body)?;
        let resp = crate::transport::http_post_isolated(&url_str, &body_str)?;
        env.new_string(&resp)
            .map(|s| s.into_raw())
            .map_err(|e| format!("jstring alloc: {}", e))
    })
}

// ─────────────────────────────────────────────────────────────────────
// IssuanceClient bridge
// ─────────────────────────────────────────────────────────────────────

/// `IssuanceClient.create(baseUrl: String, serverPubkeyG1Hex: String): long`
///
/// The created client uses whatever transport mode was last set via
/// `configureTransport`. If Tor mode is active, all issuance HTTP
/// traffic routes through the SOCKS5 proxy.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_issuanceCreate(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    pubkey_hex: JString,
) -> jlong {
    guarded(&mut env, 0, |env| {
        let url = jstring_to_rust(env, base_url)?;
        let hex_s = jstring_to_rust(env, pubkey_hex)?;
        let pubkey = parse_pubkey_g1(&hex_s)?;
        let http = build_http_for(&url, std::time::Duration::from_secs(120))?;
        let client = IssuanceClient::new(url, pubkey).with_http(http);
        Ok(into_handle(client))
    })
}

/// `IssuanceClient.destroy(handle: long)` — free the Rust-side
/// `IssuanceClient`. Double-free is undefined behaviour; Sparrow
/// guards with a single `close()` per instance.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_issuanceDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    unsafe { drop_handle::<IssuanceClient>(handle) }
}

/// `IssuanceClient.issuePack(handle: long, packSize: int, expirationMonth: int): byte[]`
///
/// Returns an opaque binary blob (format documented at the top of
/// this module) that Java stores as-is and hands back to `spend`. We
/// never leak curve types over JNI — everything spend-critical is
/// inside the blob.
///
/// `expirationMonth` is in YYYYMM format (e.g. 202612 = December 2026).
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_issuanceIssuePack(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    pack_size: jni::sys::jint,
    expiration_month: jni::sys::jint,
) -> jbyteArray {
    guarded(&mut env, ptr::null_mut(), |env| {
        if pack_size <= 0 {
            return Err("pack_size must be > 0".into());
        }
        if expiration_month <= 0 {
            return Err("expiration_month must be > 0".into());
        }
        let client = unsafe { handle_ref::<IssuanceClient>(handle) }
            .ok_or_else(|| "null IssuanceClient handle".to_string())?;
        let mut rng = OsRng;
        // start_month = current YYYYMM so the token is immediately active.
        let current_yyyymm = current_month_yyyymm();
        let issued = client
            .issue_pack(pack_size as usize, expiration_month as u32, current_yyyymm, &mut rng)
            .map_err(|e| format!("issue_pack: {}", e))?;
        // Publish an attribution entry in the same call — Sparrow's
        // wallet flow has no meaningful step between the two.
        // The tag is derived from the pack_id for now; CC-paying wallets
        // will override this with their encrypted attribution blob hash.
        let tag = perseverus_core::poseidon::poseidon_hash_many(
            &perseverus_core::poseidon::poseidon_config(),
            &[PoseidonField::from(issued.pack_id)],
        );
        client
            .publish_board_entry(&issued, tag)
            .map_err(|e| format!("publish_board_entry: {}", e))?;
        let bytes = serialize_issued_pack(&issued)?;
        vec_to_jbytes(env, &bytes)
    })
}

/// `IssuanceClient.redeemPack(handle, packSize, expirationMonth, redemptionCode): byte[]`
///
/// Issues a token pack via the `/stripe/redeem` payment-gated endpoint.
/// The blinded tokens and the redemption code are sent in a single HTTP
/// request, maintaining the privacy firewall: the redemption code is the
/// ONLY link between "who paid" and "who got tokens." After the server
/// consumes the code and signs the tokens, that link is severed.
///
/// After issuance, the attribution entry is published to the board via
/// an isolated Tor circuit (same as `issuanceIssuePack`).
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_issuanceRedeemPack(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    pack_size: jni::sys::jint,
    expiration_month: jni::sys::jint,
    redemption_code: JString,
) -> jbyteArray {
    guarded(&mut env, ptr::null_mut(), |env| {
        if pack_size <= 0 {
            return Err("pack_size must be > 0".into());
        }
        if expiration_month <= 0 {
            return Err("expiration_month must be > 0".into());
        }
        let client = unsafe { handle_ref::<IssuanceClient>(handle) }
            .ok_or_else(|| "null IssuanceClient handle".to_string())?;
        let code = jstring_to_rust(env, redemption_code)?;
        let mut rng = OsRng;
        // start_month = current YYYYMM so the token is immediately active.
        let current_yyyymm = current_month_yyyymm();
        let issued = client
            .redeem_pack(pack_size as usize, expiration_month as u32, current_yyyymm, &code, &mut rng)
            .map_err(|e| format!("redeem_pack: {}", e))?;
        // Publish attribution entry via isolated Tor circuit.
        let tag = perseverus_core::poseidon::poseidon_hash_many(
            &perseverus_core::poseidon::poseidon_config(),
            &[PoseidonField::from(issued.pack_id)],
        );
        client
            .publish_board_entry(&issued, tag)
            .map_err(|e| format!("publish_board_entry: {}", e))?;
        let bytes = serialize_issued_pack(&issued)?;
        vec_to_jbytes(env, &bytes)
    })
}

/// `IssuanceClient.redeemBtc(handle, packSize, expirationMonth, code): byte[]`
///
/// Issues a token pack via the `/btc/redeem` endpoint, gated by a scanner-
/// minted silent-payment proof-of-payment code. No board attribution entry is
/// published: on-chain payments are final (no chargebacks), so there is nothing
/// to revoke — and skipping it avoids an extra circuit/round-trip.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_issuanceRedeemBtc(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    pack_size: jni::sys::jint,
    expiration_month: jni::sys::jint,
    code: JString,
) -> jbyteArray {
    guarded(&mut env, ptr::null_mut(), |env| {
        if pack_size <= 0 {
            return Err("pack_size must be > 0".into());
        }
        if expiration_month <= 0 {
            return Err("expiration_month must be > 0".into());
        }
        let client = unsafe { handle_ref::<IssuanceClient>(handle) }
            .ok_or_else(|| "null IssuanceClient handle".to_string())?;
        let code = jstring_to_rust(env, code)?;
        let mut rng = OsRng;
        let current_yyyymm = current_month_yyyymm();
        let issued = client
            .redeem_pack_btc(pack_size as usize, expiration_month as u32, current_yyyymm, &code, &mut rng)
            .map_err(|e| format!("redeem_pack_btc: {}", e))?;
        let bytes = serialize_issued_pack(&issued)?;
        vec_to_jbytes(env, &bytes)
    })
}

/// `IssuanceClient.claimLn(handle, packSize, expirationMonth, nonce): byte[]`
///
/// Claim a Lightning-paid token pack via `/ln/claim`, using the secret nonce
/// from `/ln/invoice` as the bearer credential. No board attribution entry
/// (Lightning payments are final).
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_issuanceClaimLn(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    pack_size: jni::sys::jint,
    expiration_month: jni::sys::jint,
    nonce: JString,
) -> jbyteArray {
    guarded(&mut env, ptr::null_mut(), |env| {
        if pack_size <= 0 {
            return Err("pack_size must be > 0".into());
        }
        if expiration_month <= 0 {
            return Err("expiration_month must be > 0".into());
        }
        let client = unsafe { handle_ref::<IssuanceClient>(handle) }
            .ok_or_else(|| "null IssuanceClient handle".to_string())?;
        let nonce = jstring_to_rust(env, nonce)?;
        let mut rng = OsRng;
        let current_yyyymm = current_month_yyyymm();
        let issued = client
            .redeem_pack_ln(pack_size as usize, expiration_month as u32, current_yyyymm, &nonce, &mut rng)
            .map_err(|e| format!("redeem_pack_ln: {}", e))?;
        let bytes = serialize_issued_pack(&issued)?;
        vec_to_jbytes(env, &bytes)
    })
}

/// `Native.issuanceRedeemYearly(handle, packSize, baseMonth, code): byte[][]`
///
/// Yearly plan: one redemption code → 13 monthly packs in a SINGLE batch
/// request. `baseMonth` (YYYYMM, from the server's /epoch clock) anchors the
/// schedule:
///   - pack 0 (bridge): start=M, expiration=M+1  (covers the partial signup
///     month + all of next month, so signup day never shortchanges you)
///   - packs 1..12: start=expiration=M+1+k  (one calendar month each, M+2..M+13)
/// Returns one serialized pack blob per pack. Each pack's attribution entry is
/// published over an isolated Tor circuit, same as the single-pack path.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_issuanceRedeemYearly(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    pack_size: jni::sys::jint,
    base_month: jni::sys::jint,
    redemption_code: JString,
) -> jni::sys::jobjectArray {
    guarded(&mut env, ptr::null_mut(), |env| {
        if pack_size <= 0 {
            return Err("pack_size must be > 0".into());
        }
        if base_month <= 0 {
            return Err("base_month must be > 0".into());
        }
        let client = unsafe { handle_ref::<IssuanceClient>(handle) }
            .ok_or_else(|| "null IssuanceClient handle".to_string())?;
        let code = jstring_to_rust(env, redemption_code)?;
        let m = base_month as u32;

        // Build the 13-pack (expiration, start) schedule.
        let mut schedule: Vec<(u32, u32)> = Vec::with_capacity(13);
        schedule.push((add_months_yyyymm(m, 1), m)); // bridge: start=M, exp=M+1
        for k in 1..=12u32 {
            let month = add_months_yyyymm(m, 1 + k); // M+2 .. M+13
            schedule.push((month, month));
        }

        let mut rng = OsRng;
        let packs = client
            .redeem_packs(pack_size as usize, &schedule, &code, &mut rng)
            .map_err(|e| format!("redeem_packs: {}", e))?;

        // Publish each pack's attribution entry (isolated circuit) + serialize.
        let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(packs.len());
        for issued in &packs {
            let tag = perseverus_core::poseidon::poseidon_hash_many(
                &perseverus_core::poseidon::poseidon_config(),
                &[PoseidonField::from(issued.pack_id)],
            );
            // Board publish is for CC-chargeback attribution only — the packs
            // are already signed and spendable. A publish failure must NOT
            // discard paid-for packs; log and continue (entries can be
            // re-published later via issuanceRepublish).
            if let Err(e) = client.publish_board_entry(issued, tag) {
                crate::debug_log!("[redeem-yearly] board publish failed (non-fatal): {}", e);
            }
            blobs.push(serialize_issued_pack(issued)?);
        }

        // Return byte[][] (one blob per pack).
        let arr = env
            .new_object_array(blobs.len() as i32, "[B", jni::objects::JObject::null())
            .map_err(|e| format!("new_object_array: {}", e))?;
        for (i, blob) in blobs.iter().enumerate() {
            let jb = env
                .byte_array_from_slice(blob)
                .map_err(|e| format!("byte_array_from_slice: {}", e))?;
            env.set_object_array_element(&arr, i as i32, &jb)
                .map_err(|e| format!("set_object_array_element: {}", e))?;
        }
        Ok(arr.into_raw())
    })
}

/// `IssuanceClient.republishBoardEntry(handle, issuedPackBytes): void`
///
/// Re-publishes the attribution entry from a previously issued pack
/// blob to the server's bulletin board. This is needed after a server
/// restart wipes the in-memory board.
///
/// Errors are surfaced as `PerseverusException`; the Java side can
/// catch and discard packs whose entries can't be re-published.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_issuanceRepublish(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    issued_pack_bytes: JByteArray,
) {
    guarded(&mut env, (), |env| {
        let client = unsafe { handle_ref::<IssuanceClient>(handle) }
            .ok_or_else(|| "null IssuanceClient handle".to_string())?;
        let pack_bytes = jbytes_to_vec(env, issued_pack_bytes)?;
        let issued = deserialize_issued_pack(&pack_bytes)?;
        let tag = perseverus_core::poseidon::poseidon_hash_many(
            &perseverus_core::poseidon::poseidon_config(),
            &[PoseidonField::from(issued.pack_id)],
        );
        client
            .publish_board_entry(&issued, tag)
            .map_err(|e| format!("republish_board_entry: {}", e))?;
        Ok(())
    })
}

// ─────────────────────────────────────────────────────────────────────
// SpendClient bridge
// ─────────────────────────────────────────────────────────────────────

/// `SpendClient.bootstrap(baseUrl: String, serverPubkeyG1Hex: String, cachePath: String): long`
///
/// Fetches the Groth16 proving key over HTTP (`/circuit/pk`) — or
/// loads it from a local cache file if present. Returns an opaque
/// handle.
///
/// If `cachePath` is null or empty, falls back to a fresh download
/// every time (original behaviour).
///
/// Routes through the active transport (Tor SOCKS5 when configured).
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_spendBootstrap(
    mut env: JNIEnv,
    _class: JClass,
    base_url: JString,
    pubkey_hex: JString,
    cache_path: JString,
) -> jlong {
    guarded(&mut env, 0, |env| {
        let url = jstring_to_rust(env, base_url)?;
        let hex_s = jstring_to_rust(env, pubkey_hex)?;
        let pubkey = parse_pubkey_g1(&hex_s)?;
        let http = build_http_for(&url, std::time::Duration::from_secs(120))?;

        // Check if a cache path was provided.
        let cache_str = if cache_path.is_null() {
            String::new()
        } else {
            jstring_to_rust(env, cache_path).unwrap_or_default()
        };

        let client = if cache_str.is_empty() {
            SpendClient::bootstrap_with_http(&url, pubkey, http)
        } else {
            SpendClient::bootstrap_with_cache(&url, pubkey, http, std::path::Path::new(&cache_str))
        }
        .map_err(|e| format!("SpendClient::bootstrap: {}", e))?;

        Ok(into_handle(client))
    })
}

/// `SpendClient.destroy(handle: long)`
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_spendDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    unsafe { drop_handle::<SpendClient>(handle) }
}

/// `SpendClient.spend(handle, issuedPackBytes, spendIdx, inputBytes, currentMonth): byte[]`
///
/// - `issuedPackBytes` is the blob returned by `issuanceIssuePack`.
/// - `inputBytes` is the OPRF input (e.g. `H2C(outpoint)` preimage
///   bytes), bound into γ and into the Groth16 proof via α.
/// - `currentMonth` is the current month in YYYYMM format (e.g. 202604).
///
/// Returns the compressed serialization of γ = k·H2C(input).
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_spendExecute(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    issued_pack: JByteArray,
    spend_idx: jni::sys::jint,
    input: JByteArray,
    current_month: jni::sys::jint,
) -> jbyteArray {
    guarded(&mut env, ptr::null_mut(), |env| {
        if spend_idx < 0 {
            return Err("spend_idx must be >= 0".into());
        }
        if current_month <= 0 {
            return Err("current_month must be > 0".into());
        }
        let client = unsafe { handle_ref::<SpendClient>(handle) }
            .ok_or_else(|| "null SpendClient handle".to_string())?;

        let issued_bytes = jbytes_to_vec(env, issued_pack)?;
        let input_bytes = jbytes_to_vec(env, input)?;

        let issued = deserialize_issued_pack(&issued_bytes)?;

        let mut rng = OsRng;
        let gamma = client
            .spend(&issued, spend_idx as usize, &input_bytes, current_month as u32, &mut rng)
            .map_err(|e| format!("spend: {}", e))?;

        let mut gamma_buf = Vec::new();
        use ark_ec::CurveGroup;
        gamma
            .into_affine()
            .serialize_compressed(&mut gamma_buf)
            .map_err(|e| format!("gamma serialize: {}", e))?;
        vec_to_jbytes(env, &gamma_buf)
    })
}

/// `SpendClient.spendBatch(handle, issuedPacks, spendIndices, inputs, currentMonth): byte[][]`
///
/// Batch variant of `spendExecute`. Each element of the returned
/// `byte[][]` is a compressed γ blob, or `null` if that individual
/// spend failed (the remaining entries are still valid).
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_spendBatchExecute(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    issued_packs: JObjectArray,
    spend_indices: JIntArray,
    inputs: JObjectArray,
    current_month: jni::sys::jint,
) -> jobjectArray {
    guarded(&mut env, ptr::null_mut(), |env| {
        if current_month <= 0 {
            return Err("current_month must be > 0".into());
        }
        let client = unsafe { handle_ref::<SpendClient>(handle) }
            .ok_or_else(|| "null SpendClient handle".to_string())?;

        let len = env
            .get_array_length(&issued_packs)
            .map_err(|e| format!("issued_packs length: {}", e))? as usize;
        let idx_len = env
            .get_array_length(&spend_indices)
            .map_err(|e| format!("spend_indices length: {}", e))? as usize;
        let inp_len = env
            .get_array_length(&inputs)
            .map_err(|e| format!("inputs length: {}", e))? as usize;

        if idx_len != len || inp_len != len {
            return Err(format!(
                "array length mismatch: issued_packs={}, spend_indices={}, inputs={}",
                len, idx_len, inp_len
            ));
        }

        // Read spend_indices into a Rust vec.
        let mut idx_buf = vec![0i32; len];
        env.get_int_array_region(&spend_indices, 0, &mut idx_buf)
            .map_err(|e| format!("get spend_indices: {}", e))?;

        // Deserialize each IssuedPack and collect input byte slices.
        let mut issued_vec: Vec<IssuedPack> = Vec::with_capacity(len);
        let mut input_vec: Vec<Vec<u8>> = Vec::with_capacity(len);
        for i in 0..len {
            let pack_obj: JByteArray = env
                .get_object_array_element(&issued_packs, i as i32)
                .map_err(|e| format!("issued_packs[{}]: {}", i, e))?
                .into();
            let pack_bytes = jbytes_to_vec(env, pack_obj)?;
            issued_vec.push(deserialize_issued_pack(&pack_bytes)?);

            let inp_obj: JByteArray = env
                .get_object_array_element(&inputs, i as i32)
                .map_err(|e| format!("inputs[{}]: {}", i, e))?
                .into();
            input_vec.push(jbytes_to_vec(env, inp_obj)?);
        }

        // Build the spend_items slice that spend_batch expects.
        let spend_items: Vec<(&IssuedPack, usize, &[u8])> = issued_vec
            .iter()
            .zip(idx_buf.iter())
            .zip(input_vec.iter())
            .map(|((issued, &idx), inp)| (issued, idx as usize, inp.as_slice()))
            .collect();

        let mut rng = OsRng;
        let results = client
            .spend_batch(&spend_items, current_month as u32, &mut rng)
            .map_err(|e| format!("spend_batch: {}", e))?;

        // Build byte[][] output. Each entry is a compressed gamma or null.
        let byte_array_class = env
            .find_class("[B")
            .map_err(|e| format!("find class [B: {}", e))?;
        let out = env
            .new_object_array(results.len() as i32, &byte_array_class, JByteArray::default())
            .map_err(|e| format!("alloc byte[][]: {}", e))?;

        for (i, res) in results.into_iter().enumerate() {
            match res {
                Ok(gamma) => {
                    let mut gamma_buf = Vec::new();
                    gamma
                        .into_affine()
                        .serialize_compressed(&mut gamma_buf)
                        .map_err(|e| format!("gamma[{}] serialize: {}", i, e))?;
                    let jarr = env
                        .byte_array_from_slice(&gamma_buf)
                        .map_err(|e| format!("gamma[{}] alloc: {}", i, e))?;
                    env.set_object_array_element(&out, i as i32, &jarr)
                        .map_err(|e| format!("set result[{}]: {}", i, e))?;
                }
                Err(e) => {
                    crate::debug_log!("[spend_batch] entry {} failed: {}", i, e);
                    // null already set by new_object_array default
                }
            }
        }

        Ok(out.into_raw())
    })
}

/// `Native.spendBatchProofTimingsMs(): long[]`
///
/// Returns per-proof Groth16 generation times (in milliseconds) from
/// the most recent `spendBatchExecute` call. The array has one entry
/// per proof, in the same order as the spend items. Call this
/// immediately after `spendBatchExecute` — the data is overwritten on
/// the next batch call.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_spendBatchProofTimingsMs(
    mut env: JNIEnv,
    _class: JClass,
) -> jni::sys::jlongArray {
    let timings = last_batch_proof_timings_ms();
    let longs: Vec<i64> = timings.iter().map(|&t| t as i64).collect();
    let arr = env.new_long_array(longs.len() as i32).unwrap();
    env.set_long_array_region(&arr, 0, &longs).unwrap();
    arr.into_raw()
}

// ─────────────────────────────────────────────────────────────────────
// UTXO privacy query (filter + OPRF flow, Section 7 + Section 9)
// ─────────────────────────────────────────────────────────────────────

/// `Native.queryUtxo(serverUrl, txid, vout, blockHeight, numDecoys, chainTip): String`
///
/// Runs the full 7-step private query pipeline for a single UTXO and
/// returns the KYC tag as a human-readable string:
///   "Clean", "Coinbase", "CoinJoin", "Unknown", "KycExchange(<name>)"
///
/// This is the JNI equivalent of `perseverus-cli query`. Each call is
/// independent — no handle / lifecycle management needed. The server
/// pubkey is fetched automatically from `/server/pubkey`.
///
/// Progress events (filter downloading) are not surfaced through this
/// entry point. For progress reporting, use the handle-based API
/// (`queryCreate` / `queryStep`) — to be added in a future sprint.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_queryUtxo(
    mut env: JNIEnv,
    _class: JClass,
    server_url: JString,
    txid_bytes: JByteArray,
    vout: jni::sys::jint,
    block_height: jni::sys::jint,
    num_decoys: jni::sys::jint,
    chain_tip: jni::sys::jint,
) -> jni::sys::jstring {
    use crate::query::{private_query, NoProgress, QueryConfig};
    use crate::query_client::QueryClient;

    guarded(&mut env, ptr::null_mut(), |env| {
        let url = jstring_to_rust(env, server_url)?;
        let txid_vec = jbytes_to_vec(env, txid_bytes)?;

        if txid_vec.len() != 32 {
            return Err(format!("txid must be 32 bytes, got {}", txid_vec.len()));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_vec);

        if vout < 0 {
            return Err("vout must be >= 0".into());
        }
        if block_height <= 0 {
            return Err("block_height must be > 0".into());
        }
        if chain_tip <= 0 {
            return Err("chain_tip must be > 0".into());
        }

        let config = QueryConfig {
            num_decoys: if num_decoys >= 0 { num_decoys as usize } else { 0 },
            chain_tip: chain_tip as u32,
            ..QueryConfig::default()
        };

        let http = build_http_for(&url, std::time::Duration::from_secs(60))?;
        let client = QueryClient::new(&url).with_http(http);
        let mut rng = OsRng;

        let result = private_query(
            &client,
            txid,
            vout as u32,
            block_height as u32,
            &config,
            &NoProgress,
            &mut rng,
        )
        .map_err(|e| format!("query: {}", e))?;

        // Convert KycTag to the same string format PrivacyController parses,
        // followed by LOG: prefixed lines for filter/decoy activity.
        let tag_str = format_tag(&result.tag);

        let mut out = tag_str;
        for line in &result.log_lines {
            out.push_str("\nLOG:");
            out.push_str(line);
        }

        env.new_string(&out)
            .map(|s| s.into_raw())
            .map_err(|e| format!("jstring alloc: {}", e))
    })
}

/// Authenticated query: takes a pre-computed gamma (compressed G1
/// affine blob from `spendExecute`) and uses it to decrypt the KYC
/// tag without an additional OPRF round. The gamma was already
/// obtained via `SpendClient::spend` → `/oprf/evaluate` (with Groth16
/// proof), so the server has already validated the spend.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_queryUtxoAuthenticated(
    mut env: JNIEnv,
    _class: JClass,
    server_url: JString,
    txid_bytes: JByteArray,
    vout: jni::sys::jint,
    block_height: jni::sys::jint,
    num_decoys: jni::sys::jint,
    chain_tip: jni::sys::jint,
    gamma_bytes: JByteArray,
) -> jni::sys::jstring {
    use crate::query::{private_query_authenticated, NoProgress, QueryConfig};
    use crate::query_client::QueryClient;
    use ark_serialize::CanonicalDeserialize;
    use ark_ed_on_bn254::EdwardsAffine;

    guarded(&mut env, ptr::null_mut(), |env| {
        let url = jstring_to_rust(env, server_url)?;
        let txid_vec = jbytes_to_vec(env, txid_bytes)?;
        let gamma_vec = jbytes_to_vec(env, gamma_bytes)?;

        if txid_vec.len() != 32 {
            return Err(format!("txid must be 32 bytes, got {}", txid_vec.len()));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_vec);

        if vout < 0 {
            return Err("vout must be >= 0".into());
        }
        if block_height <= 0 {
            return Err("block_height must be > 0".into());
        }
        if chain_tip <= 0 {
            return Err("chain_tip must be > 0".into());
        }

        // Deserialize gamma from compressed affine bytes
        let gamma_affine = EdwardsAffine::deserialize_compressed(&gamma_vec[..])
            .map_err(|e| format!("gamma deserialize: {}", e))?;
        let gamma = ark_ed_on_bn254::EdwardsProjective::from(gamma_affine);

        let config = QueryConfig {
            num_decoys: if num_decoys >= 0 { num_decoys as usize } else { 0 },
            chain_tip: chain_tip as u32,
            ..QueryConfig::default()
        };

        let http = build_http_for(&url, std::time::Duration::from_secs(60))?;
        let client = QueryClient::new(&url).with_http(http);
        let mut rng = OsRng;

        let result = private_query_authenticated(
            &client,
            txid,
            vout as u32,
            block_height as u32,
            &config,
            &NoProgress,
            &mut rng,
            gamma,
        )
        .map_err(|e| format!("query: {}", e))?;

        let tag_str = format_tag(&result.tag);

        let mut out = tag_str;
        for line in &result.log_lines {
            out.push_str("\nLOG:");
            out.push_str(line);
        }

        env.new_string(&out)
            .map(|s| s.into_raw())
            .map_err(|e| format!("jstring alloc: {}", e))
    })
}

// ─────────────────────────────────────────────────────────────────────
// Filter prefetch — warm the server's filter cache for a batch of
// block heights in parallel so the query phase is instant.
// ─────────────────────────────────────────────────────────────────────

/// `Native.prefetchFilters(serverUrl: String, blockHeights: int[]): void`
///
/// For each block height, checks if the filter exists on the server,
/// triggers a build if needed, and downloads the filter bytes — all
/// heights are processed concurrently on separate threads. This is
/// fire-and-forget: errors for individual heights are logged but don't
/// fail the call.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_prefetchFilters(
    mut env: JNIEnv,
    _class: JClass,
    server_url: JString,
    block_heights: JIntArray,
) {
    guarded(&mut env, (), |env| {
        let url = jstring_to_rust(env, server_url)?;
        let len = env.get_array_length(&block_heights)
            .map_err(|e| format!("get array length: {}", e))? as usize;
        let mut buf = vec![0i32; len];
        env.get_int_array_region(&block_heights, 0, &mut buf)
            .map_err(|e| format!("get int array region: {}", e))?;
        let height_vec: Vec<u32> = buf.iter().map(|&h| h as u32).collect();

        // Deduplicate.
        let mut unique: Vec<u32> = height_vec.clone();
        unique.sort();
        unique.dedup();

        crate::debug_log!("[prefetch] starting filter prefetch for {} unique heights", unique.len());
        let t0 = std::time::Instant::now();

        // Spawn a thread per height (bounded by the number of UTXOs,
        // typically < 50, so this is fine).
        let handles: Vec<_> = unique
            .into_iter()
            .map(|h| {
                let url = url.clone();
                std::thread::spawn(move || {
                    let ht0 = std::time::Instant::now();
                    let http = match build_http_for(&url, std::time::Duration::from_secs(60)) {
                        Ok(c) => c,
                        Err(e) => {
                            crate::debug_log!("[prefetch] transport error: {}", e);
                            return;
                        }
                    };
                    let client = crate::query_client::QueryClient::new(&url).with_http(http);

                    // Download the filter from the pre-built set and cache it.
                    // Never build on demand — a missing height is out of coverage.
                    match client.download_filter(h) {
                        Ok(data) => {
                            crate::debug_log!(
                                "[prefetch] filter ready ({}KB, {}ms)",
                                data.len() / 1024,
                                ht0.elapsed().as_millis()
                            );
                            crate::query_client::QueryClient::cache_filter(h, data);
                        }
                        Err(e) => {
                            crate::debug_log!("[prefetch] download error: {}", e);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }

        crate::debug_log!(
            "[prefetch] all {} filters ready in {}ms",
            height_vec.len(),
            t0.elapsed().as_millis()
        );

        Ok(())
    });
}

/// `Native.prefetchFiltersWithDecoys(serverUrl, blockHeights, numDecoys, chainTip, scale): void`
///
/// Like `prefetchFilters` but also generates Laplace decoy heights for
/// each real block and prefetches those too. This way the query phase
/// finds everything already in the in-memory cache — zero Tor round
/// trips at query time.
///
/// Resamples when collisions occur so the total count is always exactly
/// `real_count + (real_count × numDecoys)` unique heights.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_prefetchFiltersWithDecoys(
    mut env: JNIEnv,
    _class: JClass,
    server_url: JString,
    block_heights: JIntArray,
    num_decoys: jni::sys::jint,
    chain_tip: jni::sys::jint,
    scale: jni::sys::jdouble,
) {
    guarded(&mut env, (), |env| {
        let url = jstring_to_rust(env, server_url)?;
        let len = env.get_array_length(&block_heights)
            .map_err(|e| format!("get array length: {}", e))? as usize;
        let mut buf = vec![0i32; len];
        env.get_int_array_region(&block_heights, 0, &mut buf)
            .map_err(|e| format!("get int array region: {}", e))?;
        let real_heights: Vec<u32> = buf.iter().map(|&h| h as u32).collect();
        let decoys_per_block = num_decoys.max(0) as usize;
        let tip = chain_tip.max(1) as u32;
        let laplace_scale = if scale > 0.0 { scale } else { 5.0 };

        // Collect all real heights first.
        let mut all_heights: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for &h in &real_heights {
            all_heights.insert(h);
        }
        let real_count = all_heights.len();

        // Target: exactly real_count + (real_count * decoys_per_block) unique heights.
        let target_total = real_count + (real_count * decoys_per_block);
        let mut rng = rand::rngs::OsRng;
        let max_global_attempts = target_total * 200; // safety valve
        let mut attempts = 0usize;

        if decoys_per_block > 0 {
            // Round-robin through real heights, sampling decoys for each,
            // until we reach the target count.
            let real_vec: Vec<u32> = all_heights.iter().copied().collect();
            let mut idx = 0usize;
            while all_heights.len() < target_total && attempts < max_global_attempts {
                let h = real_vec[idx % real_vec.len()];
                // Sample one candidate at a time for fine-grained fill
                let candidates = perseverus_core::laplace::select_decoy_blocks(
                    h, 1, laplace_scale, 1, tip, &mut rng,
                );
                for c in candidates {
                    if c != h && all_heights.insert(c) {
                        // inserted a new unique height
                    }
                }
                idx += 1;
                attempts += 1;
            }
        }

        let mut unique: Vec<u32> = all_heights.into_iter().collect();
        unique.sort();

        crate::debug_log!(
            "[prefetch] starting filter prefetch for {} heights ({} real + {} decoy, {} decoys/block, scale={:.1})",
            unique.len(), real_count, unique.len() - real_count, decoys_per_block, laplace_scale
        );
        let t0 = std::time::Instant::now();
        crate::query_client::prefetch_progress_reset();

        // Single batch request — one Tor round-trip for all filters.
        let http = build_http_for(&url, std::time::Duration::from_secs(180))?;
        let client = crate::query_client::QueryClient::new(&url).with_http(http);

        let total = unique.len();
        crate::debug_log!("[prefetch] requesting {} filters in one batch", total);

        match client.download_filters_batch(&unique) {
            Ok(batch) => {
                let ok_count = batch.filters.len();
                let mut total_bytes = 0usize;
                for (h, data) in batch.filters {
                    total_bytes += data.len();
                    crate::query_client::QueryClient::cache_filter(h, data);
                }
                crate::debug_log!(
                    "[prefetch] batch done: {}/{} filters cached ({} KB total) in {}ms",
                    ok_count, total, total_bytes / 1024, t0.elapsed().as_millis()
                );

                // Heights the server doesn't have are simply out of coverage in
                // a pre-built filter set. Do NOT ask the server to build them:
                // on-demand building is slow (fetches the block from a data
                // source) and, for a v5 deployment, would write an undecodable
                // v3 filter. Leave them uncached — the per-UTXO query reports
                // them as "no filter for this block".
                if !batch.missing.is_empty() {
                    crate::debug_log!(
                        "[prefetch] {} block(s) out of filter coverage (skipped, not built)",
                        batch.missing.len()
                    );
                }
            }
            Err(e) => {
                crate::debug_log!(
                    "[prefetch] batch request failed: {} — falling back to sequential",
                    e
                );
                // Fallback: download whatever the server already has. Never
                // build on demand — filters are a pre-built, served-from-disk
                // set; a missing height is simply out of coverage.
                let mut ok_count = 0usize;
                for (i, &h) in unique.iter().enumerate() {
                    let ht0 = std::time::Instant::now();
                    match client.download_filter(h) {
                        Ok(data) => {
                            crate::debug_log!(
                                "[prefetch] {}/{} ready ({}KB, {}ms)",
                                i + 1, total, data.len() / 1024, ht0.elapsed().as_millis()
                            );
                            crate::query_client::QueryClient::cache_filter(h, data);
                            ok_count += 1;
                        }
                        Err(e) => {
                            crate::debug_log!("[prefetch] {}/{} failed: {}", i + 1, total, e);
                        }
                    }
                }
                crate::debug_log!(
                    "[prefetch] sequential fallback done: {}/{} in {}ms",
                    ok_count, total, t0.elapsed().as_millis()
                );
            }
        }

        Ok(())
    });
}

// ─────────────────────────────────────────────────────────────────────
// Version probe — cheap smoke test Sparrow can hit at startup to
// confirm JNI loading works before attempting any heavyweight call.
// ─────────────────────────────────────────────────────────────────────

/// `Native.prefetchProgress(): long[]` — returns [downloadedBytes, totalBytes].
/// Java polls this from a timer to drive the progress bar during filter download.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_prefetchProgress(
    mut env: JNIEnv,
    _class: JClass,
) -> jni::sys::jlongArray {
    let (downloaded, total) = crate::query_client::prefetch_progress();
    let arr = env.new_long_array(2).unwrap();
    env.set_long_array_region(&arr, 0, &[downloaded as i64, total as i64]).unwrap();
    arr.into_raw()
}

/// `Native.version(): String` — returned as a Java string via `jstring`
/// so we don't fight the borrow checker over `JString` lifetimes.
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_version(
    mut env: JNIEnv,
    _class: JClass,
) -> jni::sys::jstring {
    match env.new_string(env!("CARGO_PKG_VERSION")) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            throw(&mut env, "failed to alloc JNI string");
            ptr::null_mut()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Test helper — returns the compressed hex of the BabyJubJub
// generator. Java-side tests use this to get a known-valid pubkey for
// lifecycle testing (open/close/double-close) without spinning up a
// server or hardcoding an ark-version-dependent constant.
// ─────────────────────────────────────────────────────────────────────

/// `Native.testG1GeneratorHex(): String`
#[no_mangle]
pub extern "system" fn Java_com_sparrowwallet_perseverus_Native_testG1GeneratorHex(
    mut env: JNIEnv,
    _class: JClass,
) -> jni::sys::jstring {
    use ark_ec::{CurveGroup, PrimeGroup};
    guarded(&mut env, ptr::null_mut(), |env| {
        let gen = EdwardsProjective::generator().into_affine();
        let mut buf = Vec::new();
        gen.serialize_compressed(&mut buf)
            .map_err(|e| format!("serialize: {}", e))?;
        let hex_str = hex::encode(&buf);
        env.new_string(&hex_str)
            .map(|s| s.into_raw())
            .map_err(|e| format!("jstring alloc: {}", e))
    })
}
