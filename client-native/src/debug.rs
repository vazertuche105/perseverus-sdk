//! Developer diagnostics, off by default.
//!
//! Set `PERSEVERUS_DEBUG=1` to print progress and timing lines to stderr.
//! On a phone stderr ends up in the system log, so even in debug mode these
//! lines must never contain anything that identifies a coin, a pack or a
//! token: no txid, vout, tag, block height of a real query, pack_id,
//! nullifier or token index. Use `debug_log!` for every diagnostic print.

use std::sync::OnceLock;

/// True when `PERSEVERUS_DEBUG` is `1` or `true` (read once).
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| matches!(std::env::var("PERSEVERUS_DEBUG").as_deref(), Ok("1") | Ok("true")))
}

/// `eprintln!` that only prints when `PERSEVERUS_DEBUG` is set.
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if $crate::debug::enabled() {
            eprintln!($($arg)*);
        }
    };
}
