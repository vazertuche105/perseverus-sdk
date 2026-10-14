//! Native client for the Perseverus privacy oracle.
//!
//! The crate has two faces:
//!
//!   1. A pure-Rust API — currently [`IssuanceClient`] for the Phase 3c
//!      `/issue` round trip, which is what the CLI and integration tests
//!      use directly.
//!   2. A `cdylib` JNI surface for Sparrow (added in a later sprint).
//!
//! Anything spend-side (proof generation, nullifier ledger calls) will
//! land here too once Phase 5 lands. Keep all wallet-facing crypto
//! orchestration in this crate so the JNI layer stays a thin shim.

pub mod issuance_client;
pub mod spend_client;
pub mod query_client;
pub mod query;
pub mod codebook;
pub mod transport;
pub mod pack_blob;

#[cfg(feature = "jni")]
pub mod jni_surface;

pub use issuance_client::{IssuanceClient, IssuanceClientError, PublishResult};
pub use spend_client::{SpendClient, SpendClientError};
pub use query_client::{QueryClient, QueryClientError};
pub use query::{QueryConfig, QueryError, QueryResult, QueryProgress, NoProgress, private_query};
