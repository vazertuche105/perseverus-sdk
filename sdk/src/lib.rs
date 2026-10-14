//! # perseverus-sdk
//!
//! Wallet SDK for BTC Medusa / Perseverus: buy anonymous token packs, then
//! learn the privacy exposure of the inputs a transaction is about to spend —
//! without telling the server which inputs they are.
//!
//! Exposed to Kotlin and Swift through UniFFI. Every method is **blocking**
//! (it does network I/O and, for `analyze_inputs`, ~0.5–1 s of Groth16
//! proving per matched funding transaction), so call it off the main thread
//! (`Dispatchers.IO` on Android).
//!
//! ```kotlin
//! val medusa = Perseverus.connect(Config(
//!     endpoint = "http://medusa…onion",
//!     dataDir = context.filesDir.path,
//!     transport = Transport.Tor(socksProxy = null),   // socks5h://127.0.0.1:9050
//!     expectedServerPubkey = null,
//! ))
//! val p = medusa.buyTokens(PayMethod.LIGHTNING, Plan.ONETIME)   // show p.paymentRequest
//! if (medusa.purchaseStatus(p.purchaseId) == PurchaseState.PAID) medusa.redeem(p.purchaseId)
//! val result = medusa.analyzeInputs(inputs, AnalyzeOptions(decoysPerInput = 8u, chainTip = tip))
//! ```

uniffi::setup_scaffolding!();

pub mod analyze;
pub mod error;
pub mod report;
pub mod store;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ark_ec::CurveGroup;
use ark_ed_on_bn254::EdwardsProjective;
use ark_serialize::CanonicalSerialize;
use perseverus_client_native::{transport, IssuanceClient, QueryClient, SpendClient};
use perseverus_core::poseidon::{poseidon_config, poseidon_hash_many, PoseidonField};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;

pub use analyze::{AnalysisResult, AnalyzeOptions};
pub use error::PerseverusError;
pub use report::{Finding, InputRef, PrivacyReport, Recommendation, ReportError, ReportStatus, Severity, SeverityCounts};
pub use store::PackInfo;

use store::{Store, StoredPurchase};

/// Tokens in a standard pack (matches the server's payment routes).
const PACK_SIZE: u32 = 100;
const HTTP_TIMEOUT: Duration = Duration::from_secs(180);
const PK_CACHE_FILE: &str = "perseverus-circuit-pk.bin";

// ─── Configuration ───────────────────────────────────────────────────

#[derive(Debug, Clone, uniffi::Enum)]
pub enum Transport {
    /// Route everything through a Tor SOCKS proxy (fails closed if Tor is
    /// down). `socks_proxy` defaults to `socks5h://127.0.0.1:9050`.
    Tor { socks_proxy: Option<String> },
    /// Clearnet. Development only: the server sees your IP.
    Direct,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Config {
    /// Server base URL, e.g. the `.onion` service (prod) or a dev host.
    pub endpoint: String,
    /// Directory where the SDK keeps token packs and the cached proving key.
    /// Back it up with the wallet: losing it loses the tokens.
    pub data_dir: String,
    pub transport: Transport,
    /// Optional pinned OPRF public key (hex). If set, `connect` refuses a
    /// server presenting a different key.
    pub expected_server_pubkey: Option<String>,
}

// ─── Purchases ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PayMethod {
    Lightning,
    Card,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Plan {
    /// One token (Lightning only).
    Trial,
    /// One 100-token pack, valid through the end of next month.
    Onetime,
    /// Card subscription; one 100-token pack per month.
    Monthly,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Purchase {
    /// Bearer credential for claiming the pack. The SDK also stores it.
    pub purchase_id: String,
    pub method: PayMethod,
    pub plan: Plan,
    pub tokens: u32,
    /// BOLT11 invoice (Lightning) or checkout URL (Card).
    pub payment_request: String,
    pub amount_sat: Option<u64>,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PurchaseState {
    Pending,
    Paid,
    Expired,
}

// ─── The SDK object ──────────────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct Perseverus {
    base_url: String,
    data_dir: PathBuf,
    server_pubkey: EdwardsProjective,
    store: Store,
    query: QueryClient,
    spend: Mutex<Option<SpendClient>>,
    /// Card redemption codes fetched by `purchase_status`, keyed by purchase id.
    card_codes: Mutex<std::collections::HashMap<String, String>>,
}

#[uniffi::export]
impl Perseverus {
    /// Configure transport, open local storage and fetch (and optionally pin)
    /// the server's OPRF public key.
    #[uniffi::constructor]
    pub fn connect(config: Config) -> Result<Arc<Self>, PerseverusError> {
        let base_url = config.endpoint.trim().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(PerseverusError::InvalidArgument { reason: "endpoint is empty".into() });
        }
        match &config.transport {
            Transport::Direct => {
                if base_url.contains(".onion") {
                    return Err(PerseverusError::InvalidArgument { reason: ".onion endpoints require Transport.Tor".into() });
                }
                transport::configure("DIRECT", None)
            }
            Transport::Tor { socks_proxy } => transport::configure("TOR", socks_proxy.as_deref()),
        }
        .map_err(|m| PerseverusError::InvalidArgument { reason: m })?;

        let data_dir = PathBuf::from(&config.data_dir);
        let store = Store::open(&data_dir)?;
        let query = QueryClient::new(&base_url).with_http(http_for(&base_url, false)?);
        let server_pubkey = query.get_server_pubkey()?;

        if let Some(expected) = config.expected_server_pubkey {
            let got = point_hex(&server_pubkey);
            if !got.eq_ignore_ascii_case(expected.trim()) {
                return Err(PerseverusError::Verification {
                    reason: format!("server pubkey {got} does not match pinned {expected}"),
                });
            }
        }

        Ok(Arc::new(Self {
            base_url,
            data_dir,
            server_pubkey,
            store,
            query,
            spend: Mutex::new(None),
            card_codes: Mutex::new(Default::default()),
        }))
    }

    /// The server's OPRF public key (hex), for pinning on first use.
    pub fn server_pubkey(&self) -> String {
        point_hex(&self.server_pubkey)
    }

    /// Current server epoch month (YYYYMM).
    pub fn current_month(&self) -> Result<u32, PerseverusError> {
        #[derive(Deserialize)]
        struct Epoch {
            month: u32,
        }
        let e: Epoch = self.get_json("/epoch")?;
        Ok(e.month)
    }

    /// Unspent tokens in currently active packs. Local; no network call
    /// except fetching the current month.
    pub fn token_balance(&self) -> Result<u32, PerseverusError> {
        self.store.balance(self.current_month()?)
    }

    pub fn list_packs(&self) -> Result<Vec<PackInfo>, PerseverusError> {
        self.store.packs(self.current_month()?)
    }

    /// Start a purchase. Show `payment_request` to the user (BOLT11 as a QR
    /// code, or open the checkout URL), then poll `purchase_status`.
    pub fn buy_tokens(&self, method: PayMethod, plan: Plan) -> Result<Purchase, PerseverusError> {
        let purchase = match method {
            PayMethod::Lightning => {
                let (plan_str, tokens) = match plan {
                    Plan::Trial => ("onetime", 1u32),
                    Plan::Onetime => ("onetime", PACK_SIZE),
                    Plan::Monthly => {
                        return Err(PerseverusError::Unsupported { reason: "monthly plans are card-only".into() })
                    }
                };
                #[derive(Deserialize)]
                struct Inv {
                    invoice: String,
                    nonce: String,
                    amount_sat: u64,
                    tokens: u32,
                    expires_at: u64,
                }
                let inv: Inv = self.post_json("/ln/invoice", &serde_json::json!({ "plan": plan_str, "tokens": tokens }), false)?;
                Purchase {
                    purchase_id: inv.nonce,
                    method,
                    plan,
                    tokens: inv.tokens,
                    payment_request: inv.invoice,
                    amount_sat: Some(inv.amount_sat),
                    expires_at: Some(inv.expires_at),
                }
            }
            PayMethod::Card => {
                let plan_str = match plan {
                    Plan::Onetime => "onetime",
                    Plan::Monthly => "monthly",
                    Plan::Trial => {
                        return Err(PerseverusError::Unsupported { reason: "the trial is Lightning-only".into() })
                    }
                };
                let mut nonce = [0u8; 16];
                OsRng.fill_bytes(&mut nonce);
                let nonce = hex::encode(nonce);
                #[derive(Deserialize)]
                struct Checkout {
                    checkout_url: String,
                }
                let c: Checkout = self.post_json("/stripe/checkout", &serde_json::json!({ "plan": plan_str, "nonce": nonce }), false)?;
                Purchase {
                    purchase_id: nonce,
                    method,
                    plan,
                    tokens: PACK_SIZE,
                    payment_request: c.checkout_url,
                    amount_sat: None,
                    expires_at: None,
                }
            }
        };
        self.store.add_pending_purchase(StoredPurchase {
            purchase_id: purchase.purchase_id.clone(),
            method: method_str(method).into(),
            plan: plan_str(plan).into(),
            tokens: purchase.tokens,
            created_at: now(),
        })?;
        Ok(purchase)
    }

    /// Purchases started but not yet redeemed (survive app restarts).
    pub fn pending_purchases(&self) -> Result<Vec<String>, PerseverusError> {
        Ok(self.store.pending_purchases()?.into_iter().map(|p| p.purchase_id).collect())
    }

    pub fn purchase_status(&self, purchase_id: String) -> Result<PurchaseState, PerseverusError> {
        let p = self.pending(&purchase_id)?;
        match p.method.as_str() {
            "lightning" => {
                #[derive(Deserialize)]
                struct S {
                    paid: bool,
                    expires_at: u64,
                }
                let s: S = self.get_json(&format!("/ln/status/{purchase_id}"))?;
                Ok(if s.paid {
                    PurchaseState::Paid
                } else if s.expires_at < now() {
                    PurchaseState::Expired
                } else {
                    PurchaseState::Pending
                })
            }
            _ => {
                #[derive(Deserialize)]
                struct S {
                    status: String,
                    redemption_code: Option<String>,
                }
                let s: S = self.get_json(&format!("/stripe/status/{purchase_id}"))?;
                match (s.status.as_str(), s.redemption_code) {
                    ("ready", Some(code)) => {
                        self.card_codes.lock().unwrap_or_else(|e| e.into_inner()).insert(purchase_id, code);
                        Ok(PurchaseState::Paid)
                    }
                    _ => Ok(PurchaseState::Pending),
                }
            }
        }
    }

    /// Claim a paid purchase: blind fresh tokens, get them signed, unblind,
    /// and store the pack locally. The claim goes over an isolated Tor
    /// circuit so it can't be linked to the purchase request by circuit.
    pub fn redeem(&self, purchase_id: String) -> Result<PackInfo, PerseverusError> {
        let p = self.pending(&purchase_id)?;
        let month = self.current_month()?;
        let expiration = add_months(month, 1); // valid through the end of next month
        let issuance = IssuanceClient::new(&self.base_url, self.server_pubkey).with_http(http_for(&self.base_url, true)?);
        let issued = match p.method.as_str() {
            "lightning" => issuance.redeem_pack_ln(p.tokens as usize, expiration, month, &purchase_id, &mut OsRng)?,
            _ => {
                if self.purchase_status(purchase_id.clone())? != PurchaseState::Paid {
                    return Err(PerseverusError::NotPaid);
                }
                let code = self
                    .card_codes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&purchase_id)
                    .ok_or(PerseverusError::NotPaid)?;
                let issued = issuance.redeem_pack(p.tokens as usize, expiration, month, &code, &mut OsRng)?;
                // Card packs publish an attribution entry (chargeback handling),
                // over its own isolated circuit, exactly as Sparrow does.
                let tag = poseidon_hash_many(&poseidon_config(), &[PoseidonField::from(issued.pack_id)]);
                issuance.publish_board_entry(&issued, tag)?;
                issued
            }
        };
        let info = self.store.add_pack(&issued, &p.method, now())?;
        self.store.remove_pending_purchase(&purchase_id)?;
        Ok(info)
    }

    /// Import a pack blob issued elsewhere (e.g. migrated from Sparrow, or
    /// restored from a backup). The blob format is shared with Sparrow.
    ///
    /// `spent` is the per-token used bitmap if the source wallet tracked one
    /// (Sparrow does); tokens marked spent there are never re-used here.
    pub fn import_pack(&self, blob: Vec<u8>, method: String, spent: Option<Vec<bool>>) -> Result<PackInfo, PerseverusError> {
        let issued = perseverus_client_native::pack_blob::deserialize_issued_pack(&blob)
            .map_err(|m| PerseverusError::InvalidArgument { reason: m })?;
        let mut info = self.store.add_pack(&issued, &method, now())?;
        if let Some(spent) = spent {
            info.remaining = self.store.mark_spent(issued.pack_id, &spent)?;
        }
        let month = self.current_month()?;
        info.active = issued.start_month <= month && month <= issued.expiration_month;
        Ok(info)
    }

    /// Analyse the inputs of a transaction before broadcast.
    ///
    /// Spends one token per distinct funding transaction that is found in the
    /// filters. Inputs that are ungraded (excluded by skip rules) or not
    /// covered (no filter yet) cost nothing. Fails with `InsufficientTokens`
    /// before spending anything if the balance is too low.
    pub fn analyze_inputs(&self, inputs: Vec<InputRef>, options: AnalyzeOptions) -> Result<AnalysisResult, PerseverusError> {
        let month = self.current_month()?;
        let make_spend = || self.spend_client();
        let ctx = analyze::Ctx { query: &self.query, spend: &make_spend, store: &self.store, current_month: month };
        analyze::analyze(&ctx, inputs, &options)
    }
}

impl Perseverus {
    fn pending(&self, purchase_id: &str) -> Result<StoredPurchase, PerseverusError> {
        self.store
            .pending_purchases()?
            .into_iter()
            .find(|p| p.purchase_id == purchase_id)
            .ok_or_else(|| PerseverusError::InvalidArgument { reason: format!("unknown purchase {purchase_id}") })
    }

    /// Spend client with the proving key cached on disk, using a fresh
    /// isolated circuit for every analysis.
    fn spend_client(&self) -> Result<SpendClient, PerseverusError> {
        let mut guard = self.spend.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            let http = http_for(&self.base_url, false)?;
            let sc = SpendClient::bootstrap_with_cache(&self.base_url, self.server_pubkey, http, &self.data_dir.join(PK_CACHE_FILE))?;
            *guard = Some(sc);
        }
        Ok(guard.as_ref().unwrap().clone().with_http(http_for(&self.base_url, true)?))
    }

    fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, PerseverusError> {
        let resp = http_for(&self.base_url, false)?.get(format!("{}{}", self.base_url, path)).send()?;
        json_or_error(resp)
    }

    fn post_json<T: serde::de::DeserializeOwned>(&self, path: &str, body: &serde_json::Value, isolated: bool) -> Result<T, PerseverusError> {
        let resp = http_for(&self.base_url, isolated)?.post(format!("{}{}", self.base_url, path)).json(body).send()?;
        json_or_error(resp)
    }
}

fn json_or_error<T: serde::de::DeserializeOwned>(resp: reqwest::blocking::Response) -> Result<T, PerseverusError> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)))
            .unwrap_or(body);
        return Err(PerseverusError::Server { status: status.as_u16(), reason: message });
    }
    resp.json().map_err(|e| PerseverusError::Internal { reason: format!("bad response: {e}") })
}

/// HTTP client for the configured transport. Loopback endpoints always go
/// direct (Tor refuses to connect to 127.0.0.1). `isolated` asks Tor for a
/// fresh circuit (random SOCKS credentials).
fn http_for(url: &str, isolated: bool) -> Result<reqwest::blocking::Client, PerseverusError> {
    let l = url.to_ascii_lowercase();
    if l.contains("://127.0.0.1") || l.contains("://localhost") || l.contains("://[::1]") {
        return reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(PerseverusError::network);
    }
    let c = if isolated { transport::build_isolated_client(HTTP_TIMEOUT) } else { transport::build_client(HTTP_TIMEOUT) };
    c.map_err(PerseverusError::network)
}

fn point_hex(p: &EdwardsProjective) -> String {
    let mut buf = Vec::new();
    p.into_affine().serialize_compressed(&mut buf).expect("point serializes");
    hex::encode(buf)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Add `n` months to a YYYYMM value with year rollover.
pub(crate) fn add_months(yyyymm: u32, n: u32) -> u32 {
    let total = (yyyymm / 100) * 12 + (yyyymm % 100).saturating_sub(1) + n;
    (total / 12) * 100 + total % 12 + 1
}

fn method_str(m: PayMethod) -> &'static str {
    match m {
        PayMethod::Lightning => "lightning",
        PayMethod::Card => "card",
    }
}

fn plan_str(p: Plan) -> &'static str {
    match p {
        Plan::Trial => "trial",
        Plan::Onetime => "onetime",
        Plan::Monthly => "monthly",
    }
}

#[cfg(test)]
mod tests {
    use super::add_months;

    #[test]
    fn month_rollover() {
        assert_eq!(add_months(202610, 1), 202611);
        assert_eq!(add_months(202612, 1), 202701);
        assert_eq!(add_months(202611, 3), 202702);
    }
}
