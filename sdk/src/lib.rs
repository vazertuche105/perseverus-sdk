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
//!     provingKeyPath = bundledPkPath,                // pk.bin shipped with the app
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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use perseverus_client_native::issuance_client::V1Credential;
use perseverus_client_native::{transport, IssuanceClient, QueryClient, SpendClient};
use perseverus_core::poseidon::{poseidon_config, poseidon_hash_many, PoseidonField};
use rand::rngs::OsRng;
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
    /// Path to the Groth16 proving key (`pk.bin`, ~4 MB) shipped with the app.
    /// Wallets should bundle it, as Sparrow does: production servers don't
    /// serve it, and a key downloaded from the server could be swapped by a
    /// malicious server. If `None`, the SDK falls back to `GET /circuit/pk`
    /// and caches the result in `data_dir`.
    pub proving_key_path: Option<String>,
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
    /// Card, paid once: 13 monthly packs (the rest of this month plus the next 12).
    Yearly,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Purchase {
    /// Bearer credential for claiming the pack. The SDK also stores it.
    pub purchase_id: String,
    pub method: PayMethod,
    pub plan: Plan,
    /// Packs this purchase redeems (13 for `Yearly`, otherwise 1).
    pub packs: u32,
    /// Total tokens across those packs.
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
    Redeemed,
    Expired,
}

// ─── The SDK object ──────────────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct Perseverus {
    base_url: String,
    data_dir: PathBuf,
    proving_key_path: Option<String>,
    server_pubkey: EdwardsProjective,
    store: Store,
    query: QueryClient,
    spend: Mutex<Option<SpendClient>>,
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
        let query = QueryClient::new(&base_url).with_v1().with_http(http_for(&base_url, false)?);
        let meta: Meta = get_json_at(&base_url, "/v1/meta")?;
        if !meta.api_version.starts_with("1.") {
            return Err(PerseverusError::Unsupported { reason: format!("server API {} is not 1.x", meta.api_version) });
        }
        if version_lt(env!("CARGO_PKG_VERSION"), &meta.min_client_version) {
            return Err(PerseverusError::Unsupported {
                reason: format!("this SDK ({}) is older than the server's minimum ({}); update it", env!("CARGO_PKG_VERSION"), meta.min_client_version),
            });
        }
        let server_pubkey = parse_point_hex(&meta.server_pubkey_hex)
            .ok_or_else(|| PerseverusError::Verification { reason: "server sent an invalid OPRF public key".into() })?;

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
            proving_key_path: config.proving_key_path,
            server_pubkey,
            store,
            query,
            spend: Mutex::new(None),
        }))
    }

    /// The server's OPRF public key (hex), for pinning on first use.
    pub fn server_pubkey(&self) -> String {
        point_hex(&self.server_pubkey)
    }

    /// Current server epoch month (YYYYMM).
    pub fn current_month(&self) -> Result<u32, PerseverusError> {
        let m: Meta = self.get_json("/v1/meta")?;
        Ok(m.current_month)
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
    ///
    /// Lightning: `Trial` (1 token) or `Onetime` (100). Card: `Onetime`,
    /// `Monthly` or `Yearly` (13 packs). The server sets the price.
    pub fn buy_tokens(&self, method: PayMethod, plan: Plan) -> Result<Purchase, PerseverusError> {
        #[derive(Deserialize)]
        struct Payment {
            kind: String,
            bolt11: Option<String>,
            amount_sat: Option<u64>,
            checkout_url: Option<String>,
        }
        #[derive(Deserialize)]
        struct V1Purchase {
            purchase_id: String,
            packs: u32,
            tokens: u32,
            expires_at: u64,
            payment: Payment,
        }
        let p: V1Purchase = self.post_json(
            "/v1/tokens/purchase",
            &serde_json::json!({ "method": method_str(method), "plan": plan_str(plan) }),
            false,
        )?;
        let payment_request = match p.payment.kind.as_str() {
            "lightning" => p.payment.bolt11,
            _ => p.payment.checkout_url,
        }
        .ok_or_else(|| PerseverusError::Internal { reason: "purchase response has no payment request".into() })?;
        let purchase = Purchase {
            purchase_id: p.purchase_id,
            method,
            plan,
            packs: p.packs,
            tokens: p.tokens,
            payment_request,
            amount_sat: p.payment.amount_sat,
            expires_at: Some(p.expires_at),
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

    /// Track a purchase that was started elsewhere (another device, or a
    /// checkout opened outside the app) so it can be polled and redeemed here.
    /// `purchase_id` is the bearer id from `POST /v1/tokens/purchase`.
    pub fn add_purchase(&self, purchase_id: String, plan: Plan) -> Result<(), PerseverusError> {
        let method = if purchase_id.starts_with("ln_") {
            PayMethod::Lightning
        } else if purchase_id.starts_with("card_") {
            PayMethod::Card
        } else {
            return Err(PerseverusError::InvalidArgument { reason: "purchase_id must start with ln_ or card_".into() });
        };
        let tokens = match plan {
            Plan::Trial => 1,
            Plan::Yearly => 13 * PACK_SIZE,
            _ => PACK_SIZE,
        };
        self.store.add_pending_purchase(StoredPurchase {
            purchase_id,
            method: method_str(method).into(),
            plan: plan_str(plan).into(),
            tokens,
            created_at: now(),
        })
    }

    /// Purchases started but not yet redeemed (survive app restarts).
    pub fn pending_purchases(&self) -> Result<Vec<String>, PerseverusError> {
        Ok(self.store.pending_purchases()?.into_iter().map(|p| p.purchase_id).collect())
    }

    /// Poll while the user pays: `Paid` means ready to `redeem`.
    pub fn purchase_status(&self, purchase_id: String) -> Result<PurchaseState, PerseverusError> {
        #[derive(Deserialize)]
        struct S {
            state: String,
        }
        let s: S = self.get_json(&format!("/v1/tokens/purchase/{purchase_id}/status"))?;
        Ok(match s.state.as_str() {
            "paid" => PurchaseState::Paid,
            "redeemed" => PurchaseState::Redeemed,
            "expired" => PurchaseState::Expired,
            _ => PurchaseState::Pending,
        })
    }

    /// Claim a paid purchase: blind fresh tokens, have the server sign them,
    /// unblind, and store the pack(s) locally. Returns one `PackInfo` per pack
    /// (13 for a yearly plan). The claim goes over an isolated Tor circuit.
    pub fn redeem(&self, purchase_id: String) -> Result<Vec<PackInfo>, PerseverusError> {
        let p = self.pending(&purchase_id)?;
        let month = self.current_month()?;
        // (expiration_month, start_month) per pack. One pack is valid through
        // the end of next month. Yearly: a bridge pack for the rest of this
        // month and the next, then one pack per calendar month for 12 months
        // (the same schedule Sparrow uses).
        let schedule: Vec<(u32, u32)> = if p.plan == "yearly" {
            let mut v = vec![(add_months(month, 1), month)];
            for k in 1..=12 {
                let m = add_months(month, 1 + k);
                v.push((m, m));
            }
            v
        } else {
            vec![(add_months(month, 1), month)]
        };
        let per_pack = (p.tokens as usize / schedule.len()).max(1);
        let issuance = IssuanceClient::new(&self.base_url, self.server_pubkey)
            .with_v1()
            .with_http(http_for(&self.base_url, true)?);
        let issued = issuance.redeem_v1(per_pack, &schedule, V1Credential::PurchaseId(&purchase_id), &mut OsRng)?;

        // Store first: the packs are already signed, so nothing after this
        // point may lose them.
        let mut infos = Vec::with_capacity(issued.len());
        for pack in &issued {
            infos.push(self.store.add_pack(pack, &p.method, now())?);
        }
        self.store.remove_pending_purchase(&purchase_id)?;

        // Card packs publish an attribution entry (chargeback handling), each
        // over its own isolated circuit, as Sparrow does. A failure here
        // doesn't affect the tokens.
        if p.method == "card" {
            for pack in &issued {
                let tag = poseidon_hash_many(&poseidon_config(), &[PoseidonField::from(pack.pack_id)]);
                if let Err(e) = issuance.publish_board_entry(pack, tag) {
                    perseverus_client_native::debug_log!("[perseverus] board publish failed (tokens unaffected): {e}");
                }
            }
        }
        let month_now = month;
        for i in &mut infos {
            i.active = i.start_month <= month_now && month_now <= i.expiration_month;
        }
        Ok(infos)
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
            let sc = match &self.proving_key_path {
                Some(path) => {
                    let bytes = std::fs::read(path).map_err(|e| PerseverusError::InvalidArgument {
                        reason: format!("proving key {path}: {e}"),
                    })?;
                    let pk = ark_groth16::ProvingKey::<ark_bn254::Bn254>::deserialize_compressed(&bytes[..])
                        .map_err(|e| PerseverusError::InvalidArgument { reason: format!("proving key {path} is not a valid pk.bin: {e}") })?;
                    SpendClient::new(&self.base_url, pk, self.server_pubkey).with_v1()
                }
                None => {
                    let http = http_for(&self.base_url, false)?;
                    SpendClient::bootstrap_with_cache(&self.base_url, self.server_pubkey, http, &self.data_dir.join(PK_CACHE_FILE))?
                        .with_v1()
                }
            };
            *guard = Some(sc);
        }
        Ok(guard.as_ref().unwrap().clone().with_http(http_for(&self.base_url, true)?))
    }

    fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, PerseverusError> {
        get_json_at(&self.base_url, path)
    }

    fn post_json<T: serde::de::DeserializeOwned>(&self, path: &str, body: &serde_json::Value, isolated: bool) -> Result<T, PerseverusError> {
        let resp = http_for(&self.base_url, isolated)?.post(format!("{}{}", self.base_url, path)).json(body).send()?;
        json_or_error(resp)
    }
}

/// The subset of `GET /v1/meta` the SDK uses.
#[derive(Deserialize)]
struct Meta {
    api_version: String,
    min_client_version: String,
    server_pubkey_hex: String,
    current_month: u32,
}

fn get_json_at<T: serde::de::DeserializeOwned>(base_url: &str, path: &str) -> Result<T, PerseverusError> {
    let resp = http_for(base_url, false)?.get(format!("{base_url}{path}")).send()?;
    json_or_error(resp)
}

fn parse_point_hex(h: &str) -> Option<EdwardsProjective> {
    let b = hex::decode(h).ok()?;
    ark_ed_on_bn254::EdwardsAffine::deserialize_compressed(&b[..]).ok().map(Into::into)
}

/// `a < b` for dotted numeric versions ("0.1.0" < "0.2").
fn version_lt(a: &str, b: &str) -> bool {
    let parse = |v: &str| v.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    let (mut x, mut y) = (parse(a), parse(b));
    let n = x.len().max(y.len());
    x.resize(n, 0);
    y.resize(n, 0);
    x < y
}

fn json_or_error<T: serde::de::DeserializeOwned>(resp: reqwest::blocking::Response) -> Result<T, PerseverusError> {
    let status = resp.status();
    if !status.is_success() {
        let message = error::server_reason(resp.text().unwrap_or_default());
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
        Plan::Yearly => "yearly",
    }
}

#[cfg(test)]
mod tests {
    use super::add_months;

    #[test]
    fn version_compare() {
        use super::version_lt;
        assert!(version_lt("0.1.0", "0.2.0"));
        assert!(version_lt("0.9", "0.10.0"));
        assert!(!version_lt("0.1.0", "0.1"));
        assert!(!version_lt("1.0.0", "0.9.9"));
    }

    #[test]
    fn month_rollover() {
        assert_eq!(add_months(202610, 1), 202611);
        assert_eq!(add_months(202612, 1), 202701);
        assert_eq!(add_months(202611, 3), 202702);
    }
}
