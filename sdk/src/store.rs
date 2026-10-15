//! Local token-pack storage.
//!
//! Balances live ONLY on the device: the server never learns how many tokens a
//! wallet holds or which pack a spend came from. The store is one JSON file in
//! the app-supplied data directory, written atomically (temp file + rename).
//!
//! Each pack is the same opaque blob Sparrow persists (`pack_blob` format), plus
//! a per-token `used` bitmap. Tokens are marked used BEFORE the spend request is
//! sent, so a crash mid-request can never cause a double-spend attempt; the
//! cost is that a token can be lost if the request dies in flight.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use perseverus_client_native::pack_blob::{deserialize_issued_pack, serialize_issued_pack};
use perseverus_core::issuance::IssuedPack;
use serde::{Deserialize, Serialize};

use crate::error::PerseverusError;

const STORE_FILE: &str = "perseverus-packs.json";
const STORE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredPack {
    pub pack_id: u64,
    pub blob_hex: String,
    pub used: Vec<bool>,
    pub start_month: u32,
    pub expiration_month: u32,
    pub method: String,
    pub acquired_at: u64,
    /// Set when the server's public revocation list shows this pack revoked
    /// (e.g. after a card chargeback). Permanent.
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredPurchase {
    pub purchase_id: String,
    pub method: String,
    pub plan: String,
    pub tokens: u32,
    pub created_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    packs: Vec<StoredPack>,
    #[serde(default)]
    pending_purchases: Vec<StoredPurchase>,
}

/// Metadata for one locally held pack (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PackInfo {
    pub pack_id: u64,
    pub size: u32,
    pub remaining: u32,
    pub start_month: u32,
    pub expiration_month: u32,
    pub method: String,
    pub acquired_at: u64,
    /// True if `start_month <= current_month <= expiration_month` and the
    /// pack isn't revoked.
    pub active: bool,
    /// True if the pack was revoked (e.g. its card payment was reversed).
    /// Its tokens can't be spent.
    pub revoked: bool,
}

pub(crate) struct Store {
    path: PathBuf,
    lock: Mutex<()>,
}

/// A reserved token: the pack plus the token index that was marked used.
pub(crate) struct Reservation {
    pub pack: IssuedPack,
    pub index: usize,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self, PerseverusError> {
        fs::create_dir_all(dir).map_err(|e| PerseverusError::Storage { reason: format!("create {}: {e}", dir.display()) })?;
        let s = Store { path: dir.join(STORE_FILE), lock: Mutex::new(()) };
        s.read()?; // fail fast on a corrupt file
        Ok(s)
    }

    fn read(&self) -> Result<StoreFile, PerseverusError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let f: StoreFile = serde_json::from_slice(&bytes)
                    .map_err(|e| PerseverusError::Storage { reason: format!("parse {}: {e}", self.path.display()) })?;
                if f.version != STORE_VERSION {
                    return Err(PerseverusError::Storage { reason: format!("unsupported store version {}", f.version) });
                }
                Ok(f)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoreFile { version: STORE_VERSION, ..Default::default() }),
            Err(e) => Err(PerseverusError::Storage { reason: format!("read {}: {e}", self.path.display()) }),
        }
    }

    fn write(&self, f: &StoreFile) -> Result<(), PerseverusError> {
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(f).expect("store serializes");
        fs::write(&tmp, bytes).map_err(|e| PerseverusError::Storage { reason: format!("write {}: {e}", tmp.display()) })?;
        fs::rename(&tmp, &self.path).map_err(|e| PerseverusError::Storage { reason: format!("rename: {e}") })
    }

    fn update<T>(&self, f: impl FnOnce(&mut StoreFile) -> Result<T, PerseverusError>) -> Result<T, PerseverusError> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut file = self.read()?;
        let out = f(&mut file)?;
        self.write(&file)?;
        Ok(out)
    }

    pub fn add_pack(&self, issued: &IssuedPack, method: &str, now: u64) -> Result<PackInfo, PerseverusError> {
        let blob = serialize_issued_pack(issued).map_err(|m| PerseverusError::Internal { reason: m })?;
        let n = issued.pack.tokens.len();
        let sp = StoredPack {
            pack_id: issued.pack_id,
            blob_hex: hex::encode(blob),
            used: vec![false; n],
            start_month: issued.start_month,
            expiration_month: issued.expiration_month,
            method: method.into(),
            acquired_at: now,
            revoked: false,
        };
        self.update(|f| {
            if f.packs.iter().any(|p| p.pack_id == sp.pack_id) {
                return Err(PerseverusError::Internal { reason: format!("pack {} already stored", sp.pack_id) });
            }
            f.packs.push(sp.clone());
            Ok(())
        })?;
        Ok(info(&sp, 0))
    }

    pub fn packs(&self, current_month: u32) -> Result<Vec<PackInfo>, PerseverusError> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        Ok(self.read()?.packs.iter().map(|p| info(p, current_month)).collect())
    }

    pub fn balance(&self, current_month: u32) -> Result<u32, PerseverusError> {
        Ok(self.packs(current_month)?.iter().filter(|p| p.active).map(|p| p.remaining).sum())
    }

    /// Reserve `n` unused tokens from active packs, soonest-expiring first, and
    /// persist them as used before returning.
    pub fn reserve(&self, n: usize, current_month: u32) -> Result<Vec<Reservation>, PerseverusError> {
        if n == 0 {
            return Ok(Vec::new());
        }
        self.update(|f| {
            let mut order: Vec<usize> = (0..f.packs.len())
                .filter(|&i| is_active(&f.packs[i], current_month))
                .collect();
            order.sort_by_key(|&i| f.packs[i].expiration_month);
            let available: usize = order.iter().map(|&i| f.packs[i].used.iter().filter(|u| !**u).count()).sum();
            if available < n {
                return Err(PerseverusError::InsufficientTokens { needed: n as u32, available: available as u32 });
            }
            let mut out = Vec::with_capacity(n);
            let mut cache: Vec<Option<IssuedPack>> = vec![None; f.packs.len()];
            'outer: for &pi in &order {
                for ti in 0..f.packs[pi].used.len() {
                    if out.len() == n {
                        break 'outer;
                    }
                    if f.packs[pi].used[ti] {
                        continue;
                    }
                    if cache[pi].is_none() {
                        let blob = hex::decode(&f.packs[pi].blob_hex)
                            .map_err(|e| PerseverusError::Storage { reason: format!("pack blob hex: {e}") })?;
                        cache[pi] = Some(deserialize_issued_pack(&blob).map_err(|m| PerseverusError::Storage { reason: m })?);
                    }
                    f.packs[pi].used[ti] = true;
                    out.push(Reservation { pack: cache[pi].clone().unwrap(), index: ti });
                }
            }
            Ok(out)
        })
    }

    /// Give back tokens whose spend the server rejected BEFORE burning the
    /// nullifier (per-entry errors in a batch response).
    pub fn release(&self, items: &[(u64, usize)]) -> Result<(), PerseverusError> {
        if items.is_empty() {
            return Ok(());
        }
        self.update(|f| {
            for &(pack_id, idx) in items {
                if let Some(p) = f.packs.iter_mut().find(|p| p.pack_id == pack_id) {
                    if let Some(u) = p.used.get_mut(idx) {
                        *u = false;
                    }
                }
            }
            Ok(())
        })
    }

    /// Mark packs revoked (from the server's public revocation list, checked
    /// on the device). Their tokens are never reserved again.
    pub fn mark_revoked(&self, pack_ids: &[u64]) -> Result<(), PerseverusError> {
        if pack_ids.is_empty() {
            return Ok(());
        }
        self.update(|f| {
            for p in f.packs.iter_mut().filter(|p| pack_ids.contains(&p.pack_id)) {
                p.revoked = true;
            }
            Ok(())
        })
    }

    /// Mark tokens as used from a bitmap (index i used if `spent[i]`).
    /// Returns the pack's remaining count.
    pub fn mark_spent(&self, pack_id: u64, spent: &[bool]) -> Result<u32, PerseverusError> {
        self.update(|f| {
            let p = f
                .packs
                .iter_mut()
                .find(|p| p.pack_id == pack_id)
                .ok_or_else(|| PerseverusError::InvalidArgument { reason: format!("unknown pack {pack_id}") })?;
            for (u, &s) in p.used.iter_mut().zip(spent) {
                *u |= s;
            }
            Ok(p.used.iter().filter(|u| !**u).count() as u32)
        })
    }

    /// Remember an unpaid/unclaimed purchase so its bearer id survives an app
    /// restart.
    pub fn add_pending_purchase(&self, p: StoredPurchase) -> Result<(), PerseverusError> {
        self.update(|f| {
            f.pending_purchases.retain(|x| x.purchase_id != p.purchase_id);
            f.pending_purchases.push(p);
            Ok(())
        })
    }

    pub fn remove_pending_purchase(&self, purchase_id: &str) -> Result<(), PerseverusError> {
        self.update(|f| {
            f.pending_purchases.retain(|x| x.purchase_id != purchase_id);
            Ok(())
        })
    }

    pub fn pending_purchases(&self) -> Result<Vec<StoredPurchase>, PerseverusError> {
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        Ok(self.read()?.pending_purchases)
    }
}

fn is_active(p: &StoredPack, m: u32) -> bool {
    !p.revoked && (m == 0 || (p.start_month <= m && m <= p.expiration_month))
}

fn info(p: &StoredPack, current_month: u32) -> PackInfo {
    PackInfo {
        pack_id: p.pack_id,
        size: p.used.len() as u32,
        remaining: p.used.iter().filter(|u| !**u).count() as u32,
        start_month: p.start_month,
        expiration_month: p.expiration_month,
        method: p.method.clone(),
        acquired_at: p.acquired_at,
        active: is_active(p, current_month),
        revoked: p.revoked,
    }
}
