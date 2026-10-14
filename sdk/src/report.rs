//! `PrivacyReport` construction from a decoded 24-bit v3-lean tag.
//!
//! All finding text, trigger rules, the primary-recommendation cascade and the
//! synthetic scores come from `docs/blueberry-v1/findings-catalog.v3lean.json`,
//! compiled in with `include_str!`. That file is the single source of truth
//! shared with the Sparrow wallet (it was extracted from, and is tested
//! against, `V3LeanReportBuilder.java`). Do not hand-edit strings here.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

const CATALOG_JSON: &str = include_str!("../../docs/blueberry-v1/findings-catalog.v3lean.json");

// ─── Public model (exported over UniFFI; serializes to the JSON schema) ───

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, uniffi::Enum)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Tag decrypted and decoded.
    Graded,
    /// Funding tx deliberately excluded from the filters (skip rules). Not a flag.
    Ungraded,
    /// No filter exists for the funding block height. Not assessed.
    NotCovered,
    /// The assessment failed; see `error`.
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, uniffi::Enum)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Good,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, uniffi::Record)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, uniffi::Record)]
pub struct Recommendation {
    /// immediate | soon | when-convenient | positive | neutral
    pub urgency: String,
    pub headline: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, uniffi::Record)]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
    pub good: u32,
}

/// One input of the transaction being analysed. `txid` is the FUNDING txid in
/// display (RPC / block-explorer) byte order; `block_height` is the height of
/// the block that confirmed it, from the wallet's own header store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, uniffi::Record)]
pub struct InputRef {
    pub txid: String,
    pub vout: u32,
    pub block_height: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_sats: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, uniffi::Record)]
pub struct ReportError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, uniffi::Record)]
pub struct PrivacyReport {
    pub schema_version: u32,
    pub status: ReportStatus,
    pub input: InputRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade_band: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u32>,
    pub score_is_exact: bool,
    pub profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_recommendation: Option<Recommendation>,
    pub findings: Vec<Finding>,
    pub severity_counts: SeverityCounts,
    pub include_in_wallet_average: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_tag: Option<String>,
    pub token_spent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ReportError>,
}

impl PrivacyReport {
    /// JSON matching `docs/blueberry-v1/privacy-report.schema.json`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("PrivacyReport is always serializable")
    }
}

// ─── Catalog (deserialized once) ──────────────────────────────────────

#[derive(Deserialize)]
struct CatalogFinding {
    id: String,
    title: String,
    severity: String,
    confidence: String,
    description: String,
    recommendation: String,
    when: String,
}

#[derive(Deserialize)]
struct CatalogRec {
    when: String,
    urgency: String,
    headline: String,
    detail: String,
}

#[derive(Deserialize)]
struct UngradedRec {
    urgency: String,
    headline: String,
    detail: String,
}

#[derive(Deserialize)]
struct UngradedRule {
    id: String,
    title: String,
    severity: String,
    confidence: String,
    description: String,
    recommendation: String,
}

#[derive(Deserialize)]
struct Ungraded {
    profile: String,
    recommendation: UngradedRec,
    rules: Vec<UngradedRule>,
}

#[derive(Deserialize)]
struct Catalog {
    fields: BTreeMap<String, (u32, u32)>,
    enums: BTreeMap<String, Vec<String>>,
    display_grade: BTreeMap<String, String>,
    synthetic_score: BTreeMap<String, u32>,
    primary_recommendation_cascade: Vec<CatalogRec>,
    findings: Vec<CatalogFinding>,
    ungraded: Ungraded,
}

fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| serde_json::from_str(CATALOG_JSON).expect("embedded findings catalog is valid"))
}

fn severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "good" => Severity::Good,
        _ => Severity::Info,
    }
}

type Fields = BTreeMap<String, u32>;

fn decode(tag: u32) -> Fields {
    catalog()
        .fields
        .iter()
        .map(|(k, &(off, w))| (k.clone(), (tag >> off) & ((1u32 << w) - 1)))
        .collect()
}

/// Evaluate a catalog trigger. The grammar is deliberately tiny:
/// `true` | term ( `||` term )*, where term is `name`, `!name`, or
/// `name (==|!=|>=|<=|>|<) N`.
fn eval(expr: &str, f: &Fields) -> bool {
    expr.split("||").any(|term| {
        let t = term.trim();
        if t == "true" {
            return true;
        }
        if let Some(name) = t.strip_prefix('!') {
            return field(f, name.trim()) == 0;
        }
        for op in ["==", "!=", ">=", "<=", ">", "<"] {
            if let Some((l, r)) = t.split_once(op) {
                let lv = field(f, l.trim());
                let rv: u32 = r.trim().parse().unwrap_or_else(|_| panic!("bad catalog literal in `{t}`"));
                return match op {
                    "==" => lv == rv,
                    "!=" => lv != rv,
                    ">=" => lv >= rv,
                    "<=" => lv <= rv,
                    ">" => lv > rv,
                    _ => lv < rv,
                };
            }
        }
        field(f, t) != 0
    })
}

fn field(f: &Fields, name: &str) -> u32 {
    *f.get(name).unwrap_or_else(|| panic!("catalog references unknown field `{name}`"))
}

fn counts(findings: &[Finding]) -> SeverityCounts {
    let mut c = SeverityCounts::default();
    for f in findings {
        match f.severity {
            Severity::Critical => c.critical += 1,
            Severity::High => c.high += 1,
            Severity::Medium => c.medium += 1,
            Severity::Low => c.low += 1,
            Severity::Info => c.info += 1,
            Severity::Good => c.good += 1,
        }
    }
    c
}

/// Build a graded report from a 24-bit v3-lean tag.
pub fn graded(input: InputRef, tag24: u32, token_spent: bool) -> PrivacyReport {
    let c = catalog();
    let tag = tag24 & 0x00FF_FFFF;
    let f = decode(tag);

    let mut findings = Vec::new();
    for cf in &c.findings {
        if !eval(&cf.when, &f) {
            continue;
        }
        let mut title = cf.title.clone();
        if title.contains("{consolidation_class}") {
            let v = &c.enums["consolidation_class"][field(&f, "consolidation_class") as usize];
            title = title.replace("{consolidation_class}", v);
        }
        if title.contains("{count}") {
            let n = field(&f, "rbf_signaled") + field(&f, "no_locktime") + field(&f, "legacy_version");
            title = format!("{n} wallet fingerprinting signal{}", if n == 1 { "" } else { "s" });
        }
        findings.push(Finding {
            id: cf.id.clone(),
            title,
            severity: severity(&cf.severity),
            confidence: cf.confidence.clone(),
            description: cf.description.clone(),
            recommendation: cf.recommendation.clone(),
        });
    }

    let band = field(&f, "grade");
    let score = if band == 3 && field(&f, "deterministic_cap") != 0 {
        c.synthetic_score["3_deterministic_cap"]
    } else {
        c.synthetic_score[&band.to_string()]
    };
    let rec = c
        .primary_recommendation_cascade
        .iter()
        .find(|r| eval(&r.when, &f))
        .expect("catalog cascade ends with `true`");
    let profile = if field(&f, "is_peel_chain") != 0 {
        "peel-chain"
    } else if field(&f, "is_coinjoin") != 0 {
        "coinjoin"
    } else {
        "transaction"
    };

    PrivacyReport {
        schema_version: 1,
        status: ReportStatus::Graded,
        input,
        grade: Some(c.display_grade[&band.to_string()].clone()),
        grade_band: Some(c.enums["grade"][band as usize].clone()),
        score: Some(score),
        score_is_exact: false,
        profile: profile.into(),
        primary_recommendation: Some(Recommendation {
            urgency: rec.urgency.clone(),
            headline: rec.headline.clone(),
            detail: rec.detail.clone(),
        }),
        severity_counts: counts(&findings),
        findings,
        include_in_wallet_average: true,
        raw_tag: Some(format!("V3LEAN:{tag:06x}")),
        token_spent,
        error: None,
    }
}

/// Funding tx excluded by the filter build-side skip rules.
pub fn ungraded(input: InputRef) -> PrivacyReport {
    let u = &catalog().ungraded;
    let findings: Vec<Finding> = u
        .rules
        .iter()
        .map(|r| Finding {
            id: r.id.clone(),
            title: r.title.clone(),
            severity: severity(&r.severity),
            confidence: r.confidence.clone(),
            description: r.description.clone(),
            recommendation: r.recommendation.clone(),
        })
        .collect();
    PrivacyReport {
        schema_version: 1,
        status: ReportStatus::Ungraded,
        input,
        grade: None,
        grade_band: None,
        score: None,
        score_is_exact: false,
        profile: u.profile.clone(),
        primary_recommendation: Some(Recommendation {
            urgency: u.recommendation.urgency.clone(),
            headline: u.recommendation.headline.clone(),
            detail: u.recommendation.detail.clone(),
        }),
        severity_counts: counts(&findings),
        findings,
        include_in_wallet_average: false,
        raw_tag: None,
        token_spent: false,
        error: None,
    }
}

/// No filter for the funding block (outside the server's coverage).
pub fn not_covered(input: InputRef) -> PrivacyReport {
    empty(input, ReportStatus::NotCovered, "not-covered", None)
}

pub fn failed(input: InputRef, code: &str, message: String, retryable: bool) -> PrivacyReport {
    empty(
        input,
        ReportStatus::Error,
        "error",
        Some(ReportError { code: code.into(), message, retryable }),
    )
}

fn empty(input: InputRef, status: ReportStatus, profile: &str, error: Option<ReportError>) -> PrivacyReport {
    PrivacyReport {
        schema_version: 1,
        status,
        input,
        grade: None,
        grade_band: None,
        score: None,
        score_is_exact: false,
        profile: profile.into(),
        primary_recommendation: None,
        findings: Vec::new(),
        severity_counts: SeverityCounts::default(),
        include_in_wallet_average: false,
        raw_tag: None,
        token_spent: false,
        error,
    }
}
