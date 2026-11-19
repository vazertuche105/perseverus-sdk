//! The whole-transaction assessment: what happens when these inputs are
//! spent TOGETHER.
//!
//! A [`PrivacyReport`] describes one coin. A transaction that spends several
//! coins also shows the world that they share an owner, so a clean coin
//! spent next to an exposed one takes on its history. [`assess_transaction`]
//! looks at the reports of all the inputs and says whether combining them is
//! a problem, which inputs cause it, and how to split them.
//!
//! **It runs entirely on the device.** It reads the reports the wallet
//! already has: no request is sent and no token is spent. That is deliberate:
//! the server never learns any coin's result, and it must never learn which
//! coins are being spent together, so this can't be a server call.
//!
//! The rules live in [`assess`] below; the text the user reads is in
//! `docs/blueberry-v1/transaction-findings.v1.json` (compiled in).
//!
//! Limits, by design:
//!   * A report describes the transaction that created the coin. The
//!     assessment therefore knows where each coin came from, not where this
//!     transaction is going (its outputs, amounts or change).
//!   * It is a set of heuristics, like the per-coin findings. `Ok` means none
//!     of the known risky combinations fired, not that the transaction is
//!     private.

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::report::{self, PrivacyReport, Recommendation, Severity};

const CATALOG_JSON: &str = include_str!("../../docs/blueberry-v1/transaction-findings.v1.json");

/// Should these inputs be spent together?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, uniffi::Enum)]
#[serde(rename_all = "snake_case")]
pub enum CombineVerdict {
    /// None of the risky combinations fired.
    Ok,
    /// A combination worth a second look (a medium finding).
    Caution,
    /// Combining these inputs does real damage (a high or critical finding):
    /// warn the user before they send.
    Avoid,
}

/// One thing the combination of inputs does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, uniffi::Record)]
pub struct TransactionFinding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
    /// The inputs this finding is about, as positions in the list of reports
    /// that was assessed (0 = first). For a "would link X to your other
    /// coins" finding these are the X; taking them out clears the finding.
    pub inputs: Vec<u32>,
}

/// Inputs that are fine to spend with each other by these rules. Two inputs
/// in different groups are what the findings warn about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, uniffi::Record)]
pub struct InputGroup {
    /// `exposed` | `coinjoin` | `known-entity` | `clean` | `lower-grade` | `unassessed`
    pub id: String,
    pub title: String,
    /// Positions in the list of reports that was assessed (0 = first).
    pub inputs: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, uniffi::Record)]
pub struct TransactionAssessment {
    pub schema_version: u32,
    pub verdict: CombineVerdict,
    /// False when some input has no grade, so the verdict covers only the rest.
    pub complete: bool,
    pub inputs_total: u32,
    pub inputs_graded: u32,
    /// Distinct earlier transactions the inputs come from. Inputs from the
    /// same one are already linked on-chain.
    pub funding_transactions: u32,
    /// Best and worst display grade among the graded inputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_grade: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worst_grade: Option<String>,
    /// The one thing to show first. Absent only for an empty input list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_recommendation: Option<Recommendation>,
    /// Most severe first.
    pub findings: Vec<TransactionFinding>,
    /// The inputs sorted into groups that are fine to spend together. One
    /// group means the whole set is consistent.
    pub groups: Vec<InputGroup>,
}

impl TransactionAssessment {
    /// JSON matching `docs/blueberry-v1/transaction-assessment.schema.json`.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("TransactionAssessment is always serializable")
    }
}

/// Assess a set of inputs as one transaction, from reports the wallet already
/// has (from `analyze_inputs`, now or earlier). On the device: no request,
/// no token. Call it again whenever the user adds or removes an input.
#[uniffi::export]
pub fn assess_transaction(reports: Vec<PrivacyReport>) -> TransactionAssessment {
    assess(&reports)
}

/// [`assess_transaction`]'s result as JSON
/// (`docs/blueberry-v1/transaction-assessment.schema.json`).
#[uniffi::export]
pub fn transaction_assessment_json(assessment: TransactionAssessment) -> String {
    assessment.to_json()
}

// ─── Text catalog ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Text {
    id: String,
    severity: String,
    title: String,
    description: String,
    recommendation: String,
}

#[derive(Deserialize)]
struct GroupText {
    id: String,
    title: String,
}

#[derive(Deserialize)]
struct Catalog {
    findings: Vec<Text>,
    groups: Vec<GroupText>,
}

fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| serde_json::from_str(CATALOG_JSON).expect("embedded transaction catalog is valid"))
}

// ─── Rules ────────────────────────────────────────────────────────────

/// What kind of coin an input is, for grouping. Earlier variants win.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Sanctioned or darknet link, chain taint, or a dust pattern.
    Exposed,
    Coinjoin,
    KnownEntity,
    /// Grade band B or C.
    Clean,
    /// Grade band D or F.
    LowerGrade,
    Unassessed,
}

impl Class {
    fn id(self) -> &'static str {
        match self {
            Class::Exposed => "exposed",
            Class::Coinjoin => "coinjoin",
            Class::KnownEntity => "known-entity",
            Class::Clean => "clean",
            Class::LowerGrade => "lower-grade",
            Class::Unassessed => "unassessed",
        }
    }
}

/// The tag fields of one graded input, by name.
type Fields = BTreeMap<String, u32>;

fn class_of(f: Option<&Fields>) -> Class {
    let Some(f) = f else { return Class::Unassessed };
    let v = |name: &str| f.get(name).copied().unwrap_or(0);
    if v("entity_class") >= 2 || v("chain_taint") != 0 || v("dust_class") >= 2 {
        Class::Exposed
    } else if v("is_coinjoin") != 0 {
        Class::Coinjoin
    } else if v("entity_class") == 1 {
        Class::KnownEntity
    } else if v("grade") <= 1 {
        Class::Clean
    } else {
        Class::LowerGrade
    }
}

pub(crate) fn assess(reports: &[PrivacyReport]) -> TransactionAssessment {
    let total = reports.len();
    let fields: Vec<Option<Fields>> = reports.iter().map(report::tag_fields).collect();
    let classes: Vec<Class> = fields.iter().map(|f| class_of(f.as_ref())).collect();
    let funding: HashSet<String> = reports.iter().map(|r| r.input.txid.to_ascii_lowercase()).collect();
    let m = funding.len();
    let graded = fields.iter().filter(|f| f.is_some()).count();

    // Inputs (by position) whose tag satisfies `pred`.
    let having = |pred: &dyn Fn(&Fields) -> bool| -> Vec<u32> {
        fields.iter().enumerate().filter(|(_, f)| f.as_ref().is_some_and(|f| pred(f))).map(|(i, _)| i as u32).collect()
    };
    let in_class = |c: Class| -> Vec<u32> {
        classes.iter().enumerate().filter(|(_, x)| **x == c).map(|(i, _)| i as u32).collect()
    };
    let val = |f: &Fields, name: &str| f.get(name).copied().unwrap_or(0);

    let bands: Vec<u32> = fields.iter().flatten().map(|f| val(f, "grade")).collect();
    let best_grade = bands.iter().min().map(|b| report::display_grade(*b));
    let worst_grade = bands.iter().max().map(|b| report::display_grade(*b));

    // (id, inputs, best, worst) for each finding that fires.
    let mut fired: Vec<(&str, Vec<u32>, Option<String>, Option<String>)> = Vec::new();
    let mut fire = |id: &'static str, inputs: Vec<u32>| fired.push((id, inputs, None, None));
    let unassessed = in_class(Class::Unassessed);

    if total == 0 {
        // nothing to say
    } else if graded == 0 {
        fire("none-assessed", unassessed.clone());
    } else if m == 1 {
        // One earlier transaction: its outputs are already linked on-chain.
        fire(if total == 1 { "single-input" } else { "same-origin" }, vec![]);
    } else {
        // "Would link X to your other coins": X is some but not all inputs.
        let partial = |v: &Vec<u32>| !v.is_empty() && v.len() < total;

        let sanctioned = having(&|f| val(f, "entity_class") >= 2);
        if partial(&sanctioned) {
            fire("mix-sanctioned-or-darknet", sanctioned);
        }
        let dust = having(&|f| val(f, "dust_class") >= 2);
        if partial(&dust) {
            fire("mix-dust-attack", dust);
        }
        let taint = having(&|f| val(f, "chain_taint") != 0);
        if partial(&taint) {
            fire("mix-taint", taint);
        }
        let coinjoin = having(&|f| val(f, "is_coinjoin") != 0);
        if partial(&coinjoin) {
            fire("mix-coinjoin-with-other", coinjoin.clone());
        }
        if coinjoin.len() >= 2 {
            fire("merge-coinjoin-outputs", coinjoin);
        }
        let known = having(&|f| val(f, "entity_class") == 1);
        if partial(&known) {
            fire("mix-known-entity", known);
        }

        // Clean next to lower-grade, among the coins with no special flag
        // (flagged ones are covered by the findings above).
        let clean = in_class(Class::Clean);
        let lower = in_class(Class::LowerGrade);
        if !clean.is_empty() && !lower.is_empty() {
            let band_of = |i: &u32| val(fields[*i as usize].as_ref().expect("graded"), "grade");
            let best = clean.iter().map(band_of).min().expect("non-empty");
            let worst = lower.iter().map(band_of).max().expect("non-empty");
            let id = if worst >= 3 { "mix-grade-spread-severe" } else { "mix-grade-spread" };
            fired.push((id, clean, Some(report::display_grade(best)), Some(report::display_grade(worst))));
        }

        let risky = !fired.is_empty();
        if !unassessed.is_empty() {
            fired.push(("incomplete", unassessed.clone(), None, None));
        }
        fired.push(("links-inputs", vec![], None, None));
        if !risky && unassessed.is_empty() {
            fired.push(("consistent", vec![], None, None));
        }
    }

    let c = catalog();
    let mut findings: Vec<TransactionFinding> = fired
        .into_iter()
        .map(|(id, inputs, best, worst)| {
            let t = c.findings.iter().find(|t| t.id == id).unwrap_or_else(|| panic!("transaction catalog has no `{id}`"));
            let fill = |s: &str| {
                s.replace("{n}", &inputs.len().to_string())
                    .replace("{total}", &total.to_string())
                    .replace("{m}", &m.to_string())
                    .replace("{best}", best.as_deref().unwrap_or(""))
                    .replace("{worst}", worst.as_deref().unwrap_or(""))
            };
            TransactionFinding {
                id: t.id.clone(),
                title: fill(&t.title),
                severity: report::severity(&t.severity),
                description: fill(&t.description),
                recommendation: fill(&t.recommendation),
                inputs,
            }
        })
        .collect();
    findings.sort_by_key(|f| f.severity); // stable: rule order within a severity

    let verdict = match findings.first().map(|f| f.severity) {
        Some(Severity::Critical | Severity::High) => CombineVerdict::Avoid,
        Some(Severity::Medium) => CombineVerdict::Caution,
        _ => CombineVerdict::Ok,
    };

    // Show a problem first if there is one; otherwise the good news rather
    // than the always-present "links N coins" note.
    let primary = findings
        .iter()
        .find(|f| f.severity <= Severity::Low)
        .or_else(|| findings.iter().find(|f| f.severity == Severity::Good))
        .or(findings.first())
        .map(|f| Recommendation {
            urgency: match f.severity {
                Severity::Critical | Severity::High => "immediate",
                Severity::Medium => "soon",
                Severity::Low | Severity::Info => "when-convenient",
                Severity::Good => "positive",
            }
            .into(),
            headline: f.title.clone(),
            detail: f.recommendation.clone(),
        });

    let groups = c
        .groups
        .iter()
        .filter_map(|g| {
            let inputs: Vec<u32> =
                classes.iter().enumerate().filter(|(_, x)| x.id() == g.id).map(|(i, _)| i as u32).collect();
            (!inputs.is_empty()).then(|| InputGroup { id: g.id.clone(), title: g.title.clone(), inputs })
        })
        .collect();

    TransactionAssessment {
        schema_version: 1,
        verdict,
        complete: total > 0 && unassessed.is_empty(),
        inputs_total: total as u32,
        inputs_graded: graded as u32,
        funding_transactions: m as u32,
        best_grade,
        worst_grade,
        primary_recommendation: primary,
        findings,
        groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::InputRef;

    // v3-lean tag bits (see findings-catalog.v3lean.json "fields").
    const GRADE_C: u32 = 1 << 1;
    const GRADE_D: u32 = 2 << 1;
    const GRADE_F: u32 = 3 << 1;
    const COINJOIN: u32 = 1 << 3;
    const DUST_ATTACK: u32 = 3 << 8;
    const KNOWN_ENTITY: u32 = 1 << 12;
    const DARKNET: u32 = 2 << 12;
    const TAINT: u32 = 1 << 15;

    fn input(n: u8) -> InputRef {
        InputRef { txid: format!("{n:02x}").repeat(32), vout: 0, block_height: 900_000, value_sats: None }
    }

    /// A graded report for funding tx `n` with tag `tag` (grade B if no grade bits).
    fn coin(n: u8, tag: u32) -> PrivacyReport {
        report::graded(input(n), tag, true)
    }

    fn ids(a: &TransactionAssessment) -> Vec<&str> {
        a.findings.iter().map(|f| f.id.as_str()).collect()
    }

    fn inputs_of<'a>(a: &'a TransactionAssessment, id: &str) -> &'a [u32] {
        &a.findings.iter().find(|f| f.id == id).unwrap_or_else(|| panic!("no finding {id}: {:?}", ids(a))).inputs
    }

    #[test]
    fn one_clean_coin_with_three_poor_ones() {
        // The case this exists for: input 0 is clean, 1..3 are poor.
        let a = assess(&[coin(1, 0), coin(2, GRADE_D), coin(3, GRADE_F), coin(4, GRADE_D)]);
        assert_eq!(a.verdict, CombineVerdict::Avoid);
        assert_eq!(a.findings[0].id, "mix-grade-spread-severe");
        assert_eq!(a.findings[0].inputs, [0], "the clean coin is the one to take out");
        assert!(a.findings[0].description.contains("the best is B, the worst is F"), "{}", a.findings[0].description);
        let p = a.primary_recommendation.as_ref().unwrap();
        assert_eq!((p.urgency.as_str(), p.headline.as_str()), ("immediate", "Mixes clean coins with badly exposed ones"));
        assert_eq!((a.best_grade.as_deref(), a.worst_grade.as_deref()), (Some("B"), Some("F")));
        assert_eq!(a.groups.len(), 2);
        assert_eq!((a.groups[0].id.as_str(), &a.groups[0].inputs[..]), ("clean", &[0u32][..]));
        assert_eq!((a.groups[1].id.as_str(), &a.groups[1].inputs[..]), ("lower-grade", &[1u32, 2, 3][..]));
        assert!(a.complete);
        assert_eq!((a.inputs_total, a.inputs_graded, a.funding_transactions), (4, 4, 4));
    }

    #[test]
    fn clean_with_d_is_a_caution() {
        let a = assess(&[coin(1, GRADE_C), coin(2, GRADE_D)]);
        assert_eq!(a.verdict, CombineVerdict::Caution);
        assert_eq!(ids(&a), ["mix-grade-spread", "links-inputs"]);
    }

    #[test]
    fn similar_coins_are_ok() {
        for tags in [[0, GRADE_C, 0], [GRADE_D, GRADE_F, GRADE_D]] {
            let a = assess(&[coin(1, tags[0]), coin(2, tags[1]), coin(3, tags[2])]);
            assert_eq!(a.verdict, CombineVerdict::Ok, "{tags:?}");
            assert_eq!(ids(&a), ["links-inputs", "consistent"]);
            assert_eq!(a.groups.len(), 1);
            let p = a.primary_recommendation.unwrap();
            assert_eq!((p.urgency.as_str(), p.headline.as_str()), ("positive", "Inputs have similar privacy profiles"));
            assert!(a.findings[0].title.contains("Links 3 coins") && a.findings[0].description.contains("3 different"));
        }
    }

    #[test]
    fn one_input_or_one_funding_transaction_links_nothing_new() {
        let a = assess(&[coin(1, GRADE_F | DARKNET)]);
        assert_eq!((a.verdict, ids(&a)), (CombineVerdict::Ok, vec!["single-input"]));

        // two outputs of the same earlier transaction
        let mut second = coin(1, GRADE_F);
        second.input.vout = 1;
        let a = assess(&[coin(1, GRADE_F), second]);
        assert_eq!((a.verdict, ids(&a)), (CombineVerdict::Ok, vec!["same-origin"]));
        assert_eq!(a.funding_transactions, 1);
    }

    #[test]
    fn flagged_coins_contaminate_the_rest() {
        let a = assess(&[coin(1, 0), coin(2, GRADE_F | DARKNET), coin(3, GRADE_F | DUST_ATTACK), coin(4, GRADE_D | TAINT)]);
        assert_eq!(a.verdict, CombineVerdict::Avoid);
        assert_eq!(&ids(&a)[..3], ["mix-sanctioned-or-darknet", "mix-dust-attack", "mix-taint"]);
        assert_eq!(inputs_of(&a, "mix-sanctioned-or-darknet"), [1]);
        assert_eq!(inputs_of(&a, "mix-dust-attack"), [2]);
        assert_eq!(inputs_of(&a, "mix-taint"), [3]);
        // flagged coins are reported by their own findings, not as a grade spread too
        assert!(!ids(&a).iter().any(|i| i.starts_with("mix-grade-spread")));
        assert_eq!(a.groups.iter().map(|g| (g.id.as_str(), g.inputs.clone())).collect::<Vec<_>>(), [
            ("exposed", vec![1, 2, 3]),
            ("clean", vec![0])
        ]);
        // if every input has the flag, nothing new gets contaminated
        let a = assess(&[coin(1, GRADE_F | DARKNET), coin(2, GRADE_F | DARKNET)]);
        assert_eq!(ids(&a), ["links-inputs", "consistent"]);
    }

    #[test]
    fn coinjoin_rules() {
        // mixed with an unmixed coin: undoes the CoinJoin
        let a = assess(&[coin(1, COINJOIN), coin(2, 0)]);
        assert_eq!((a.verdict, ids(&a)), (CombineVerdict::Avoid, vec!["mix-coinjoin-with-other", "links-inputs"]));
        assert_eq!(inputs_of(&a, "mix-coinjoin-with-other"), [0]);
        // only CoinJoin outputs, several of them
        let a = assess(&[coin(1, COINJOIN), coin(2, COINJOIN)]);
        assert_eq!((a.verdict, ids(&a)), (CombineVerdict::Caution, vec!["merge-coinjoin-outputs", "links-inputs"]));
        // both at once
        let a = assess(&[coin(1, COINJOIN), coin(2, COINJOIN), coin(3, 0)]);
        assert_eq!(&ids(&a)[..2], ["mix-coinjoin-with-other", "merge-coinjoin-outputs"]);
    }

    #[test]
    fn known_entity_with_other_coins() {
        let a = assess(&[coin(1, GRADE_C | KNOWN_ENTITY), coin(2, 0)]);
        assert_eq!((a.verdict, ids(&a)), (CombineVerdict::Caution, vec!["mix-known-entity", "links-inputs"]));
        assert_eq!(inputs_of(&a, "mix-known-entity"), [0]);
        let a = assess(&[coin(1, KNOWN_ENTITY), coin(2, KNOWN_ENTITY)]);
        assert_eq!(a.verdict, CombineVerdict::Ok, "all from known entities: nothing new");
    }

    #[test]
    fn unassessed_inputs_make_it_incomplete_not_ok_by_default() {
        let a = assess(&[coin(1, 0), report::not_covered(input(2)), report::ungraded(input(3))]);
        assert!(!a.complete);
        assert_eq!((a.verdict, ids(&a)), (CombineVerdict::Ok, vec!["incomplete", "links-inputs"]));
        assert_eq!(inputs_of(&a, "incomplete"), [1, 2]);
        assert_eq!(a.primary_recommendation.unwrap().headline, "Not every input could be assessed");
        assert_eq!((a.inputs_total, a.inputs_graded), (3, 1));
        // a flag still fires when the other inputs are unknown
        let a = assess(&[coin(1, GRADE_F | DARKNET), report::not_covered(input(2))]);
        assert_eq!(a.verdict, CombineVerdict::Avoid);

        let a = assess(&[report::not_covered(input(1)), report::failed(input(2), "spend_failed", "x".into(), true)]);
        assert_eq!((a.verdict, a.complete, ids(&a)), (CombineVerdict::Ok, false, vec!["none-assessed"]));
        assert_eq!((a.best_grade, a.worst_grade), (None, None));

        let a = assess(&[]);
        assert!(a.findings.is_empty() && a.primary_recommendation.is_none() && !a.complete);
    }

    #[test]
    fn schema_lists_exactly_the_catalog_ids() {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../docs/blueberry-v1/transaction-assessment.schema.json")).unwrap();
        let ids = |v: &serde_json::Value| -> Vec<String> {
            let mut x: Vec<String> = v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
            x.sort();
            x
        };
        let mut findings: Vec<String> = catalog().findings.iter().map(|f| f.id.clone()).collect();
        findings.sort();
        assert_eq!(ids(&schema["properties"]["findings"]["items"]["properties"]["id"]["enum"]), findings);
        let mut groups: Vec<String> = catalog().groups.iter().map(|g| g.id.clone()).collect();
        groups.sort();
        assert_eq!(ids(&schema["properties"]["groups"]["items"]["properties"]["id"]["enum"]), groups);
        // every class the rules use has a group title
        for c in [Class::Exposed, Class::Coinjoin, Class::KnownEntity, Class::Clean, Class::LowerGrade, Class::Unassessed] {
            assert!(catalog().groups.iter().any(|g| g.id == c.id()), "{}", c.id());
        }
    }

    #[test]
    fn catalog_covers_every_rule_and_fills_every_placeholder() {
        let a = assess(&[
            coin(1, 0),
            coin(2, GRADE_F),
            coin(3, GRADE_F | DARKNET),
            coin(4, GRADE_F | DUST_ATTACK),
            coin(5, TAINT),
            coin(6, COINJOIN),
            coin(7, COINJOIN),
            coin(8, KNOWN_ENTITY),
            report::not_covered(input(9)),
        ]);
        for f in &a.findings {
            for s in [&f.title, &f.description, &f.recommendation] {
                assert!(!s.contains('{') && !s.is_empty(), "{}: {s}", f.id);
            }
        }
        let sev: Vec<Severity> = a.findings.iter().map(|f| f.severity).collect();
        assert!(sev.windows(2).all(|w| w[0] <= w[1]), "most severe first: {sev:?}");
        // the JSON form keeps the snake_case names the schema documents
        let j: serde_json::Value = serde_json::from_str(&a.to_json()).unwrap();
        assert_eq!(j["verdict"], "avoid");
        assert_eq!(j["findings"][0]["severity"], "critical");
        assert!(j["groups"].as_array().unwrap().len() >= 5);
    }
}
