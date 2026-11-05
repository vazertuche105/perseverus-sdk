//! `check_transport`: does a wallet's own transport really keep different
//! circuit tags on different Tor circuits?
//!
//! It sends requests under several fresh tags to the server's clearnet
//! endpoint, which reports the Tor exit address each one arrived from
//! (`GET /v1/transport/exit`), and compares the exits.
//!
//! The check is statistical. Tor picks exit relays at random, weighted by
//! bandwidth, so two properly separate circuits occasionally pick the same
//! busy exit. One shared exit now and then is normal and passes. What fails
//! is the pattern of broken isolation: different tags *keep* arriving from
//! the same exit.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use perseverus_client_native::net::new_circuit_tag;

use crate::{PerseverusError, PerseverusTransport, Transport, TransportError, TransportRequest};

/// Fewest / most circuit tags `check_transport` accepts.
const MIN_CIRCUITS: u32 = 4;
const MAX_CIRCUITS: u32 = 32;
/// Requests sent under each tag.
const REQUESTS_PER_CIRCUIT: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TransportVerdict {
    /// Different tags left Tor through different exits (allowing for the
    /// occasional chance overlap).
    Pass,
    /// Isolation or Tor routing isn't working; `summary` says which.
    Fail,
    /// More overlap than chance usually gives, but not clearly broken. Run
    /// the check again; if it keeps coming back like this, treat it as a fail.
    Inconclusive,
}

/// The exits seen for one circuit tag.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CircuitExits {
    pub circuit: String,
    /// One entry per request: the exit address, or `"refused"` if the server
    /// didn't see the request come from a listed Tor exit.
    pub exits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TransportCheck {
    pub verdict: TransportVerdict,
    /// What the result means, in a sentence or three.
    pub summary: String,
    pub circuits_tested: u32,
    /// Different exits among the tags' first answers.
    pub distinct_exits: u32,
    /// Tags whose exit another tag had already used. Up to one per eight
    /// tags is normal chance.
    pub shared_exits: u32,
    /// Requests the server refused as not coming from a listed Tor exit.
    pub refused_requests: u32,
    /// Tags whose own requests arrived from more than one exit. Not a
    /// failure: Tor may rebuild a circuit. Informational.
    pub circuits_that_changed_exit: u32,
    pub results: Vec<CircuitExits>,
}

/// Check that `transport` sends requests with different circuit tags over
/// different Tor circuits, against `endpoint` (the server's clearnet
/// `https://` address; a `.onion` has no exit relay to compare).
///
/// Sends `circuits` × 2 requests (`circuits` between 4 and 32; 8 is a good
/// choice). Blocking: Tor builds a circuit per tag, so it takes a while.
#[uniffi::export]
pub fn check_transport(
    endpoint: String,
    transport: Arc<dyn PerseverusTransport>,
    circuits: u32,
) -> Result<TransportCheck, PerseverusError> {
    let base = endpoint.trim().trim_end_matches('/').to_string();
    if !(MIN_CIRCUITS..=MAX_CIRCUITS).contains(&circuits) {
        return Err(PerseverusError::InvalidArgument {
            reason: format!("circuits must be between {MIN_CIRCUITS} and {MAX_CIRCUITS}"),
        });
    }
    crate::check_endpoint(&base, &Transport::Custom { transport: transport.clone() })?;
    if reqwest::Url::parse(&base).ok().and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase().ends_with(".onion"))) == Some(true) {
        return Err(not_available());
    }

    let mut results = Vec::with_capacity(circuits as usize);
    for _ in 0..circuits {
        let tag = new_circuit_tag("check");
        let mut exits = Vec::with_capacity(REQUESTS_PER_CIRCUIT);
        for _ in 0..REQUESTS_PER_CIRCUIT {
            exits.push(ask_exit(&*transport, &base, &tag)?);
        }
        results.push(CircuitExits { circuit: tag, exits });
    }
    Ok(judge(results))
}

fn not_available() -> PerseverusError {
    PerseverusError::Unsupported {
        reason: "check_transport needs the server's clearnet https:// endpoint: over the .onion there is no exit relay to compare".into(),
    }
}

/// One request; the exit address, or "refused".
fn ask_exit(t: &dyn PerseverusTransport, base: &str, circuit: &str) -> Result<String, PerseverusError> {
    let r = t
        .send(TransportRequest {
            method: "GET".into(),
            url: format!("{base}/v1/transport/exit"),
            headers: vec![],
            body: vec![],
            circuit: circuit.into(),
            timeout_ms: 120_000,
        })
        .map_err(|TransportError::Failed { reason }| PerseverusError::Network { reason })?;
    let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap_or_default();
    let code = body["error"]["code"].as_str().unwrap_or("");
    match (r.status, code) {
        (200, _) => body["exit_ip"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| PerseverusError::Internal { reason: "transport/exit answer has no exit_ip".into() }),
        (403, "tor_required") => Ok("refused".into()),
        (404, "not_available") => Err(not_available()),
        (status, _) => Err(PerseverusError::Server {
            status,
            reason: crate::error::server_reason(String::from_utf8_lossy(&r.body).into_owned()),
        }),
    }
}

pub(crate) fn judge(results: Vec<CircuitExits>) -> TransportCheck {
    let n = results.len() as u32;
    let refused = results.iter().flat_map(|c| &c.exits).filter(|e| *e == "refused").count() as u32;
    // Each tag's first exit that the server accepted.
    let firsts: Vec<&str> = results.iter().filter_map(|c| c.exits.iter().find(|e| *e != "refused").map(String::as_str)).collect();
    let answered = firsts.len() as u32;
    let distinct = firsts.iter().collect::<HashSet<_>>().len() as u32;
    let shared = answered - distinct;
    let changed = results
        .iter()
        .filter(|c| c.exits.iter().filter(|e| *e != "refused").collect::<HashSet<_>>().len() > 1)
        .count() as u32;
    let allowed = (answered / 8).max(1);
    let biggest_group = {
        let mut m: HashMap<&str, u32> = HashMap::new();
        for e in &firsts {
            *m.entry(e).or_default() += 1;
        }
        m.into_values().max().unwrap_or(0)
    };

    let (verdict, mut summary) = if answered * 2 < n {
        (
            TransportVerdict::Fail,
            format!(
                "{refused} of {} requests were refused as not coming from a Tor exit relay. \
                 The transport is probably not sending requests through Tor.",
                n as usize * REQUESTS_PER_CIRCUIT
            ),
        )
    } else if distinct == 1 && answered >= MIN_CIRCUITS {
        (
            TransportVerdict::Fail,
            format!(
                "All {answered} circuit tags left Tor through the same exit relay. \
                 Different tags are not getting different circuits."
            ),
        )
    } else if shared <= allowed {
        (
            TransportVerdict::Pass,
            format!(
                "{answered} circuit tags left Tor through {distinct} different exit relays. \
                 Isolation works. An occasional shared exit is normal: Tor picks exits at random, \
                 weighted by bandwidth, so separate circuits sometimes pick the same busy relay."
            ),
        )
    } else if distinct * 2 <= answered {
        (
            TransportVerdict::Fail,
            format!(
                "{answered} circuit tags left Tor through only {distinct} exit relays \
                 ({biggest_group} through the same one). Different tags keep sharing circuits."
            ),
        )
    } else {
        (
            TransportVerdict::Inconclusive,
            format!(
                "{answered} circuit tags left Tor through {distinct} exit relays: {shared} shared one, \
                 more than chance usually gives (up to {allowed}). Run the check again. If it keeps \
                 coming back like this, isolation isn't working."
            ),
        )
    };
    if refused > 0 && verdict != TransportVerdict::Fail {
        summary.push_str(&format!(
            " {refused} request(s) were refused as not from a listed Tor exit; a brand-new exit relay can take up to an hour to be listed."
        ));
    }
    TransportCheck {
        verdict,
        summary,
        circuits_tested: n,
        distinct_exits: distinct,
        shared_exits: shared,
        refused_requests: refused,
        circuits_that_changed_exit: changed,
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(exits_per_tag: &[&[&str]]) -> TransportCheck {
        judge(
            exits_per_tag
                .iter()
                .enumerate()
                .map(|(i, e)| CircuitExits { circuit: format!("check-{i}"), exits: e.iter().map(|s| s.to_string()).collect() })
                .collect(),
        )
    }

    #[test]
    fn verdicts() {
        let distinct: Vec<[&str; 2]> = (0..8).map(|i| [["a", "b", "c", "d", "e", "f", "g", "h"][i]; 2]).collect();
        let v: Vec<&[&str]> = distinct.iter().map(|x| &x[..]).collect();
        let r = run(&v);
        assert_eq!((r.verdict, r.distinct_exits, r.shared_exits), (TransportVerdict::Pass, 8, 0));

        // one chance overlap among 8: still a pass
        let r = run(&[&["a", "a"], &["a", "a"], &["c", "c"], &["d", "d"], &["e", "e"], &["f", "f"], &["g", "g"], &["h", "h"]]);
        assert_eq!((r.verdict, r.shared_exits), (TransportVerdict::Pass, 1));

        // everything through one exit: isolation broken
        let r = run(&[&["x", "x"][..]; 8]);
        assert_eq!(r.verdict, TransportVerdict::Fail);
        assert!(r.summary.contains("same exit"), "{}", r.summary);

        // mostly shared
        let r = run(&[&["a", "a"], &["a", "a"], &["a", "a"], &["b", "b"], &["b", "b"], &["b", "b"], &["c", "c"], &["d", "d"]]);
        assert_eq!(r.verdict, TransportVerdict::Fail);

        // somewhat more overlap than chance: run again
        let r = run(&[&["a", "a"], &["a", "a"], &["b", "b"], &["b", "b"], &["c", "c"], &["d", "d"], &["e", "e"], &["f", "f"]]);
        assert_eq!(r.verdict, TransportVerdict::Inconclusive);

        // not through Tor
        let r = run(&[&["refused", "refused"][..]; 8]);
        assert_eq!((r.verdict, r.refused_requests), (TransportVerdict::Fail, 16));
        assert!(r.summary.contains("not sending requests through Tor"));

        // one new exit refused, the rest fine: pass, with a note
        let r = run(&[&["refused", "z"], &["b", "b"], &["c", "c"], &["d", "d"], &["e", "e"], &["f", "f"], &["g", "g"], &["h", "h"]]);
        assert_eq!(r.verdict, TransportVerdict::Pass);
        assert!(r.summary.contains("brand-new exit"));

        // a tag whose circuit was rebuilt is informational only
        let r = run(&[&["a", "q"], &["b", "b"], &["c", "c"], &["d", "d"]]);
        assert_eq!((r.verdict, r.circuits_that_changed_exit), (TransportVerdict::Pass, 1));
    }
}
