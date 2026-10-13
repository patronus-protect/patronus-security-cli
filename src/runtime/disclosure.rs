//! User-confirmed disclosure of selected PII types from a dangerous runtime result.
//!
//! Only exact, typed PII evidence spans of confirmed types become visible. Every
//! other finding stays masked and wins over an overlapping confirmed span: other
//! PII types, unknown scanner labels, DLP, prompt injection, threat, and any
//! verdict that only names its chunk. The finished view is scanned again on this
//! device; anything but the revealed PII rejects it.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use serde_json::Value;

use crate::{ark::ContentAnalyzer, config::ChunkingConfig};

use super::{
    payload::{analyze_payload, REDACTED},
    protocol::{DisclosureSpan, JobStatus, PiiType, ScanOutcome, Verdict},
};

type Range = (usize, usize);

/// Spans of confirmed types that no remaining lock touches.
pub fn revealable(outcome: &ScanOutcome, authorized: &BTreeSet<PiiType>) -> Vec<DisclosureSpan> {
    if outcome.status != JobStatus::Completed
        || outcome.verdict != Some(Verdict::Dangerous)
        || !outcome.coverage.complete
    {
        return vec![];
    }
    let confirmed = |span: &DisclosureSpan| span.pii_type.is_some_and(|t| authorized.contains(&t));
    let fields: BTreeSet<usize> = outcome.disclosure.iter().map(|s| s.field_id).collect();
    let mut result = Vec::new();
    for field in fields {
        let spans: Vec<&DisclosureSpan> = outcome
            .disclosure
            .iter()
            .filter(|s| s.field_id == field)
            .collect();
        let explained = union(spans.iter().map(|s| (s.start_byte, s.end_byte)).collect());
        let mut locks: Vec<Range> = spans
            .iter()
            .filter(|s| !confirmed(s))
            .map(|s| (s.start_byte, s.end_byte))
            .collect();
        for finding in outcome.findings.iter().filter(|f| f.field_id == field) {
            let range = (finding.start_byte, finding.end_byte);
            // A PII finding is explained by its typed spans, whose own types lock or
            // release them. Anything else, including a chunk-level verdict, locks.
            if finding.category != "pii" || !covered(range, &explained) {
                locks.push(range);
            }
        }
        result.extend(
            spans
                .into_iter()
                .filter(|s| {
                    confirmed(s)
                        && !locks
                            .iter()
                            .any(|l| overlaps(*l, (s.start_byte, s.end_byte)))
                })
                .cloned(),
        );
    }
    result
}

pub fn counts(spans: &[DisclosureSpan]) -> BTreeMap<PiiType, usize> {
    let mut counts = BTreeMap::new();
    for span in spans {
        if let Some(t) = span.pii_type {
            *counts.entry(t).or_insert(0) += 1;
        }
    }
    counts
}

/// Binds a confirmation to the exact locations it was shown for.
pub fn digest(spans: &[DisclosureSpan]) -> String {
    let encoded = serde_json::to_vec(spans).unwrap_or_default();
    blake3::hash(&encoded).to_hex().to_string()
}

/// The disclosed view, or `None` when nothing is revealable or the view does not
/// re-scan as expected. `analyzer` must scan on this device only.
pub fn disclose(
    analyzer: &dyn ContentAnalyzer,
    payload: &Value,
    original: &ScanOutcome,
    authorized: &BTreeSet<PiiType>,
    chunking: &ChunkingConfig,
    deadline: Instant,
) -> Option<Value> {
    let revealed = revealable(original, authorized);
    if revealed.is_empty() {
        return None;
    }
    let (view, visible) = build_view(payload, original, &revealed)?;
    verify(analyzer, &view, &visible, chunking, deadline).then_some(view)
}

/// Masks every finding except the revealed spans. Returns the view and, per
/// field, the revealed ranges in view coordinates.
pub fn build_view(
    payload: &Value,
    original: &ScanOutcome,
    revealed: &[DisclosureSpan],
) -> Option<(Value, Vec<Vec<Range>>)> {
    let fields: Vec<&str> = match payload {
        Value::String(text) => vec![text],
        Value::Array(values) => values.iter().map(Value::as_str).collect::<Option<_>>()?,
        _ => return None,
    };
    let mut output = Vec::with_capacity(fields.len());
    let mut visible = Vec::with_capacity(fields.len());
    for (field_id, text) in fields.iter().enumerate() {
        let open: Vec<Range> = revealed
            .iter()
            .filter(|s| s.field_id == field_id)
            .map(|s| (s.start_byte, s.end_byte))
            .collect();
        let mut mask = Vec::new();
        for finding in original.findings.iter().filter(|f| f.field_id == field_id) {
            let range = (finding.start_byte, finding.end_byte);
            if range.0 >= range.1 || text.get(range.0..range.1).is_none() {
                return None;
            }
            mask.extend(subtract(range, &open));
        }
        let mask = union(mask);
        let mut view = String::with_capacity(text.len());
        let mut cursor = 0;
        for &(start, end) in &mask {
            view.push_str(text.get(cursor..start)?);
            view.push_str(REDACTED);
            cursor = end;
        }
        view.push_str(text.get(cursor..)?);
        // Revealed spans never intersect the mask, so each maps by a fixed shift.
        let position = |offset: usize| {
            mask.iter()
                .filter(|(_, end)| *end <= offset)
                .fold(offset, |at, (start, end)| {
                    at - (end - start) + REDACTED.len()
                })
        };
        visible.push(union(
            open.iter()
                .map(|&(s, e)| (position(s), position(e)))
                .collect(),
        ));
        output.push(Value::String(view));
    }
    let view = if payload.is_string() {
        output.remove(0)
    } else {
        Value::Array(output)
    };
    Some((view, visible))
}

/// Accepts the view only if every finding in it lies within revealed PII.
fn verify(
    analyzer: &dyn ContentAnalyzer,
    view: &Value,
    visible: &[Vec<Range>],
    chunking: &ChunkingConfig,
    deadline: Instant,
) -> bool {
    let result = analyze_payload(analyzer, view, chunking, deadline);
    result.status == JobStatus::Completed
        && result.coverage.complete
        && result.findings.iter().all(|f| {
            f.category == "pii"
                && visible
                    .get(f.field_id)
                    .is_some_and(|open| covered((f.start_byte, f.end_byte), open))
        })
}

/// Sorted, disjoint ranges; touching ranges merge like `redact` does.
fn union(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.retain(|(s, e)| s < e);
    ranges.sort_unstable();
    let mut merged: Vec<Range> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn overlaps(a: Range, b: Range) -> bool {
    a.0 < b.1 && b.0 < a.1
}

/// Whether `range` lies entirely within the sorted, disjoint `ranges`.
fn covered(range: Range, ranges: &[Range]) -> bool {
    ranges.iter().any(|&(s, e)| s <= range.0 && range.1 <= e)
}

/// Parts of `range` outside `holes`.
fn subtract(range: Range, holes: &[Range]) -> Vec<Range> {
    let mut parts = vec![range];
    for &hole in holes {
        parts = parts
            .into_iter()
            .flat_map(|(s, e)| {
                if !overlaps((s, e), hole) {
                    return vec![(s, e)];
                }
                [(s, hole.0.max(s)), (hole.1.min(e), e)]
                    .into_iter()
                    .filter(|(a, b)| a < b)
                    .collect()
            })
            .collect();
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::protocol::{PayloadCoverage, RuntimeFinding};
    use serde_json::json;

    fn finding(field_id: usize, start: usize, end: usize, category: &str) -> RuntimeFinding {
        RuntimeFinding {
            field_id,
            start_byte: start,
            end_byte: end,
            category: category.into(),
            label: "x".into(),
            level: Some("l1".into()),
            confidence: 1.0,
        }
    }

    fn span(field_id: usize, start: usize, end: usize, t: Option<PiiType>) -> DisclosureSpan {
        DisclosureSpan {
            field_id,
            start_byte: start,
            end_byte: end,
            pii_type: t,
        }
    }

    fn outcome(findings: Vec<RuntimeFinding>, disclosure: Vec<DisclosureSpan>) -> ScanOutcome {
        ScanOutcome {
            status: JobStatus::Completed,
            verdict: Some(Verdict::Dangerous),
            findings,
            coverage: PayloadCoverage {
                complete: true,
                ..PayloadCoverage::default()
            },
            redacted: None,
            reason: None,
            notice: None,
            disclosure,
        }
    }

    fn only(types: &[PiiType]) -> BTreeSet<PiiType> {
        types.iter().copied().collect()
    }

    #[test]
    fn reveals_only_confirmed_types() {
        let text = "mail a@b.de ip 10.0.0.1 tel 0301234567";
        let outcome = outcome(
            vec![
                finding(0, 5, 11, "pii"),
                finding(0, 15, 23, "pii"),
                finding(0, 28, 38, "pii"),
            ],
            vec![
                span(0, 5, 11, Some(PiiType::Email)),
                span(0, 15, 23, Some(PiiType::IpAddress)),
                span(0, 28, 38, Some(PiiType::Phone)),
            ],
        );
        let open = revealable(&outcome, &only(&[PiiType::Email, PiiType::IpAddress]));
        assert_eq!(counts(&open).len(), 2);
        let (view, visible) = build_view(&json!(text), &outcome, &open).unwrap();
        assert_eq!(view, json!("mail a@b.de ip 10.0.0.1 tel [REDACTED]"));
        assert_eq!(visible, vec![vec![(5, 11), (15, 23)]]);
    }

    #[test]
    fn remaining_locks_take_precedence() {
        // An injection finding overlaps the email; a chunk-level PII verdict covers the IP.
        let outcome = outcome(
            vec![
                finding(0, 0, 10, "pii"),
                finding(0, 8, 20, "prompt_injection"),
                finding(1, 0, 30, "pii"),
            ],
            vec![
                span(0, 0, 10, Some(PiiType::Email)),
                span(1, 5, 13, Some(PiiType::IpAddress)),
            ],
        );
        assert!(revealable(&outcome, &only(&[PiiType::Email, PiiType::IpAddress])).is_empty());
    }

    #[test]
    fn unknown_and_unconfirmed_overlapping_spans_lock() {
        let outcome = outcome(
            vec![finding(0, 0, 30, "pii")],
            vec![
                span(0, 0, 22, Some(PiiType::Iban)),
                span(0, 10, 30, Some(PiiType::CreditCard)),
                span(0, 40, 50, None),
            ],
        );
        assert!(revealable(&outcome, &only(&[PiiType::Iban])).is_empty());
        assert_eq!(
            revealable(&outcome, &only(&[PiiType::Iban, PiiType::CreditCard])).len(),
            2
        );
    }

    #[test]
    fn maps_view_offsets_across_multibyte_text_and_masks() {
        let text = "Grüße 🔑 secret, mail ä@b.de";
        let secret = text.find("secret").unwrap();
        let mail = text.find("ä@b.de").unwrap();
        let outcome = outcome(
            vec![
                finding(0, secret, secret + 6, "dlp"),
                finding(0, mail, text.len(), "pii"),
            ],
            vec![span(0, mail, text.len(), Some(PiiType::Email))],
        );
        let open = revealable(&outcome, &only(&[PiiType::Email]));
        let (view, visible) = build_view(&json!([text]), &outcome, &open).unwrap();
        let view = view[0].as_str().unwrap();
        assert_eq!(view, "Grüße 🔑 [REDACTED], mail ä@b.de");
        let (s, e) = visible[0][0];
        assert_eq!(&view[s..e], "ä@b.de");
    }
}
