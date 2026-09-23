//! On-demand localization of prompt-injection findings by iterative bisection.
//!
//! Only regions the scanner already reported (evidence spans, or the chunk that
//! carried the verdict) are refined, and only on this device. A region is split in
//! two; each half that is still flagged is split again, until the smallest flagged
//! parts remain. Smaller clean fragments alone never overturn a finding: every
//! narrowed result must scan clean in context, otherwise that finding keeps its
//! coarse region.
use std::{collections::HashMap, ops::Range, time::Instant};

use serde_json::Value;

use crate::{ark::ContentAnalyzer, config::ChunkingConfig};

use super::{
    payload::{analyze_payload, redact},
    protocol::{JobStatus, RuntimeFinding, ScanOutcome, Verdict},
};

/// Scans one finding may spend. Bisection needs about two per level.
const CHECKS_PER_FINDING: usize = 24;
/// Scans one refinement may spend across all findings and verifications.
const MAX_CHECKS: usize = 96;
/// Regions with at most this many words are not split further.
const MIN_WORDS: usize = 8;

struct Refiner<'a> {
    analyzer: &'a dyn ContentAnalyzer,
    chunking: &'a ChunkingConfig,
    deadline: Instant,
    checks: usize,
    finding_checks: usize,
    cache: HashMap<blake3::Hash, ScanOutcome>,
}

impl Refiner<'_> {
    /// A complete scan result, or `None` once the deadline or a budget is spent.
    fn scan(&mut self, text: &str, per_finding: bool) -> Option<ScanOutcome> {
        if Instant::now() >= self.deadline {
            return None;
        }
        let key = blake3::hash(text.as_bytes());
        if let Some(result) = self.cache.get(&key) {
            return Some(result.clone());
        }
        if self.checks >= MAX_CHECKS || (per_finding && self.finding_checks >= CHECKS_PER_FINDING) {
            return None;
        }
        self.checks += 1;
        if per_finding {
            self.finding_checks += 1;
        }
        let result = analyze_payload(
            self.analyzer,
            &Value::String(text.into()),
            self.chunking,
            self.deadline,
        );
        if result.status != JobStatus::Completed || !result.coverage.complete {
            return None;
        }
        self.cache.insert(key, result.clone());
        Some(result)
    }

    fn flagged(&mut self, text: &str) -> Option<bool> {
        self.scan(text, true).map(|result| {
            result
                .findings
                .iter()
                .any(|f| f.category == "prompt_injection")
        })
    }

    /// The smallest flagged parts of `region`, or `region` itself when it cannot shrink.
    fn bisect(&mut self, text: &str, region: Range<usize>) -> Vec<Range<usize>> {
        let Some((left, right)) = split(text, region.clone()) else {
            return vec![region];
        };
        let left_flagged = self.flagged(&text[left.clone()]);
        let right_flagged = self.flagged(&text[right.clone()]);
        match (left_flagged, right_flagged) {
            (Some(true), Some(false)) => self.bisect(text, left),
            (Some(false), Some(true)) => self.bisect(text, right),
            (Some(true), Some(true)) => {
                let mut spans = self.bisect(text, left);
                spans.extend(self.bisect(text, right));
                spans
            }
            // Neither half alone is flagged: the instruction may cross the cut, so try
            // the middle half once. If that loses the signal too, it needs its context.
            (Some(false), Some(false)) => match middle(text, region.clone()) {
                Some(center) if self.flagged(&text[center.clone()]) == Some(true) => {
                    self.bisect(text, center)
                }
                _ => vec![region],
            },
            // An unfinished scan never narrows.
            _ => vec![region],
        }
    }

    /// Narrows one injection finding and verifies the result in its region's context.
    fn narrow(&mut self, text: &str, region: Range<usize>) -> Vec<Range<usize>> {
        self.finding_checks = 0;
        let spans = self.bisect(text, region.clone());
        if spans == [region.clone()] {
            return spans;
        }
        let local: Vec<_> = spans
            .iter()
            .map(|span| finding(span.start - region.start, span.end - region.start))
            .collect();
        let masked = redact(&text[region.clone()], &local);
        match self.scan(&masked, false) {
            Some(result) if result.verdict == Some(Verdict::Approved) => spans,
            _ => vec![region],
        }
    }
}

/// Byte offsets of word starts within `part`.
fn word_starts(part: &str) -> Vec<usize> {
    part.char_indices()
        .filter_map(|(i, c)| {
            (!c.is_whitespace()
                && (i == 0
                    || part[..i]
                        .chars()
                        .next_back()
                        .is_some_and(char::is_whitespace)))
            .then_some(i)
        })
        .collect()
}

/// The word-aligned middle half of a region, which spans its bisection cut.
fn middle(text: &str, region: Range<usize>) -> Option<Range<usize>> {
    let words = word_starts(&text[region.clone()]);
    if words.len() <= MIN_WORDS {
        return None;
    }
    let end = words
        .get(words.len() * 3 / 4)
        .map_or(region.end, |&offset| region.start + offset);
    Some(region.start + words[words.len() / 4]..end)
}

/// Splits a region into two word-aligned halves, preferring a sentence or line
/// boundary near the middle. `None` when the region is too short to split.
fn split(text: &str, region: Range<usize>) -> Option<(Range<usize>, Range<usize>)> {
    let part = &text[region.clone()];
    let words = word_starts(part);
    if words.len() <= MIN_WORDS {
        return None;
    }
    let ideal = words.len() / 2;
    let radius = (words.len() / 4).max(1);
    let boundary = (ideal.saturating_sub(radius).max(1)..=(ideal + radius).min(words.len() - 1))
        .filter(|&i| {
            part[..words[i]].trim_end().ends_with(['.', '!', '?'])
                || part[words[i - 1]..words[i]].contains('\n')
        })
        .min_by_key(|&i| i.abs_diff(ideal))
        .unwrap_or(ideal);
    let cut = region.start + words[boundary];
    Some((region.start..cut, cut..region.end))
}

fn finding(start_byte: usize, end_byte: usize) -> RuntimeFinding {
    RuntimeFinding {
        field_id: 0,
        start_byte,
        end_byte,
        category: "prompt_injection".into(),
        label: "unsafe_instruction".into(),
        level: None,
        confidence: 1.0,
    }
}

/// Original verdict/coverage/findings remain immutable. Each finding or field that
/// cannot be narrowed and verified keeps its coarse redaction; the others still narrow.
/// `analyzer` must scan on this device only.
pub fn refine_redaction(
    analyzer: &dyn ContentAnalyzer,
    payload: &Value,
    original: &ScanOutcome,
    chunking: &ChunkingConfig,
    deadline: Instant,
) -> Option<Value> {
    if original.status != JobStatus::Completed
        || original.verdict != Some(Verdict::Dangerous)
        || !original.coverage.complete
    {
        return None;
    }
    let fields: Vec<&str> = match payload {
        Value::String(text) => vec![text],
        Value::Array(values) => values.iter().map(Value::as_str).collect::<Option<_>>()?,
        _ => return None,
    };
    let mut refiner = Refiner {
        analyzer,
        chunking,
        deadline,
        checks: 0,
        finding_checks: 0,
        cache: HashMap::new(),
    };
    let mut output = Vec::new();
    for (field_id, text) in fields.iter().enumerate() {
        let old: Vec<_> = original
            .findings
            .iter()
            .filter(|f| f.field_id == field_id)
            .cloned()
            .collect();
        let mut spans = Vec::new();
        for finding_item in &old {
            let region = finding_item.start_byte..finding_item.end_byte;
            if region.is_empty() || text.get(region.clone()).is_none() {
                return None;
            }
            if finding_item.category == "prompt_injection" {
                // The durable same-policy finding already establishes danger.
                spans.extend(
                    refiner
                        .narrow(text, region)
                        .into_iter()
                        .map(|r| finding(r.start, r.end)),
                );
            } else {
                spans.push(finding_item.clone());
            }
        }
        let coarse = redact(text, &old);
        let masked = redact(text, &spans);
        // A narrowed field must also scan clean as a whole; otherwise keep its coarse view.
        let verified = masked == coarse
            || refiner
                .scan(&masked, false)
                .is_some_and(|result| result.verdict == Some(Verdict::Approved));
        output.push(Value::String(if verified { masked } else { coarse }));
    }
    Some(if payload.is_string() {
        output.remove(0)
    } else {
        Value::Array(output)
    })
}
