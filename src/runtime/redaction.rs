//! On-demand localization of prompt-injection findings by iterative bisection.
//!
//! Only regions the scanner already reported (evidence spans, or the chunk that
//! carried the verdict) are refined, and only on this device. A region is split in
//! two; each half that is still flagged is split again, until the smallest flagged
//! parts remain. Restoring a sibling must scan clean in the masked field's context.
//! Once restored, that sibling stays visible even if later scans fail or exhaust
//! their budget. Fallback keeps the last verified mask, never an older, larger one.
//! Line-structured text (env files, CSV, configs) is split by lines even when it has
//! few words. A part of a hidden container (an HTML comment) that stays flagged
//! masks the whole container: hidden text is not content for the user or the agent,
//! and its harmless-looking lead-in can carry the instruction without its payload.
use std::{collections::HashMap, ops::Range, time::Instant};

use serde_json::Value;

use crate::{ark::ContentAnalyzer, config::ChunkingConfig};

use super::{
    payload::{analyze_payload, redact},
    protocol::{JobStatus, RuntimeFinding, ScanOutcome, Verdict},
};

/// Scans one finding may spend. Bisection needs about two per level.
const CHECKS_PER_FINDING: usize = 24;
/// Scans one refinement may spend across all findings.
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
        self.scan(text, true)
            .and_then(|result| match result.verdict {
                Some(Verdict::Approved) => Some(false),
                Some(Verdict::Dangerous) => Some(true),
                _ => None,
            })
    }

    /// Commit only verified smaller masks; a later failure never undoes that progress.
    fn narrow(
        &mut self,
        text: &str,
        region: Range<usize>,
        regions: &mut Vec<Range<usize>>,
        fixed: &[RuntimeFinding],
    ) {
        let Some((left, right)) = split(text, region.clone()) else {
            return;
        };
        let left_flagged = self.flagged(&text[left.clone()]);
        let right_flagged = self.flagged(&text[right.clone()]);
        let parts: Vec<(Range<usize>, bool)> = match (left_flagged, right_flagged) {
            // Neither half alone is flagged: the instruction may cross the cut, so try
            // the middle half once. If that loses the signal too, it needs its context.
            (Some(false), Some(false)) => match middle(text, region.clone()) {
                Some(center) if self.flagged(&text[center.clone()]) == Some(true) => {
                    vec![(center, true)]
                }
                _ => return,
            },
            (None, None) => return,
            _ => [(left, left_flagged), (right, right_flagged)]
                .into_iter()
                .filter(|(_, flagged)| *flagged != Some(false))
                .map(|(part, flagged)| (part, flagged == Some(true)))
                .collect(),
        };
        let index = regions.iter().position(|part| part == &region).unwrap();
        let mut candidate = regions.clone();
        candidate.splice(index..index + 1, parts.iter().map(|(part, _)| part.clone()));
        let masked = masked_view(text, &candidate, fixed);
        if masked != masked_view(text, regions, fixed)
            && !self
                .scan(&masked, false)
                .is_some_and(|result| result.verdict == Some(Verdict::Approved))
        {
            return;
        }
        *regions = candidate;
        for (part, flagged) in parts {
            if flagged {
                self.narrow(text, part, regions, fixed);
            }
        }
    }
}

fn masked_view(text: &str, regions: &[Range<usize>], fixed: &[RuntimeFinding]) -> String {
    let mut spans = fixed.to_vec();
    spans.extend(regions.iter().map(|part| finding(part.start, part.end)));
    redact(text, &spans)
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

/// Byte offsets of the starts of non-blank lines within `part`.
fn line_starts(part: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(part.match_indices('\n').map(|(i, _)| i + 1))
        .filter(|&i| {
            part[i..]
                .lines()
                .next()
                .is_some_and(|line| !line.trim().is_empty())
        })
        .collect()
}

/// Splits a region into two word-aligned halves, preferring a sentence or line
/// boundary near the middle. Regions with few words split between lines instead.
/// `None` when the region is a single short line.
fn split(text: &str, region: Range<usize>) -> Option<(Range<usize>, Range<usize>)> {
    let part = &text[region.clone()];
    let words = word_starts(part);
    if words.len() <= MIN_WORDS {
        let lines = line_starts(part);
        if lines.len() < 2 {
            return None;
        }
        let cut = region.start + lines[lines.len() / 2];
        return Some((region.start..cut, cut..region.end));
    }
    // Paragraphs are natural units: cut at the blank line nearest the middle first,
    // however far from it, so a harmless paragraph is not fused to an attack.
    if let Some(boundary) = (1..words.len())
        .filter(|&i| part[words[i - 1]..words[i]].matches('\n').count() >= 2)
        .min_by_key(|&i| i.abs_diff(words.len() / 2))
    {
        let cut = region.start + words[boundary];
        return Some((region.start..cut, cut..region.end));
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

/// Byte ranges of HTML comments; an unterminated comment runs to the end.
fn hidden_containers(text: &str) -> Vec<Range<usize>> {
    let mut containers = Vec::new();
    let mut from = 0;
    while let Some(open) = text[from..].find("<!--").map(|i| from + i) {
        let end = text[open + 4..]
            .find("-->")
            .map_or(text.len(), |i| open + 4 + i + 3);
        containers.push(open..end);
        from = end;
    }
    containers
}

/// Widens each masked region to every hidden container it touches, then merges overlaps.
fn cover_hidden_containers(text: &str, regions: &mut Vec<Range<usize>>) {
    let containers = hidden_containers(text);
    for region in regions.iter_mut() {
        for container in &containers {
            if container.start < region.end && region.start < container.end {
                region.start = region.start.min(container.start);
                region.end = region.end.max(container.end);
            }
        }
    }
    regions.sort_unstable_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for region in regions.drain(..) {
        match merged.last_mut().filter(|last| region.start <= last.end) {
            Some(last) => last.end = last.end.max(region.end),
            None => merged.push(region),
        }
    }
    *regions = merged;
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

/// Original verdict/coverage/findings remain immutable. Each unresolved part keeps
/// its redaction; approved siblings are never masked again by a later fallback.
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
        let mut regions = Vec::new();
        for finding_item in &old {
            let region = finding_item.start_byte..finding_item.end_byte;
            if region.is_empty() || text.get(region.clone()).is_none() {
                return None;
            }
            if finding_item.category == "prompt_injection" {
                regions.push(region);
            } else {
                spans.push(finding_item.clone());
            }
        }
        // Overlapping model-stage findings share one refinement. A later duplicate
        // must not mask approved siblings again after the deadline or budget expires.
        regions.sort_unstable_by_key(|r| r.start);
        let mut merged: Vec<Range<usize>> = Vec::new();
        for region in regions {
            if let Some(last) = merged.last_mut().filter(|last| region.start < last.end) {
                last.end = last.end.max(region.end);
            } else {
                merged.push(region);
            }
        }
        let mut regions = merged.clone();
        for region in merged {
            refiner.finding_checks = 0;
            // The durable same-policy finding already establishes danger.
            refiner.narrow(text, region, &mut regions, &spans);
        }
        cover_hidden_containers(text, &mut regions);
        output.push(Value::String(masked_view(text, &regions, &spans)));
    }
    Some(if payload.is_string() {
        output.remove(0)
    } else {
        Value::Array(output)
    })
}
