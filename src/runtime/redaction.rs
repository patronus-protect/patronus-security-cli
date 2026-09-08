//! On-demand localization. Smaller clean fragments alone never overturn a finding.
use std::{collections::HashMap, ops::Range, time::Instant};

use serde_json::Value;

use crate::{ark::ContentAnalyzer, config::ChunkingConfig};

use super::{
    payload::{analyze_payload, redact},
    protocol::{JobStatus, RuntimeFinding, ScanOutcome, Verdict},
};

const MAX_CHECKS: usize = 20;
const MIN_WORDS: usize = 8;

struct Refiner<'a> {
    analyzer: &'a dyn ContentAnalyzer,
    chunking: &'a ChunkingConfig,
    deadline: Instant,
    checks: usize,
    cache: HashMap<blake3::Hash, ScanOutcome>,
}

impl Refiner<'_> {
    fn scan(&mut self, text: &str) -> Option<ScanOutcome> {
        if Instant::now() >= self.deadline {
            return None;
        }
        let key = blake3::hash(text.as_bytes());
        if let Some(result) = self.cache.get(&key) {
            return Some(result.clone());
        }
        if self.checks >= MAX_CHECKS {
            return None;
        }
        self.checks += 1;
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

    fn narrow(&mut self, text: &str, region: Range<usize>) -> Option<Vec<Range<usize>>> {
        let part = &text[region.clone()];
        let words: Vec<usize> = part
            .char_indices()
            .filter_map(|(i, c)| {
                (!c.is_whitespace()
                    && (i == 0
                        || part[..i]
                            .chars()
                            .next_back()
                            .is_some_and(char::is_whitespace)))
                .then_some(i)
            })
            .take(1025)
            .collect();
        if words.len() <= MIN_WORDS || words.len() > 1024 {
            return Some(vec![region]);
        }
        // Try balanced halves, thirds, then quarters of the SAME parent. Stop
        // at the first verified recovery instead of minimizing every bad leaf.
        for parts in 2..=4 {
            let mut cuts = vec![0];
            for n in 1..parts {
                let ideal = words.len() * n / parts;
                let radius = (words.len() / (2 * parts)).max(1);
                let first = ideal.saturating_sub(radius).max(1);
                let last = (ideal + radius).min(words.len() - 1);
                let boundary = (first..=last)
                    .filter(|&i| {
                        words[i] > *cuts.last().unwrap()
                            && (part[..words[i]].trim_end().ends_with(['.', '!', '?'])
                                || part[words[i - 1]..words[i]].contains('\n'))
                    })
                    .min_by_key(|&i| i.abs_diff(ideal))
                    .unwrap_or(ideal);
                if words[boundary] > *cuts.last().unwrap() {
                    cuts.push(words[boundary]);
                }
            }
            cuts.push(part.len());
            let mut spans = Vec::new();
            for pair in cuts.windows(2) {
                let result = self.scan(&part[pair[0]..pair[1]])?;
                if result
                    .findings
                    .iter()
                    .any(|f| f.category == "prompt_injection")
                {
                    spans.push(pair[0]..pair[1]);
                }
            }
            // Losing every signal is not evidence that the parent is safe.
            if spans.is_empty() || spans.len() == cuts.len() - 1 {
                continue;
            }
            let local: Vec<_> = spans.iter().map(|r| finding(r.start, r.end)).collect();
            let masked = redact(part, &local);
            if self.scan(&masked)?.verdict != Some(Verdict::Approved) {
                continue;
            }
            // Check restored text at each boundary with neighboring context.
            let mut boundaries_clean = true;
            for &cut in &cuts[1..cuts.len() - 1] {
                let i = words.partition_point(|&start| start < cut);
                let start = words[i.saturating_sub(4)];
                let end = words.get(i + 4).copied().unwrap_or(part.len());
                let overlap: Vec<_> = spans
                    .iter()
                    .filter_map(|r| {
                        let a = r.start.max(start);
                        let b = r.end.min(end);
                        (a < b).then(|| finding(a - start, b - start))
                    })
                    .collect();
                if self.scan(&redact(&part[start..end], &overlap))?.verdict
                    != Some(Verdict::Approved)
                {
                    boundaries_clean = false;
                    break;
                }
            }
            if boundaries_clean {
                return Some(
                    spans
                        .into_iter()
                        .map(|r| region.start + r.start..region.start + r.end)
                        .collect(),
                );
            }
        }
        Some(vec![region])
    }
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

/// Original verdict/coverage/findings remain immutable. Failure keeps coarse redaction.
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
        cache: HashMap::new(),
    };
    let mut output = Vec::new();
    for (field_id, text) in fields.iter().enumerate() {
        let mut spans = Vec::new();
        for old in original.findings.iter().filter(|f| f.field_id == field_id) {
            let region = old.start_byte..old.end_byte;
            if region.is_empty() || text.get(region.clone()).is_none() {
                return None;
            }
            if old.category == "prompt_injection" {
                // The durable same-policy finding already establishes danger.
                spans.extend(
                    refiner
                        .narrow(text, region)?
                        .into_iter()
                        .map(|r| finding(r.start, r.end)),
                );
            } else {
                spans.push(old.clone());
            }
        }
        let masked = redact(text, &spans);
        let old: Vec<_> = original
            .findings
            .iter()
            .filter(|f| f.field_id == field_id)
            .cloned()
            .collect();
        // Unchanged coarse views and already-approved fields need no new analysis.
        if masked != redact(text, &old) && refiner.scan(&masked)?.verdict != Some(Verdict::Approved)
        {
            return None;
        }
        output.push(Value::String(masked));
    }
    Some(if payload.is_string() {
        output.remove(0)
    } else {
        Value::Array(output)
    })
}
