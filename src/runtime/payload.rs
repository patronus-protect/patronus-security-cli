//! Complete JSON text coverage and redaction for local runtime jobs.

use std::time::Instant;

use serde_json::Value;

use crate::ark::{ChunkInput, ContentAnalyzer, FinalClassification, ScanNotice};
use crate::chunk::text_ranges;
use crate::config::ChunkingConfig;
use crate::runtime::protocol::{JobStatus, PayloadCoverage, RuntimeFinding, ScanOutcome, Verdict};

const REDACTED: &str = "[REDACTED]";

pub fn analyze_payload(
    analyzer: &dyn ContentAnalyzer,
    payload: &Value,
    chunking: &ChunkingConfig,
    deadline: Instant,
) -> ScanOutcome {
    let mut scan = PayloadScan {
        analyzer,
        chunking,
        deadline,
        coverage: PayloadCoverage::default(),
        findings: Vec::new(),
        next_field: 0,
        input_tokens: 0,
        notice: None,
    };
    let unsupported = inspect(payload, &mut scan.coverage);
    let result = if unsupported {
        Err(ScanError::Incomplete("unsupported_content"))
    } else if chunking.target_bytes == 0 || chunking.overlap_bytes >= chunking.target_bytes {
        Err(ScanError::Failed("invalid_chunking"))
    } else {
        scan.input_tokens = match payload {
            Value::String(text) => crate::inference::input_tokens(text),
            Value::Array(items) => items
                .iter()
                .map(|v| crate::inference::input_tokens(v.as_str().expect("validated text")))
                .sum(),
            _ => unreachable!("validated payload"),
        };
        scan.value(payload)
    };
    merge_findings(&mut scan.findings);
    let (status, verdict, redacted, reason) = match result {
        Ok(redacted) => {
            scan.coverage.complete = true;
            let dangerous = !scan.findings.is_empty();
            (
                JobStatus::Completed,
                Some(if dangerous {
                    Verdict::Dangerous
                } else {
                    Verdict::Approved
                }),
                dangerous.then_some(redacted),
                None,
            )
        }
        Err(ScanError::Incomplete(reason)) => {
            (JobStatus::Incomplete, None, None, Some(reason.into()))
        }
        Err(ScanError::Failed(reason)) => (JobStatus::Failed, None, None, Some(reason.into())),
    };
    ScanOutcome {
        status,
        verdict,
        findings: scan.findings,
        coverage: scan.coverage,
        redacted,
        reason,
        notice: scan.notice,
    }
}

enum ScanError {
    Incomplete(&'static str),
    Failed(&'static str),
}

struct PayloadScan<'a> {
    analyzer: &'a dyn ContentAnalyzer,
    chunking: &'a ChunkingConfig,
    deadline: Instant,
    coverage: PayloadCoverage,
    findings: Vec<RuntimeFinding>,
    next_field: usize,
    input_tokens: usize,
    notice: Option<ScanNotice>,
}

impl PayloadScan<'_> {
    fn check_deadline(&self) -> Result<(), ScanError> {
        if Instant::now() >= self.deadline {
            Err(ScanError::Failed("scan_timeout"))
        } else {
            Ok(())
        }
    }

    fn value(&mut self, value: &Value) -> Result<Value, ScanError> {
        self.check_deadline()?;
        match value {
            Value::String(text) => self.text(text).map(Value::String),
            Value::Array(items) => items
                .iter()
                .map(|item| self.value(item))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            _ => Err(ScanError::Incomplete("unsupported_payload")),
        }
    }

    fn text(&mut self, text: &str) -> Result<String, ScanError> {
        let field_id = self.next_field;
        self.next_field += 1;
        if text.is_empty() {
            return Ok(String::new());
        }
        let field = format!("field-{field_id}");
        // Runtime strings already have exact UTF-8 offsets, including a literal
        // BOM. File decoding and its original-byte map are unnecessary here.
        let mut scanned_until = 0;
        let findings_before = self.findings.len();
        self.check_deadline()?;
        let mut chunks = text_ranges(text, self.chunking).enumerate();
        loop {
            self.check_deadline()?;
            let Some((index, chunk)) = chunks.next() else {
                break;
            };
            self.check_deadline()?;
            let chunk_text = &text[chunk.clone()];
            let chunk_id = format!("{field}-{index}");
            let outcome = self
                .analyzer
                .analyze(ChunkInput {
                    input_tokens: Some(self.input_tokens),
                    run_id: "runtime",
                    chunk_id: &chunk_id,
                    file_id: &field,
                    path: &field,
                    content: chunk_text,
                })
                .map_err(|error| {
                    if let Some(retry_after) = crate::inference::usage_limit_retry_after(&error) {
                        self.notice = Some(ScanNotice::api_usage_limit("none", retry_after));
                        ScanError::Failed("usage_limit_reached")
                    } else if let Some(reason) = crate::api_client::authentication_reason(&error) {
                        self.notice = Some(ScanNotice::api_authentication(reason, "none"));
                        ScanError::Failed(reason)
                    } else {
                        ScanError::Failed(crate::inference::scan_failure_reason(&error))
                    }
                })?;
            if outcome.notice.is_some() {
                self.notice = outcome.notice.clone();
            }
            self.check_deadline()?;
            if outcome.degraded
                || !outcome.failures.is_empty()
                || outcome.classifications.is_empty()
            {
                return Err(ScanError::Incomplete("incomplete_classification"));
            }
            for classification in outcome.classifications {
                self.project(&classification, chunk_text, field_id, chunk.start)?;
            }
            self.coverage.bytes_scanned += chunk.end.saturating_sub(scanned_until);
            scanned_until = scanned_until.max(chunk.end);
        }
        self.coverage.fields_scanned += 1;
        Ok(redact(text, &self.findings[findings_before..]))
    }

    fn project(
        &mut self,
        classification: &FinalClassification,
        text: &str,
        field_id: usize,
        chunk_start: usize,
    ) -> Result<(), ScanError> {
        if !classification.terminal || !valid_confidence(classification.confidence) {
            return Err(ScanError::Incomplete("invalid_classification"));
        }
        // Never forward free-form classifier labels, evidence text, paths or
        // exception details into model-visible findings.
        let (category, label) = match classification.category.as_str() {
            "prompt_injection" => ("prompt_injection", "unsafe_instruction"),
            "dlp" => ("dlp", "sensitive_data"),
            "pii" => ("pii", "personal_data"),
            "threat" => ("threat", "threat_signal"),
            _ => return Err(ScanError::Incomplete("invalid_classification")),
        };
        if !classification.matched {
            return if classification.evidence.is_empty() {
                Ok(())
            } else {
                Err(ScanError::Incomplete("invalid_classification"))
            };
        }
        let level = match classification.level.as_str() {
            "l1" | "l2" | "l3" => Some(classification.level.clone()),
            _ => None,
        };
        let mut push = |start_byte, end_byte, confidence| {
            self.findings.push(RuntimeFinding {
                field_id,
                start_byte,
                end_byte,
                category: category.into(),
                label: label.into(),
                level: level.clone(),
                confidence,
            });
        };
        // A verdict without evidence spans still names its chunk: every other chunk
        // was classified on its own, so masking the whole field would hide text the
        // scanner judged separately.
        if classification.evidence.is_empty() {
            push(
                chunk_start,
                chunk_start + text.len(),
                classification.confidence,
            );
        }
        for span in &classification.evidence {
            if span.start >= span.end
                || span.end > text.len()
                || !text.is_char_boundary(span.start)
                || !text.is_char_boundary(span.end)
                || !valid_confidence(span.confidence)
            {
                return Err(ScanError::Incomplete("invalid_evidence_span"));
            }
            push(
                chunk_start + span.start,
                chunk_start + span.end,
                span.confidence,
            );
        }
        Ok(())
    }
}

fn valid_confidence(value: f64) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

pub(super) fn redact(text: &str, findings: &[RuntimeFinding]) -> String {
    let mut spans: Vec<_> = findings
        .iter()
        .map(|finding| (finding.start_byte, finding.end_byte))
        .collect();
    spans.sort_unstable();
    let mut result = String::new();
    let mut cursor = 0;
    let mut redacting = false;
    for (start, end) in spans {
        if redacting && start <= cursor {
            cursor = cursor.max(end);
        } else {
            result.push_str(&text[cursor..start]);
            result.push_str(REDACTED);
            cursor = end;
            redacting = true;
        }
    }
    result.push_str(&text[cursor..]);
    result
}

fn merge_findings(findings: &mut Vec<RuntimeFinding>) {
    findings.sort_by(|a, b| {
        (a.field_id, &a.category, &a.level, a.start_byte, a.end_byte).cmp(&(
            b.field_id,
            &b.category,
            &b.level,
            b.start_byte,
            b.end_byte,
        ))
    });
    let mut merged: Vec<RuntimeFinding> = Vec::new();
    for finding in findings.drain(..) {
        if let Some(last) = merged.last_mut() {
            if last.field_id == finding.field_id
                && last.category == finding.category
                && last.level == finding.level
                && finding.start_byte <= last.end_byte
            {
                last.end_byte = last.end_byte.max(finding.end_byte);
                last.confidence = last.confidence.max(finding.confidence);
                continue;
            }
        }
        merged.push(finding);
    }
    *findings = merged;
}

fn inspect(value: &Value, coverage: &mut PayloadCoverage) -> bool {
    match value {
        Value::String(text) => {
            if !text.is_empty() {
                coverage.fields_total += 1;
                coverage.bytes_total += text.len();
            }
            false
        }
        // Every item must be visited because `inspect` records coverage as a side effect.
        #[allow(clippy::unnecessary_fold)]
        Value::Array(items) => items.iter().fold(false, |unsupported, item| {
            !item.is_string() || inspect(item, coverage) || unsupported
        }),
        _ => true,
    }
}
