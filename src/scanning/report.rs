use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ark::FinalClassification;
use crate::chunk::{hash, ChunkRecord};
use crate::cli::FailOn;
use crate::discovery::FileRecord;
use crate::target::TargetKind;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    Clean,
    Findings,
    Incomplete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub path: String,
    pub category: String,
    pub label: String,
    pub confidence: f64,
    pub level: String,
    pub source: String,
    pub line_start: usize,
    pub line_end: usize,
    pub original_byte_start: usize,
    pub original_byte_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureRecord {
    pub schema: String,
    pub run_id: String,
    pub path: Option<String>,
    pub chunk_id: Option<String>,
    pub category: Option<String>,
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub discovered_files: usize,
    pub eligible_files: usize,
    pub analyzed_files: usize,
    pub skipped_files: usize,
    pub eligible_bytes: u64,
    pub analyzed_bytes: u64,
    pub chunks: usize,
    pub classifications: usize,
    pub failures: usize,
    pub degraded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema: String,
    pub run_id: String,
    pub status: ScanStatus,
    pub conclusion: String,
    pub target_kind: TargetKind,
    pub target: String,
    pub scanner_version: String,
    pub ark_version: String,
    pub ark_categories: Vec<String>,
    pub ark_max_level: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub ark_category_levels: std::collections::BTreeMap<String, String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub coverage: Coverage,
    pub findings: Vec<Finding>,
    pub skipped: Vec<SkippedSummary>,
    pub failures: Vec<FailureRecord>,
    pub report_path: String,
    pub scope_disclaimer: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedSummary {
    pub reason: String,
    pub count: usize,
}

pub struct ReportBuilder {
    pub findings: Vec<Finding>,
    seen_findings: HashSet<String>,
    pub failures: Vec<FailureRecord>,
    pub classification_count: usize,
    pub chunk_count: usize,
    pub degraded: bool,
}

struct ProjectedFinding<'a> {
    label: &'a str,
    start: usize,
    end: usize,
    line_start: usize,
    line_end: usize,
    confidence: f64,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            seen_findings: HashSet::new(),
            failures: Vec::new(),
            classification_count: 0,
            chunk_count: 0,
            degraded: false,
        }
    }

    pub fn classification(&mut self, classification: &FinalClassification, chunk: &ChunkRecord) {
        self.classification_count += 1;
        if !classification.matched {
            return;
        }
        if classification.evidence.is_empty() {
            self.push_finding(
                classification,
                ProjectedFinding {
                    label: &classification.label,
                    start: chunk.original_byte_start,
                    end: chunk.original_byte_end,
                    line_start: chunk.line_start,
                    line_end: chunk.line_end,
                    confidence: classification.confidence,
                },
            );
            return;
        }
        for evidence in &classification.evidence {
            self.push_finding(
                classification,
                ProjectedFinding {
                    label: &evidence.label,
                    start: chunk.original_byte_start + evidence.start,
                    end: chunk.original_byte_start + evidence.end,
                    line_start: chunk.line_start + evidence.line_start.saturating_sub(1),
                    line_end: chunk.line_start + evidence.line_end.saturating_sub(1),
                    confidence: evidence.confidence,
                },
            );
        }
    }

    fn push_finding(&mut self, classification: &FinalClassification, span: ProjectedFinding<'_>) {
        let key = format!(
            "{}\0{}\0{}\0{}\0{}",
            classification.path, classification.category, span.label, span.start, span.end
        );
        if !self.seen_findings.insert(key.clone()) {
            return;
        }
        self.findings.push(Finding {
            finding_id: hash(key.as_bytes()),
            path: classification.path.clone(),
            category: classification.category.clone(),
            label: span.label.to_owned(),
            confidence: span.confidence,
            level: classification.level.clone(),
            source: classification.source.clone(),
            line_start: span.line_start,
            line_end: span.line_end,
            original_byte_start: span.start,
            original_byte_end: span.end,
        });
    }

    pub fn failure(
        &mut self,
        run_id: &str,
        path: Option<&str>,
        chunk_id: Option<&str>,
        category: Option<&str>,
        kind: &str,
        message: impl Into<String>,
    ) {
        self.failures.push(FailureRecord {
            schema: "patronus.security-scanner.failure.v1".into(),
            run_id: run_id.into(),
            path: path.map(str::to_owned),
            chunk_id: chunk_id.map(str::to_owned),
            category: category.map(str::to_owned),
            kind: kind.into(),
            message: sanitize(&message.into(), 1024),
        });
    }
}

impl Default for ReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_report(
    run_id: String,
    target_kind: TargetKind,
    target: String,
    started_at: DateTime<Utc>,
    duration_ms: u64,
    files: &[FileRecord],
    eligible_files: usize,
    eligible_bytes: u64,
    analyzed_files: usize,
    analyzed_bytes: u64,
    categories: Vec<String>,
    level: String,
    mut builder: ReportBuilder,
    report_path: String,
) -> Report {
    builder.findings.sort_by(|a, b| {
        (&a.path, a.line_start, &a.category, &a.finding_id).cmp(&(
            &b.path,
            b.line_start,
            &b.category,
            &b.finding_id,
        ))
    });
    let skipped_files = files.iter().filter(|file| !file.eligible).count();
    let mut grouped = std::collections::BTreeMap::new();
    for file in files.iter().filter(|file| !file.eligible) {
        *grouped
            .entry(file.skip_reason.clone().unwrap_or_else(|| "unknown".into()))
            .or_insert(0) += 1;
    }
    let incomplete = skipped_files > 0
        || !builder.failures.is_empty()
        || builder.degraded
        || analyzed_files < eligible_files;
    let status = if incomplete {
        ScanStatus::Incomplete
    } else if builder.findings.is_empty() {
        ScanStatus::Clean
    } else {
        ScanStatus::Findings
    };
    let conclusion = match status {
        ScanStatus::Clean => {
            "Ark found no supported signals in all eligible analyzed content.".into()
        }
        ScanStatus::Findings => format!(
            "Ark found {} supported signal(s); review the findings.",
            builder.findings.len()
        ),
        ScanStatus::Incomplete => {
            "Coverage is incomplete; no clean conclusion is possible. Findings may also be present."
                .into()
        }
        ScanStatus::Failed => "No valid completed report could be produced.".into(),
    };
    Report {
        schema: "patronus.security-scanner.report.v1".into(),
        run_id,
        status,
        conclusion,
        target_kind,
        target,
        scanner_version: crate::VERSION.into(),
        ark_version: crate::ARK_VERSION.into(),
        ark_categories: categories,
        ark_max_level: level,
        ark_category_levels: Default::default(),
        started_at,
        completed_at: Utc::now(),
        duration_ms,
        coverage: Coverage {
            discovered_files: files.len(),
            eligible_files,
            analyzed_files,
            skipped_files,
            eligible_bytes,
            analyzed_bytes,
            chunks: builder.chunk_count,
            classifications: builder.classification_count,
            failures: builder.failures.len(),
            degraded: builder.degraded,
        },
        findings: builder.findings,
        skipped: grouped
            .into_iter()
            .map(|(reason, count)| SkippedSummary { reason, count })
            .collect(),
        failures: builder.failures,
        report_path,
        scope_disclaimer: [
            "SQL injection",
            "SSRF",
            "remote code execution",
            "authorization bugs",
            "insecure cryptography",
            "vulnerable dependencies or CVEs",
            "business-logic flaws",
            "malicious runtime behavior",
        ]
        .map(str::to_owned)
        .to_vec(),
    }
}

pub fn exit_code(status: ScanStatus, fail_on: FailOn) -> i32 {
    match (status, fail_on) {
        (_, FailOn::Never) => 0,
        (ScanStatus::Findings, FailOn::Findings) => 1,
        (ScanStatus::Incomplete, FailOn::Incomplete) => 3,
        (ScanStatus::Failed, _) => 4,
        _ => 0,
    }
}

pub fn markdown(report: &Report) -> String {
    let mut output = format!(
        "# Patronus Security Scanner Report\n\n## {:?}\n\n{}\n\n",
        report.status,
        escape_markdown(&report.conclusion)
    );
    output.push_str("## Scope\n\n");
    output.push_str(&format!(
        "- Scanner: `{}`\n- Ark: `{}` ({}, {})\n- Started: `{}`\n- Duration: `{:.2}s`\n\n",
        report.scanner_version,
        report.ark_version,
        report.ark_max_level,
        report.ark_categories.join(", "),
        report.started_at.to_rfc3339(),
        report.duration_ms as f64 / 1000.0
    ));
    output.push_str("## Coverage\n\n| Metric | Value |\n|---|---:|\n");
    output.push_str(&format!("| Eligible bytes | {} |\n| Analyzed bytes | {} |\n| Eligible files | {} |\n| Analyzed files | {} |\n| Skipped files | {} |\n| Chunks | {} |\n| Classifier failures | {} |\n\n", report.coverage.eligible_bytes, report.coverage.analyzed_bytes, report.coverage.eligible_files, report.coverage.analyzed_files, report.coverage.skipped_files, report.coverage.chunks, report.coverage.failures));
    if report.status == ScanStatus::Incomplete {
        output.push_str("> **Incomplete coverage:** skipped, failed, or degraded content prevents a clean conclusion.\n\n");
    }
    output.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        output.push_str("No supported signals were projected from completed classifications.\n\n");
    }
    for finding in &report.findings {
        output.push_str(&format!(
            "- `{}` lines {}–{}: **{}** / `{}` (confidence {:.3}, {}, {})\n",
            escape_markdown(&finding.path),
            finding.line_start,
            finding.line_end,
            escape_markdown(&finding.category),
            escape_markdown(&finding.label),
            finding.confidence,
            escape_markdown(&finding.level),
            escape_markdown(&finding.source)
        ));
    }
    output.push_str("\n## Skipped content\n\n");
    if report.skipped.is_empty() {
        output.push_str("None.\n");
    }
    for skipped in &report.skipped {
        output.push_str(&format!(
            "- {}: {}\n",
            escape_markdown(&skipped.reason),
            skipped.count
        ));
    }
    output.push_str("\n## Scope disclaimer\n\nThis scanner reports only supported Ark signal classes. It does not establish the absence of:\n\n");
    for item in &report.scope_disclaimer {
        output.push_str(&format!("- {}\n", escape_markdown(item)));
    }
    output.push_str(&format!(
        "\nArtifacts: `{}`\n",
        escape_markdown(&report.report_path)
    ));
    output
}

pub fn terminal_summary(report: &Report) -> String {
    let status = format!("{:?}", report.status).to_ascii_uppercase();
    let first = match report.status {
        ScanStatus::Clean => format!("{status} — no supported signals found"),
        ScanStatus::Findings => format!(
            "{status} — {} findings in {} files",
            report.findings.len(),
            report
                .findings
                .iter()
                .map(|f| &f.path)
                .collect::<HashSet<_>>()
                .len()
        ),
        ScanStatus::Incomplete => format!(
            "{status} — coverage is incomplete; {} findings also present",
            report.findings.len()
        ),
        ScanStatus::Failed => format!("{status} — no valid completed report"),
    };
    format!("{first}\nScanned {:.1} MB across {}/{} eligible files in {:.2}s\nCoverage: {} skipped, {} failures{}\nReport: {}", report.coverage.analyzed_bytes as f64 / 1_000_000.0, report.coverage.analyzed_files, report.coverage.eligible_files, report.duration_ms as f64 / 1000.0, report.coverage.skipped_files, report.coverage.failures, if report.coverage.degraded { ", Ark degraded" } else { "" }, report.report_path)
}

fn sanitize(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
        .take(max)
        .collect()
}

fn escape_markdown(value: &str) -> String {
    sanitize(value, 4096)
        .replace('`', "\\`")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
