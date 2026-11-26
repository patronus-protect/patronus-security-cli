use std::cell::RefCell;

use patronus_ark_core::cascade::{
    ModuleDecision, ScanGateMatrix, SecurityLevel, Stage, StageOutcome,
};
use patronus_ark_core::warmup::DownloadPolicy;
use patronus_ark_core::wolf::{WolfConfig, WolfModel};
use patronus_ark_core::{NativeResult, ScanReport, Scanner, ScannerConfig, SecurityCategory};
use serde::{Deserialize, Serialize};

use crate::config::{scan_category, ArkConfig};
use crate::error::{Result, ScannerError};

#[derive(Debug, Clone, Serialize)]
pub struct FinalClassification {
    pub schema: &'static str,
    pub run_id: String,
    pub chunk_id: String,
    pub file_id: String,
    pub path: String,
    pub category: String,
    pub source: String,
    pub level: String,
    pub terminal: bool,
    pub matched: bool,
    pub label: String,
    pub confidence: f64,
    pub decision: Option<serde_json::Value>,
    pub evidence: Vec<Evidence>,
    pub duration_ms: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub confidence: f64,
    pub line_start: usize,
    pub line_end: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChunkInput<'a> {
    pub run_id: &'a str,
    pub chunk_id: &'a str,
    pub file_id: &'a str,
    pub path: &'a str,
    pub content: &'a str,
    /// Total tokens across the original runtime result, before chunking.
    pub input_tokens: Option<usize>,
}

#[derive(Debug)]
pub struct AnalysisOutcome {
    pub classifications: Vec<FinalClassification>,
    pub failures: Vec<String>,
    pub degraded: bool,
    /// Set when the scan still completed, but not the way the provider mode intended.
    pub notice: Option<ScanNotice>,
}

/// A fixed, public explanation for how a scan was processed. It never carries
/// backend error text, so it may cross the runtime protocol to agents and users.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanNotice {
    pub code: String,
    /// `local` when the scan completed on this device instead, `none` when it could not.
    pub fallback: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

impl ScanNotice {
    pub fn api_usage_limit(fallback: &str, retry_after: Option<u64>) -> Self {
        Self {
            code: "api_usage_limit".into(),
            fallback: fallback.into(),
            retry_after,
        }
    }

    /// `reason` is one of the fixed `authentication_*` failure codes.
    pub fn api_authentication(reason: &str, fallback: &str) -> Self {
        Self {
            code: format!("api_{reason}"),
            fallback: fallback.into(),
            retry_after: None,
        }
    }
}

pub trait ContentAnalyzer {
    fn prepare(&mut self) -> Result<()>;
    fn analyze(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome>;
    fn analyze_scoped(&self, input: ChunkInput<'_>, scope: &str) -> Result<AnalysisOutcome> {
        if scope.ends_with(".user_input") {
            self.analyze_user_prompt(input)
        } else {
            self.analyze(input)
        }
    }
    fn analyze_user_prompt(&self, _input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        Err(ScannerError::Ark(
            "user prompt scan policy is unsupported".into(),
        ))
    }
    /// Analyze on this device only, never through the API. Redaction refinement
    /// re-scans fragments of text that is already dangerous and must not upload them.
    /// Analyzers without an API route are local already.
    /// Build what scans of `scope` (`<host>.<surface>`) need, so its first scan
    /// does not pay for it. Analyzers without scopes have nothing to build.
    fn prepare_scope(&self, _scope: &str) -> Result<()> {
        Ok(())
    }
    fn analyze_local(&self, input: ChunkInput<'_>, scope: Option<&str>) -> Result<AnalysisOutcome> {
        match scope {
            Some(scope) => self.analyze_scoped(input, scope),
            None => self.analyze(input),
        }
    }
}

/// Ark Core's synchronous scanner: L1 rules and built-in L1 models per
/// category, and Wolf Defender Edge as the L3 of `injection` where the cascade
/// escalates.
pub struct ArkAnalyzer {
    config: ScannerConfig,
    scanner: RefCell<Option<Scanner>>,
    requested: Vec<SecurityCategory>,
    user_prompt_pii: bool,
    include_evidence_text: bool,
}

/// Inputs and evidence beyond these limits fail instead of being truncated.
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_FINDINGS: usize = 10_000;

impl ArkAnalyzer {
    pub fn new(config: &ArkConfig, include_evidence_text: bool) -> Result<Self> {
        Self::with_policy(
            config,
            &crate::analysis_config::AnalysisConfig::default(),
            include_evidence_text,
        )
    }

    pub fn with_policy(
        config: &ArkConfig,
        policy: &crate::analysis_config::AnalysisConfig,
        include_evidence_text: bool,
    ) -> Result<Self> {
        let scanner = scanner_config(config, policy)?;
        Ok(Self {
            requested: scanner.categories.clone(),
            config: scanner,
            scanner: RefCell::new(None),
            user_prompt_pii: policy.user_prompt_pii,
            include_evidence_text,
        })
    }

    pub fn prepare_assets(config: &ArkConfig) -> Result<()> {
        Self::prepare_policy_assets(config, &crate::analysis_config::AnalysisConfig::default())
    }

    /// Whether the model files the configuration needs (Wolf Edge at L3) are
    /// in place, without downloading or loading them.
    pub fn policy_assets_ready(
        config: &ArkConfig,
        policy: &crate::analysis_config::AnalysisConfig,
    ) -> Result<bool> {
        let scanner = scanner_config(config, policy)?
            .resolved()
            .map_err(|error| ScannerError::Ark(error.to_string()))?;
        let Some(wolf) = &scanner.wolf else {
            return Ok(true);
        };
        let dir = wolf
            .bundle_dir
            .as_deref()
            .ok_or_else(|| ScannerError::Ark("Wolf bundle directory is not resolved".into()))?;
        patronus_ark_core::warmup::wolf_assets_present(dir, wolf.model, wolf.precision).map_err(
            |error| {
                ScannerError::Ark(format!(
                    "Local model validation failed; no download started: {error}"
                ))
            },
        )
    }

    /// Download what the configuration needs (Wolf Edge at L3) and verify it.
    pub fn prepare_policy_assets(
        config: &ArkConfig,
        policy: &crate::analysis_config::AnalysisConfig,
    ) -> Result<()> {
        let mut scanner = scanner_config(config, policy)?;
        scanner.download = DownloadPolicy::Missing;
        patronus_ark_core::warmup::prepare_assets(&scanner)
            .map_err(|error| ScannerError::Ark(error.to_string()))
    }

    fn with_scanner<T>(&self, run: impl FnOnce(&mut Scanner) -> Result<T>) -> Result<T> {
        let mut slot = self.scanner.borrow_mut();
        if slot.is_none() {
            *slot = Some(build_scanner(&self.config)?);
        }
        run(slot.as_mut().expect("scanner was just built"))
    }
}

/// The Ark Core configuration of one analyzer.
fn scanner_config(
    config: &ArkConfig,
    policy: &crate::analysis_config::AnalysisConfig,
) -> Result<ScannerConfig> {
    policy.validate(config).map_err(ScannerError::Ark)?;
    let categories = config
        .categories
        .iter()
        .map(|category| scan_category(category).map_err(ScannerError::Ark))
        .collect::<Result<Vec<_>>>()?;
    let max_level = parse_level(&config.max_level)?;
    let gates = ScanGateMatrix {
        pii_mode: policy.pii_mode,
        dlp_mode: policy.dlp_mode,
        rules: policy
            .l1_rules
            .iter()
            .map(|(id, enabled)| (id.clone(), *enabled))
            .collect(),
        models: policy
            .l1_detectors
            .iter()
            .map(|(name, enabled)| (format!("native:{name}"), *enabled))
            .collect(),
        l1: policy.skip_l1.then_some(false),
        cascade: Some(
            patronus_ark_core::cascade::Cascade::new(policy.cascade_config(&config.categories))
                .map_err(|error| ScannerError::Ark(error.to_string()))?,
        ),
        ..Default::default()
    };
    let wolf = (max_level == SecurityLevel::L3
        && categories.contains(&SecurityCategory::Injection))
    .then(|| WolfConfig {
        model: WolfModel::Edge,
        ..Default::default()
    });
    Ok(ScannerConfig {
        categories,
        max_level,
        gates,
        max_input_bytes: Some(MAX_INPUT_BYTES),
        max_findings: Some(MAX_FINDINGS),
        cache_root: config.model_dir.clone(),
        download: if config.download_files {
            DownloadPolicy::Missing
        } else {
            DownloadPolicy::Never
        },
        wolf,
        ..Default::default()
    })
}

fn build_scanner(config: &ScannerConfig) -> Result<Scanner> {
    let built = if config.download == DownloadPolicy::Missing {
        Scanner::warmup(config.clone())
    } else {
        Scanner::new(config.clone())
    };
    built.map_err(|error| ScannerError::Ark(error.to_string()))
}

impl ContentAnalyzer for ArkAnalyzer {
    fn prepare(&mut self) -> Result<()> {
        self.with_scanner(|_| Ok(()))
    }

    fn analyze(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        self.analyze_categories(input, &self.requested)
    }

    fn analyze_user_prompt(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        let requested: Vec<_> = self
            .requested
            .iter()
            .copied()
            .filter(|category| self.user_prompt_pii || *category != SecurityCategory::Pii)
            .collect();
        self.analyze_categories(input, &requested)
    }
}

impl ArkAnalyzer {
    fn analyze_categories(
        &self,
        input: ChunkInput<'_>,
        requested: &[SecurityCategory],
    ) -> Result<AnalysisOutcome> {
        if requested.is_empty() {
            return Err(ScannerError::Ark(
                "no scan categories enabled for this input".into(),
            ));
        }
        let report = self.with_scanner(|scanner| {
            scanner
                .scan_categories(input.content, requested)
                .map_err(|error| ScannerError::Ark(error.to_string()))
        })?;
        Ok(classify(
            &input,
            requested,
            &report,
            self.include_evidence_text,
        ))
    }
}

/// One classification per requested category from a scan report. With the
/// cascade, the module decision is authoritative: it names the stage that
/// decided (rules, L1 model or Wolf) and whether the category was detected.
fn classify(
    input: &ChunkInput<'_>,
    requested: &[SecurityCategory],
    report: &ScanReport,
    include_evidence_text: bool,
) -> AnalysisOutcome {
    let mut classifications = Vec::new();
    let mut failures = Vec::new();
    for category in requested {
        let name = category.as_str();
        let native = report.native.iter().find(|result| result.category == name);
        let decision = report
            .decision
            .as_ref()
            .and_then(|decisions| decisions.iter().find(|d| d.module == *category));
        let Some(verdict) = verdict(name, native, decision) else {
            failures.push(format!(
                "missing terminal classification for category {name}"
            ));
            continue;
        };
        let mut evidence: Vec<Evidence> = native
            .filter(|_| verdict.matched)
            .map(|result| {
                result
                    .evidence_spans
                    .iter()
                    .map(|span| Evidence {
                        start: span.start_byte,
                        end: span.end_byte,
                        label: span.label.clone(),
                        confidence: span.score.clamp(0.0, 1.0),
                        line_start: line_at(input.content, span.start_byte),
                        line_end: line_at(
                            input.content,
                            if span.end_byte > span.start_byte {
                                span.end_byte - 1
                            } else {
                                span.end_byte
                            },
                        ),
                        text: include_evidence_text.then(|| span.text.clone()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        evidence.sort_by_key(|span| (span.start, span.end));
        let duration_ms = native.map_or(0.0, |result| result.duration_ms)
            + decision.map_or(0.0, |d| {
                d.layers.iter().map(|layer| layer.duration_ms).sum()
            });
        classifications.push(FinalClassification {
            schema: "patronus.security-scanner.classification.v1",
            run_id: input.run_id.into(),
            chunk_id: input.chunk_id.into(),
            file_id: input.file_id.into(),
            path: input.path.into(),
            category: name.into(),
            source: verdict.source,
            level: verdict.level.into(),
            terminal: true,
            matched: verdict.matched,
            label: verdict.label,
            confidence: verdict.confidence,
            decision: decision.and_then(|d| serde_json::to_value(d).ok()),
            evidence,
            duration_ms: duration_ms.max(0.0).round() as u64,
            warnings: Vec::new(),
        });
    }
    AnalysisOutcome {
        classifications,
        failures,
        degraded: false,
        notice: None,
    }
}

struct Verdict {
    matched: bool,
    level: &'static str,
    source: String,
    label: String,
    confidence: f64,
}

fn verdict(
    category: &str,
    native: Option<&NativeResult>,
    decision: Option<&ModuleDecision>,
) -> Option<Verdict> {
    let native_label = native
        .map(|result| result.class_name.clone())
        .filter(|label| !is_benign(label));
    match decision {
        Some(decision) => {
            let matched = decision.outcome == StageOutcome::Detected;
            let (source, confidence) = match decision.decided_by {
                Stage::Heuristic => ("heuristic", decision.score),
                // The L1 model reports its decision logit.
                Stage::L1Model => ("l1_model", 1.0 / (1.0 + (-decision.score).exp())),
                Stage::Policy => ("policy", decision.score),
                Stage::L2 => ("l2", decision.score),
                Stage::L3 => ("wolf", decision.score),
            };
            Some(Verdict {
                matched,
                level: if decision.decided_by == Stage::L3 {
                    "l3"
                } else {
                    "l1"
                },
                source: source.into(),
                label: if matched {
                    native_label.unwrap_or_else(|| category.into())
                } else {
                    "safe".into()
                },
                confidence: confidence.clamp(0.0, 1.0),
            })
        }
        None => native.map(|result| Verdict {
            matched: native_label.is_some(),
            level: "l1",
            source: result.model.clone(),
            label: result.class_name.clone(),
            confidence: result.confidence.clamp(0.0, 1.0),
        }),
    }
}

fn parse_level(value: &str) -> Result<SecurityLevel> {
    match value {
        "l1" => Ok(SecurityLevel::L1),
        "l3" => Ok(SecurityLevel::L3),
        other => Err(ScannerError::Ark(format!(
            "unsupported level {other}; use l1 or l3"
        ))),
    }
}

pub(crate) fn is_benign(label: &str) -> bool {
    matches!(
        label.to_ascii_lowercase().as_str(),
        "benign"
            | "clean"
            | "safe"
            | "allow"
            | "no_match"
            | "none"
            | "non_injection"
            | "not_pii"
            | "not_dlp"
    )
}

fn line_at(text: &str, byte_offset: usize) -> usize {
    let mut offset = byte_offset.min(text.len());
    while offset > 0 && !text.is_char_boundary(offset) {
        offset -= 1;
    }
    1 + text.as_bytes()[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use patronus_ark_core::EvidenceSpan;

    fn input(content: &str) -> ChunkInput<'_> {
        ChunkInput {
            run_id: "run",
            chunk_id: "chunk",
            file_id: "file",
            path: "path",
            content,
            input_tokens: None,
        }
    }

    fn native(category: &str, class_name: &str, spans: Vec<EvidenceSpan>) -> NativeResult {
        NativeResult {
            category: category.into(),
            class_name: class_name.into(),
            confidence: 0.4,
            level: "L1".into(),
            model: "native:fixture".into(),
            duration_ms: 1.0,
            layers: vec![],
            evidence_spans: spans,
            label_scores: vec![],
            decision: None,
        }
    }

    fn span() -> EvidenceSpan {
        serde_json::from_value(serde_json::json!({
            "label": "rule", "text": "ignore", "score": 0.9,
            "start_byte": 0, "end_byte": 6, "start_char": 0, "end_char": 6
        }))
        .unwrap()
    }

    fn decision(
        module: SecurityCategory,
        outcome: StageOutcome,
        by: Stage,
        score: f64,
    ) -> ModuleDecision {
        ModuleDecision {
            module,
            outcome,
            decided_by: by,
            score,
            layers: vec![],
        }
    }

    fn report(native: Vec<NativeResult>, decisions: Vec<ModuleDecision>) -> ScanReport {
        ScanReport {
            input_bytes: 6,
            native,
            wolf: None,
            decision: Some(decisions),
        }
    }

    #[test]
    fn wolf_decision_reports_l3_without_rule_evidence() {
        let report = report(
            vec![native("injection", "safe", vec![])],
            vec![decision(
                SecurityCategory::Injection,
                StageOutcome::Detected,
                Stage::L3,
                0.93,
            )],
        );
        let outcome = classify(
            &input("ignore"),
            &[SecurityCategory::Injection],
            &report,
            false,
        );
        let result = &outcome.classifications[0];
        assert_eq!(
            (
                result.category.as_str(),
                result.level.as_str(),
                result.source.as_str()
            ),
            ("injection", "l3", "wolf")
        );
        assert!(result.matched);
        assert_eq!(result.label, "injection");
        assert!(result.evidence.is_empty());
        assert_eq!(result.confidence, 0.93);
    }

    #[test]
    fn cascade_clear_overrides_native_spans() {
        let report = report(
            vec![native("jailbreak", "jailbreak", vec![span()])],
            vec![decision(
                SecurityCategory::Jailbreak,
                StageOutcome::Clear,
                Stage::L1Model,
                -4.0,
            )],
        );
        let outcome = classify(
            &input("ignore"),
            &[SecurityCategory::Jailbreak],
            &report,
            false,
        );
        let result = &outcome.classifications[0];
        assert!(!result.matched);
        assert_eq!(
            (
                result.label.as_str(),
                result.source.as_str(),
                result.level.as_str()
            ),
            ("safe", "l1_model", "l1")
        );
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn rule_detection_keeps_its_evidence() {
        let report = report(
            vec![native("injection", "injection", vec![span()])],
            vec![decision(
                SecurityCategory::Injection,
                StageOutcome::Detected,
                Stage::Heuristic,
                0.8,
            )],
        );
        let outcome = classify(
            &input("ignore"),
            &[SecurityCategory::Injection],
            &report,
            true,
        );
        let result = &outcome.classifications[0];
        assert!(result.matched);
        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.evidence[0].text.as_deref(), Some("ignore"));
    }

    #[test]
    fn a_category_without_result_is_a_failure() {
        let report = report(vec![], vec![]);
        let outcome = classify(&input("x"), &[SecurityCategory::Pii], &report, false);
        assert!(outcome.classifications.is_empty());
        assert_eq!(outcome.failures.len(), 1);
    }
}
