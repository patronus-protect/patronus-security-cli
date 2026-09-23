use std::collections::HashMap;
use std::time::Duration;

use patronus_ark::{
    QueuedSecurityEvent, SecurityGateway, SecurityLevel, SecurityRequestCompletion,
};
use serde::{Deserialize, Serialize};

use crate::config::{ark_category, ArkConfig};
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
    fn analyze_local(&self, input: ChunkInput<'_>, scope: Option<&str>) -> Result<AnalysisOutcome> {
        match scope {
            Some(scope) => self.analyze_scoped(input, scope),
            None => self.analyze(input),
        }
    }
}

pub struct ArkAnalyzer {
    gateways: HashMap<String, SecurityGateway>,
    policies: HashMap<String, (String, patronus_ark::ScanGateMatrix)>,
    user_prompt_pii: bool,
    requested: Vec<String>,
    include_evidence_text: bool,
}

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
        policy.validate(config).map_err(ScannerError::Ark)?;
        let mut groups: HashMap<String, Vec<patronus_ark::SecurityCategory>> = HashMap::new();
        let mut policies = HashMap::new();
        for category in &config.categories {
            let normalized = normalize_category(category);
            let level = policy.level(&normalized, config).to_owned();
            groups
                .entry(level.clone())
                .or_default()
                .push(ark_category(category).map_err(ScannerError::Ark)?);
            let gates = patronus_ark::ScanGateMatrix {
                l1: policy.l1.get(&normalized).copied(),
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
                ..Default::default()
            };
            policies.insert(normalized, (level, gates));
        }
        let mut gateways = HashMap::new();
        for (level, categories) in groups {
            let gateway = SecurityGateway::with_max_level(
                categories,
                parse_level(&level)?,
                config.model_dir.clone(),
                config.download_files,
            );
            // Reuse the desktop's installed shared L3 model when available.
            // Apply the same strategy for readiness, preparation and scanning.
            if config
                .model_dir
                .as_ref()
                .is_some_and(|dir| patronus_ark::assets::unified_l3_assets_present(dir))
            {
                gateway.set_l3_strategy(patronus_ark::L3Strategy::Multi);
            }
            gateway.set_queue_worker_count(config.queue_capacity);
            gateways.insert(level, gateway);
        }
        Ok(Self {
            gateways,
            policies,
            user_prompt_pii: policy.user_prompt_pii,
            requested: config.categories.clone(),
            include_evidence_text,
        })
    }

    pub fn prepare_assets(config: &ArkConfig) -> Result<()> {
        Self::prepare_policy_assets(config, &crate::analysis_config::AnalysisConfig::default())
    }

    /// Inspect required assets without enabling downloads or loading model sessions.
    pub fn policy_assets_ready(
        config: &ArkConfig,
        policy: &crate::analysis_config::AnalysisConfig,
    ) -> Result<bool> {
        let mut local = config.clone();
        local.download_files = false;
        let analyzer = Self::with_policy(&local, policy, false)?;
        let mut ready = true;
        for gateway in analyzer.gateways.values() {
            let readiness = gateway.asset_readiness();
            for level in [readiness.l2, readiness.l3] {
                if let patronus_ark::SecurityLevelReadiness::NotReady { failures } = level {
                    for failure in failures {
                        if failure.kind != patronus_ark::SecurityFailureKind::MissingAsset {
                            return Err(ScannerError::Ark(format!(
                                "Local model validation failed; no download started: {failure}"
                            )));
                        }
                        eprintln!("{failure}");
                    }
                    ready = false;
                }
            }
        }
        Ok(ready)
    }

    pub fn prepare_policy_assets(
        config: &ArkConfig,
        policy: &crate::analysis_config::AnalysisConfig,
    ) -> Result<()> {
        let mut downloadable = config.clone();
        downloadable.download_files = true;
        let analyzer = Self::with_policy(&downloadable, policy, false)?;
        for gateway in analyzer.gateways.values() {
            let readiness = gateway.asset_readiness();
            if !matches!(
                readiness.l2,
                patronus_ark::SecurityLevelReadiness::NotReady { .. }
            ) && !matches!(
                readiness.l3,
                patronus_ark::SecurityLevelReadiness::NotReady { .. }
            ) {
                continue;
            }
            gateway
                .prepare_assets()
                .map_err(|error| ScannerError::Ark(error.to_string()))?;
        }
        Ok(())
    }
}

impl ContentAnalyzer for ArkAnalyzer {
    fn prepare(&mut self) -> Result<()> {
        for gateway in self.gateways.values_mut() {
            gateway
                .warmup()
                .map_err(|error| ScannerError::Ark(error.to_string()))?;
        }
        Ok(())
    }

    fn analyze(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        self.analyze_categories(input, &self.requested)
    }

    fn analyze_user_prompt(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        let requested: Vec<_> = self
            .requested
            .iter()
            .filter(|category| self.user_prompt_pii || *category != "pii")
            .cloned()
            .collect();
        self.analyze_categories(input, &requested)
    }
}

impl ArkAnalyzer {
    fn analyze_categories(
        &self,
        input: ChunkInput<'_>,
        requested: &[String],
    ) -> Result<AnalysisOutcome> {
        if requested.is_empty() {
            return Err(ScannerError::Ark(
                "no scan categories enabled for this input".into(),
            ));
        }
        let mut combined = AnalysisOutcome {
            classifications: Vec::new(),
            failures: Vec::new(),
            degraded: false,
            notice: None,
        };
        for category in requested {
            let outcome = self.analyze_category(input.clone(), category)?;
            combined.classifications.extend(outcome.classifications);
            combined.failures.extend(outcome.failures);
            combined.degraded |= outcome.degraded;
        }
        Ok(combined)
    }

    fn analyze_category(
        &self,
        input: ChunkInput<'_>,
        category: &String,
    ) -> Result<AnalysisOutcome> {
        let requested = std::slice::from_ref(category);
        let (level, gates) = self
            .policies
            .get(&normalize_category(category))
            .ok_or_else(|| ScannerError::Ark("category is not enabled".into()))?;
        let gateway = &self.gateways[level];
        let categories = requested
            .iter()
            .map(|category| ark_category(category).map_err(ScannerError::Ark))
            .collect::<Result<Vec<_>>>()?;
        if categories.is_empty() {
            return Err(ScannerError::Ark(
                "no scan categories enabled for this input".into(),
            ));
        }
        let request_id =
            gateway.enqueue_categories(categories, input.content.to_owned(), Some(gates.clone()));
        let mut results: HashMap<String, Vec<patronus_ark::SecurityScanResult>> = HashMap::new();
        let completion = loop {
            let event = gateway
                .consume_next_event(Some(Duration::from_secs(30)))
                .ok_or_else(|| {
                    ScannerError::Ark(format!("timed out waiting for request {request_id}"))
                })?;
            if event.request_id() != request_id {
                continue;
            }
            match event {
                QueuedSecurityEvent::Result(queued) => results
                    .entry(normalize_category(&queued.result.category))
                    .or_default()
                    .push(queued.result),
                QueuedSecurityEvent::Progress(_) | QueuedSecurityEvent::Provisional(_) => {}
                QueuedSecurityEvent::Finished { completion, .. } => break completion,
            }
        };
        let (mut failures, degraded) = completion_failures(completion);
        let mut classifications = Vec::new();
        for requested in requested {
            let normalized = normalize_category(requested);
            let Some(candidates) = results.remove(&normalized) else {
                failures.push(format!(
                    "missing terminal classification for category {requested}"
                ));
                continue;
            };
            let result = candidates
                .into_iter()
                .max_by(|left, right| {
                    let (left_label, left_confidence, _) = authoritative_result(left);
                    let (right_label, right_confidence, _) = authoritative_result(right);
                    (
                        level_rank(&left.level),
                        !is_benign(&left_label),
                        left.decision.is_some(),
                    )
                        .cmp(&(
                            level_rank(&right.level),
                            !is_benign(&right_label),
                            right.decision.is_some(),
                        ))
                        .then_with(|| left_confidence.total_cmp(&right_confidence))
                        .then_with(|| left.model.cmp(&right.model))
                })
                .expect("non-empty candidates");
            let mut evidence: Vec<Evidence> = result
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
                    text: self.include_evidence_text.then(|| span.text.clone()),
                })
                .collect();
            let (label, confidence, source) = authoritative_result(&result);
            let decision = result
                .decision
                .as_ref()
                .and_then(|value| serde_json::to_value(value).ok());
            let matched = !is_benign(&label);
            if !matched {
                evidence.clear();
            }
            classifications.push(FinalClassification {
                schema: "patronus.security-scanner.classification.v1",
                run_id: input.run_id.into(),
                chunk_id: input.chunk_id.into(),
                file_id: input.file_id.into(),
                path: input.path.into(),
                category: normalized,
                source,
                level: result.level.to_ascii_lowercase(),
                terminal: true,
                matched,
                label,
                confidence,
                decision,
                evidence,
                duration_ms: result.duration_ms.max(0.0).round() as u64,
                warnings: Vec::new(),
            });
        }
        Ok(AnalysisOutcome {
            classifications,
            failures,
            degraded,
            notice: None,
        })
    }
}

fn authoritative_result(result: &patronus_ark::SecurityScanResult) -> (String, f64, String) {
    result
        .decision
        .as_ref()
        .map(|decision| {
            let final_result = &decision.final_result;
            (
                final_result.class_name.clone(),
                final_result.confidence.clamp(0.0, 1.0),
                final_result.source.clone(),
            )
        })
        .unwrap_or_else(|| {
            (
                result.class_name.clone(),
                result.confidence.clamp(0.0, 1.0),
                result.model.clone(),
            )
        })
}

fn parse_level(value: &str) -> Result<SecurityLevel> {
    match value {
        "l1" => Ok(SecurityLevel::L1),
        "l2" => Ok(SecurityLevel::L2),
        "l3" => Ok(SecurityLevel::L3),
        other => Err(ScannerError::Ark(format!("unsupported level {other}"))),
    }
}

fn normalize_category(category: &str) -> String {
    match category {
        "injection" | "prompt-injection" => "prompt_injection".into(),
        other => other.replace('-', "_"),
    }
}

fn level_rank(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "l3" => 3,
        "l2" => 2,
        _ => 1,
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

fn completion_failures(completion: SecurityRequestCompletion) -> (Vec<String>, bool) {
    match completion {
        SecurityRequestCompletion::Complete => (Vec::new(), false),
        SecurityRequestCompletion::Degraded { failures } => (
            failures
                .into_iter()
                .map(|failure| failure.to_string())
                .collect(),
            true,
        ),
        SecurityRequestCompletion::Failed { failures } => (
            failures
                .into_iter()
                .map(|failure| failure.to_string())
                .collect(),
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decision_final_result_overrides_raw_classifier_fields() {
        let decision = serde_json::from_value(json!({
            "schema_version": "1",
            "final_result": {"class_name": "benign", "confidence": 0.0, "source": "default"},
            "decision_candidate": {
                "source": "l2", "class_name": "injection", "confidence": 0.97,
                "acceptance_threshold": 0.99, "accepted": false, "evidence": null
            },
            "recommendation": {"accepted": false, "final_arbitration": "default", "operating_point": "best_f1", "acceptance_threshold": 0.99},
            "candidates": [],
            "terminality": {"completion": "complete", "degraded": false, "degradation_reason": null},
            "provenance": {"ark_version": "0.1.8", "schema_version": "1", "model": "fixture"}
        })).unwrap();
        let result = patronus_ark::SecurityScanResult {
            category: "injection".into(),
            class_name: "injection".into(),
            confidence: 0.97,
            level: "L2".into(),
            model: "raw-model".into(),
            duration_ms: 0.0,
            layers: vec![],
            internal_l2_chunk_outputs: vec![],
            evidence_spans: vec![],
            label_scores: vec![],
            decision: Some(decision),
        };
        assert_eq!(
            authoritative_result(&result),
            ("benign".into(), 0.0, "default".into())
        );
    }
}
