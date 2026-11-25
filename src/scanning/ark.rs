use std::collections::HashMap;
use std::time::Duration;

use patronus_ark::{
    GatewayConfig, L3Strategy, QueuedSecurityEvent, ScanRequest, ScanRequestOptions,
    SecurityGateway, SecurityRequestCompletion,
};
use patronus_ark_core::cascade::{ScanGateMatrix, SecurityLevel};
use patronus_ark_core::warmup::DownloadPolicy;
use patronus_ark_core::SecurityCategory;
use serde::{Deserialize, Serialize};

use crate::config::{ark_categories, ArkConfig};
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
    policies: HashMap<String, (String, ScanGateMatrix)>,
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
        let mut groups: HashMap<String, Vec<SecurityCategory>> = HashMap::new();
        let mut policies = HashMap::new();
        for category in &config.categories {
            let normalized = normalize_category(category);
            let level = policy.level(&normalized, config).to_owned();
            // A gateway refuses duplicate categories; `prompt_injection` and
            // `threat` share Ark's `injection` class.
            let classes = ark_categories(category).map_err(ScannerError::Ark)?;
            for (group, ark_classes) in [
                (level.as_str(), classes.primary),
                (L1_ONLY, classes.l1_only),
            ] {
                if ark_classes.is_empty() {
                    continue;
                }
                let group = groups.entry(group.to_owned()).or_default();
                for ark in ark_classes {
                    if !group.contains(ark) {
                        group.push(*ark);
                    }
                }
            }
            let gates = ScanGateMatrix {
                l1: policy.l1.get(&normalized).copied(),
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
                ..Default::default()
            };
            policies.insert(normalized, (level, gates));
        }
        let mut gateways = HashMap::new();
        for (level, categories) in groups {
            let mut gateway_config = GatewayConfig::new(categories, parse_level(&level)?);
            gateway_config.core.cache_root = config.model_dir.clone();
            gateway_config.core.download = if config.download_files {
                DownloadPolicy::Missing
            } else {
                DownloadPolicy::Never
            };
            // Ark 0.1.18 dropped its default input limits; keep the 0.1.16 ones.
            gateway_config.core.max_input_bytes = Some(ARK_MAX_INPUT_BYTES);
            gateway_config.core.max_findings = Some(ARK_MAX_FINDINGS);
            // Reuse the desktop's installed shared L3 model when available.
            // Apply the same strategy for readiness, preparation and scanning.
            if config
                .model_dir
                .as_ref()
                .is_some_and(|dir| unified_l3_assets_present(dir))
            {
                gateway_config.l3_strategy = L3Strategy::Multi;
            }
            let gateway = SecurityGateway::new(gateway_config).map_err(ScannerError::Ark)?;
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
        let normalized = normalize_category(category);
        let (level, gates) = self
            .policies
            .get(&normalized)
            .ok_or_else(|| ScannerError::Ark("category is not enabled".into()))?;
        let classes = ark_categories(category).map_err(ScannerError::Ark)?;
        // The L1-only classes share the request when the category runs at L1.
        let mut requests = Vec::new();
        if level == L1_ONLY || classes.l1_only.is_empty() {
            let mut all = classes.primary.to_vec();
            for class in classes.l1_only {
                if !all.contains(class) {
                    all.push(*class);
                }
            }
            requests.push((level.as_str(), all));
        } else {
            requests.push((level.as_str(), classes.primary.to_vec()));
            requests.push((L1_ONLY, classes.l1_only.to_vec()));
        }
        let mut pending = Vec::new();
        for (level, categories) in requests {
            let gateway = &self.gateways[level];
            let request_id = gateway
                .enqueue(ScanRequest {
                    categories: Some(categories),
                    options: ScanRequestOptions {
                        gates: Some(gates.clone()),
                        ..Default::default()
                    },
                    ..ScanRequest::new(input.content)
                })
                .map_err(ScannerError::Ark)?;
            pending.push((gateway, request_id));
        }
        // Each Ark class keeps its own authoritative (deepest) result.
        let mut by_class: HashMap<String, patronus_ark::SecurityScanResult> = HashMap::new();
        let mut failures = Vec::new();
        let mut degraded = false;
        for (gateway, request_id) in pending {
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
                    QueuedSecurityEvent::Result(queued) => {
                        let result = queued.result;
                        match by_class.get(&result.category) {
                            Some(current) if !authoritative_over(&result, current) => {}
                            _ => {
                                by_class.insert(result.category.clone(), result);
                            }
                        }
                    }
                    QueuedSecurityEvent::Progress(_) | QueuedSecurityEvent::Provisional(_) => {}
                    QueuedSecurityEvent::Finished { completion, .. } => break completion,
                }
            };
            let (request_failures, request_degraded) = completion_failures(completion);
            failures.extend(request_failures);
            degraded |= request_degraded;
        }
        let mut classifications = Vec::new();
        if by_class.is_empty() {
            failures.push(format!(
                "missing terminal classification for category {category}"
            ));
        } else {
            // Across classes the strongest detection decides our category; the
            // evidence of every matching class is kept.
            let class_results: Vec<_> = by_class.into_values().collect();
            let matching: Vec<_> = class_results
                .iter()
                .filter(|result| !is_benign(&authoritative_result(result).0))
                .collect();
            let result = class_results
                .iter()
                .max_by(|left, right| {
                    let (left_label, left_confidence, _) = authoritative_result(left);
                    let (right_label, right_confidence, _) = authoritative_result(right);
                    (!is_benign(&left_label), level_rank(&left.level))
                        .cmp(&(!is_benign(&right_label), level_rank(&right.level)))
                        .then_with(|| left_confidence.total_cmp(&right_confidence))
                        .then_with(|| left.model.cmp(&right.model))
                })
                .expect("non-empty class results");
            let mut evidence: Vec<Evidence> = matching
                .iter()
                .flat_map(|result| result.evidence_spans.iter())
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
            evidence.sort_by(|a, b| (a.start, a.end, &a.label).cmp(&(b.start, b.end, &b.label)));
            evidence.dedup_by(|a, b| (a.start, a.end, &a.label) == (b.start, b.end, &b.label));
            let (label, confidence, source) = authoritative_result(result);
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
                duration_ms: class_results
                    .iter()
                    .map(|result| result.duration_ms)
                    .fold(0.0, f64::max)
                    .round() as u64,
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

/// Within one Ark class the deepest layer is authoritative, then a detection,
/// then a result with a decision, then confidence (Ark 0.1.18 semantics).
fn authoritative_over(
    candidate: &patronus_ark::SecurityScanResult,
    current: &patronus_ark::SecurityScanResult,
) -> bool {
    let (candidate_label, candidate_confidence, _) = authoritative_result(candidate);
    let (current_label, current_confidence, _) = authoritative_result(current);
    (
        level_rank(&candidate.level),
        !is_benign(&candidate_label),
        candidate.decision.is_some(),
    )
        .cmp(&(
            level_rank(&current.level),
            !is_benign(&current_label),
            current.decision.is_some(),
        ))
        .then_with(|| candidate_confidence.total_cmp(&current_confidence))
        .then_with(|| candidate.model.cmp(&current.model))
        .is_gt()
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

/// The gateway that scans a category's L1-only Ark classes.
const L1_ONLY: &str = "l1";
const ARK_MAX_INPUT_BYTES: usize = 1024 * 1024;
const ARK_MAX_FINDINGS: usize = 10_000;

/// Whether the shared (multi-head) L3 bundle is installed below `model_dir`.
fn unified_l3_assets_present(model_dir: &std::path::Path) -> bool {
    let asset = patronus_ark::assets::UNIFIED_L3_ASSET;
    let bundle = asset.spec.cache_dir(model_dir);
    asset
        .selected_files()
        .iter()
        .all(|file| bundle.join(file).is_file())
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
            "provenance": {"ark_version": "0.1.18", "schema_version": "1", "model": "fixture"}
        })).unwrap();
        let result = patronus_ark::SecurityScanResult {
            native: patronus_ark_core::NativeResult {
                category: "injection".into(),
                class_name: "injection".into(),
                confidence: 0.97,
                level: "L2".into(),
                model: "raw-model".into(),
                duration_ms: 0.0,
                layers: vec![],
                evidence_spans: vec![],
                label_scores: vec![],
                decision: Some(decision),
            },
            internal_l2_chunk_outputs: vec![],
            module_decision: None,
        };
        assert_eq!(
            authoritative_result(&result),
            ("benign".into(), 0.0, "default".into())
        );
    }
}
