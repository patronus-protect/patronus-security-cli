use crate::{
    api_client::authentication_reason,
    ark::{
        AnalysisOutcome, ArkAnalyzer, ChunkInput, ContentAnalyzer, Evidence, FinalClassification,
        ScanNotice,
    },
    config::{Config, ProviderMode},
    error::{Result, ScannerError},
};
use serde_json::{json, Value};

pub fn input_tokens(text: &str) -> usize {
    tiktoken_rs::cl100k_base_singleton()
        .encode_ordinary(text)
        .len()
}

fn local_route(mode: ProviderMode, input: &ChunkInput<'_>, user_prompt: bool) -> bool {
    mode == ProviderMode::Local
        || (mode == ProviderMode::Hybrid
            && (user_prompt
                || input
                    .input_tokens
                    .unwrap_or_else(|| input_tokens(input.content))
                    <= 1024))
}

type ScopedInference = std::collections::BTreeMap<String, (Box<Inference>, Option<Box<Inference>>)>;

pub struct Inference {
    local: std::cell::RefCell<Option<ArkAnalyzer>>,
    local_prepared: std::cell::Cell<bool>,
    config: Config,
    scoped: std::cell::RefCell<ScopedInference>,
}

impl Inference {
    pub fn new(config: &Config) -> Result<Self> {
        Self::with_local_initialization(config, true)
    }

    pub fn new_lazy(config: &Config) -> Result<Self> {
        Self::with_local_initialization(config, false)
    }

    fn with_local_initialization(config: &Config, initialize_local: bool) -> Result<Self> {
        Ok(Self {
            local: std::cell::RefCell::new(
                if initialize_local && config.provider.mode != ProviderMode::Api {
                    Some(ArkAnalyzer::with_policy(
                        &config.ark,
                        &config.analysis,
                        config.output.include_evidence_text,
                    )?)
                } else {
                    None
                },
            ),
            local_prepared: std::cell::Cell::new(false),
            config: config.clone(),
            scoped: Default::default(),
        })
    }

    fn cloud(&self, input: ChunkInput<'_>, user_prompt: bool) -> Result<AnalysisOutcome> {
        let mut classifications = vec![];
        for category in &self.config.ark.categories {
            if user_prompt && category == "pii" && !self.config.analysis.user_prompt_pii {
                continue;
            }
            let canonical = if category == "injection" {
                "prompt_injection"
            } else {
                category
            };
            let api_category = if canonical == "prompt_injection" {
                "injection"
            } else {
                canonical
            };
            let level = self.config.analysis.level(canonical, &self.config.ark);
            let mut gates = json!({"rules":self.config.analysis.l1_rules,
                "models":self.config.analysis.l1_detectors.iter().map(|(k,v)| (format!("native:{k}"), *v)).collect::<std::collections::BTreeMap<_,_>>()});
            if let Some(enabled) = self.config.analysis.l1.get(canonical) {
                gates["l1"] = json!(enabled);
            }
            let request = json!({"text": input.content, "config": {
                "categories": [api_category], "max_level": level.to_uppercase(), "gates":gates
            }});
            let jobs = crate::api_client::submit(&self.config, request, false)?;
            if jobs.len() != 1 {
                return Err(error("Expected one API text result"));
            }
            let job = &jobs[0];
            classifications.push(classification(
                &input,
                canonical,
                api_category,
                job,
                self.config.output.include_evidence_text,
            )?);
        }
        if classifications.is_empty() {
            return Err(error("No categories enabled for this surface"));
        }
        Ok(AnalysisOutcome {
            classifications,
            failures: vec![],
            degraded: false,
            notice: None,
        })
    }
}

impl ContentAnalyzer for Inference {
    fn prepare(&mut self) -> Result<()> {
        if self.local.get_mut().is_some() || self.config.provider.mode == ProviderMode::Local {
            if self.local.get_mut().is_none() {
                *self.local.get_mut() = Some(ArkAnalyzer::with_policy(
                    &self.config.ark,
                    &self.config.analysis,
                    self.config.output.include_evidence_text,
                )?);
            }
            self.local.get_mut().as_mut().unwrap().prepare()?;
            self.local_prepared.set(true);
        }
        Ok(())
    }
    fn analyze(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        self.analyze_text(input)
    }
    fn analyze_user_prompt(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        self.analyze_prompt(input)
    }
    fn analyze_scoped(&self, input: ChunkInput<'_>, scope: &str) -> Result<AnalysisOutcome> {
        let profile = self.scoped_profile(scope)?;
        if local_route(
            self.config.provider.mode,
            &input,
            scope.ends_with(".user_input"),
        ) {
            return self.scoped_scan(input, scope, &profile, true);
        }
        let fallback = input.clone();
        with_api_fallback(
            self.config.provider.mode,
            || self.scoped_scan(input, scope, &profile, false),
            || self.scoped_scan(fallback, scope, &profile, true),
        )
    }
    fn analyze_local(&self, input: ChunkInput<'_>, scope: Option<&str>) -> Result<AnalysisOutcome> {
        match scope {
            Some(scope) => {
                let profile = self.scoped_profile(scope)?;
                self.scoped_scan(input, scope, &profile, true)
            }
            None => self.local(input, false),
        }
    }
}
impl Inference {
    fn scoped_profile(&self, scope: &str) -> Result<crate::plugin_policies::Profile> {
        if !crate::plugin_policies::valid_scope(scope) {
            return Err(error("Invalid plugin policy scope"));
        }
        Ok(self
            .config
            .plugin_policies
            .get(scope)
            .cloned()
            .unwrap_or_else(|| {
                crate::plugin_policies::Profile::current(
                    &self.config,
                    scope.split_once('.').expect("validated scope").1,
                )
            }))
    }

    /// Runs a plugin policy's L1 and model analyzers on one route.
    fn scoped_scan(
        &self,
        input: ChunkInput<'_>,
        scope: &str,
        profile: &crate::plugin_policies::Profile,
        local: bool,
    ) -> Result<AnalysisOutcome> {
        let cache_key = self.scoped_analyzers(scope, profile, local)?;
        let scoped = self.scoped.borrow();
        let (l1, models) = &scoped[&cache_key];
        let scan = |analyzer: &Inference, input| {
            if scope.ends_with(".user_input") {
                analyzer.analyze_user_prompt(input)
            } else {
                analyzer.analyze(input)
            }
        };
        let mut outcome = scan(l1, input.clone())?;
        if let Some(models) = models {
            let assessed = crate::plugin_policies::assess(scan(models, input)?);
            outcome.classifications.extend(assessed.classifications);
            outcome.failures.extend(assessed.failures);
            outcome.degraded |= assessed.degraded;
        }
        Ok(outcome)
    }
}

impl Inference {
    /// Builds, once per scope and route, the L1 and model analyzers for a plugin policy.
    fn scoped_analyzers(
        &self,
        scope: &str,
        profile: &crate::plugin_policies::Profile,
        local: bool,
    ) -> Result<String> {
        let cache_key = format!("{scope}:{local}");
        let mut base = self.config.clone();
        base.provider.mode = if local {
            ProviderMode::Local
        } else {
            ProviderMode::Api
        };
        let mut scoped = self.scoped.borrow_mut();
        if !scoped.contains_key(&cache_key) {
            let mut l1_config = profile.apply(&base);
            l1_config.ark.categories = profile.l1_categories();
            l1_config.analysis.category_levels.clear();
            l1_config.analysis.confidence.clear();
            let mut l1 = Inference::new(&l1_config)?;
            l1.prepare()?;
            let mut model_config = profile.apply(&base);
            model_config
                .ark
                .categories
                .retain(|category| match category.as_str() {
                    "injection" | "prompt_injection" => profile.injection.enabled,
                    "threat" => profile.threat.enabled,
                    _ => false,
                });
            let models = if model_config.ark.categories.is_empty() {
                None
            } else {
                for category in &model_config.ark.categories {
                    model_config.analysis.l1.insert(category.clone(), false);
                }
                let mut models = Inference::new(&model_config)?;
                models.prepare()?;
                Some(Box::new(models))
            };
            scoped.insert(cache_key.clone(), (Box::new(l1), models));
        }
        Ok(cache_key)
    }

    fn local(&self, input: ChunkInput<'_>, user_prompt: bool) -> Result<AnalysisOutcome> {
        let mut local = self.local.borrow_mut();
        if local.is_none() {
            *local = Some(ArkAnalyzer::with_policy(
                &self.config.ark,
                &self.config.analysis,
                self.config.output.include_evidence_text,
            )?);
        }
        let local = local.as_mut().unwrap();
        if !self.local_prepared.get() {
            local.prepare()?;
            self.local_prepared.set(true);
        }
        if user_prompt {
            local.analyze_user_prompt(input)
        } else {
            local.analyze(input)
        }
    }

    fn analyze_text(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        if local_route(self.config.provider.mode, &input, false) {
            self.local(input, false)
        } else {
            let fallback = input.clone();
            with_api_fallback(
                self.config.provider.mode,
                || self.cloud(input, false),
                || self.local(fallback, false),
            )
        }
    }
    fn analyze_prompt(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        if self.config.provider.mode == ProviderMode::Api {
            let fallback = input.clone();
            with_api_fallback(
                self.config.provider.mode,
                || self.cloud(input, true),
                || self.local(fallback, true),
            )
        } else {
            self.local(input, true)
        }
    }
}

/// `Some(retry_after)` when the Patronus API refused work because the plan's usage
/// or rate limit is exhausted; such failures can be retried locally.
pub fn usage_limit_retry_after(error: &ScannerError) -> Option<Option<u64>> {
    match error {
        ScannerError::Api {
            kind: patronus_api_client::ErrorKind::Quota | patronus_api_client::ErrorKind::RateLimit,
            retry_after,
            ..
        } => Some(*retry_after),
        _ => None,
    }
}

/// A fixed public failure code for an analyzer error that has no dedicated
/// notice (usage limit and authentication are handled by the caller). The code
/// names the failing component and never carries backend text.
pub fn scan_failure_reason(error: &ScannerError) -> &'static str {
    match error {
        ScannerError::Api { kind, .. } => match kind {
            patronus_api_client::ErrorKind::Timeout => "api_timeout",
            patronus_api_client::ErrorKind::Transport => "api_unavailable",
            patronus_api_client::ErrorKind::Protocol => "api_invalid_response",
            patronus_api_client::ErrorKind::Validation => "api_request_rejected",
            patronus_api_client::ErrorKind::Authentication => "authentication_rejected",
            patronus_api_client::ErrorKind::Quota | patronus_api_client::ErrorKind::RateLimit => {
                "usage_limit_reached"
            }
        },
        ScannerError::Config { .. } => "configuration_unavailable",
        _ => "local_scanner_error",
    }
}

/// Runs the API scan and falls back to the local scan when the usage limit is
/// exhausted or, in Hybrid mode, when API authentication is missing, expired or
/// rejected. Hybrid already scans locally, so a lost login must not leave large
/// results unscanned. API mode keeps authentication failures: the user chose the API.
/// If the local scan is unavailable too, the API error is kept so callers can report
/// the actual cause.
pub(crate) fn with_api_fallback(
    mode: ProviderMode,
    remote: impl FnOnce() -> Result<AnalysisOutcome>,
    local: impl FnOnce() -> Result<AnalysisOutcome>,
) -> Result<AnalysisOutcome> {
    let error = match remote() {
        Ok(outcome) => return Ok(outcome),
        Err(error) => error,
    };
    let notice = if let Some(retry_after) = usage_limit_retry_after(&error) {
        ScanNotice::api_usage_limit("local", retry_after)
    } else if let Some(reason) =
        authentication_reason(&error).filter(|_| mode == ProviderMode::Hybrid)
    {
        ScanNotice::api_authentication(reason, "local")
    } else {
        return Err(error);
    };
    match local() {
        Ok(mut outcome) => {
            outcome.notice = Some(notice);
            Ok(outcome)
        }
        Err(_) => Err(error),
    }
}

fn error(message: &str) -> ScannerError {
    ScannerError::Ark(message.into())
}

pub(crate) fn classification(
    input: &ChunkInput<'_>,
    category: &str,
    api_category: &str,
    job: &Value,
    include_text: bool,
) -> Result<FinalClassification> {
    if job["status"] != "completed"
        || job["completion"]["state"] != "complete"
        || job["completion"]["failures"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    {
        return Err(error("API coverage is incomplete"));
    }
    let item = &job["categories"][api_category];
    let label = item["class_name"]
        .as_str()
        .ok_or_else(|| error("Missing API classification"))?;
    let confidence = score(&item["confidence"])?;
    let level = item["level"].as_str().unwrap_or("").to_ascii_lowercase();
    if !["l1", "l2", "l3"].contains(&level.as_str()) {
        return Err(error("Invalid API level"));
    }
    let mut evidence = vec![];
    let empty = Vec::new();
    let spans = match item.get("evidence_spans") {
        None => &empty,
        Some(value) => value
            .as_array()
            .ok_or_else(|| error("Invalid API evidence"))?,
    };
    for span in spans {
        let start = span["start_byte"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| error("Invalid API evidence"))?;
        let end = span["end_byte"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| error("Invalid API evidence"))?;
        if start >= end
            || end > input.content.len()
            || !input.content.is_char_boundary(start)
            || !input.content.is_char_boundary(end)
        {
            return Err(error("Invalid API evidence offsets"));
        }
        evidence.push(Evidence {
            start,
            end,
            label: span["label"].as_str().unwrap_or(label).into(),
            confidence: score(&span["score"])?,
            line_start: input.content[..start]
                .bytes()
                .filter(|b| *b == b'\n')
                .count()
                + 1,
            line_end: input.content[..end].bytes().filter(|b| *b == b'\n').count() + 1,
            text: include_text.then(|| input.content[start..end].to_owned()),
        });
    }
    let matched = !crate::ark::is_benign(label);
    if !matched && !evidence.is_empty() {
        return Err(error("Contradictory API classification"));
    }
    Ok(FinalClassification {
        schema: "patronus.security-scanner.classification.v1",
        run_id: input.run_id.into(),
        chunk_id: input.chunk_id.into(),
        file_id: input.file_id.into(),
        path: input.path.into(),
        category: category.into(),
        source: "patronus-api".into(),
        level,
        terminal: true,
        matched,
        label: label.into(),
        confidence,
        decision: None,
        evidence,
        duration_ms: item["duration_ms"].as_f64().unwrap_or(0.0).max(0.0) as u64,
        warnings: vec![],
    })
}
fn score(value: &Value) -> Result<f64> {
    value
        .as_f64()
        .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
        .ok_or_else(|| error("Invalid API confidence"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn job() -> Value {
        json!({"status":"completed","completion":{"state":"complete","failures":[]},"categories":{"pii":{"class_name":"EMAIL","confidence":0.95,"level":"L2","evidence_spans":[{"label":"EMAIL","score":0.95,"start_byte":0,"end_byte":2,"text":"é"}]}}})
    }
    #[test]
    fn api_offsets_are_utf8_bytes_and_payload_text_is_not_retained() {
        let input = ChunkInput {
            input_tokens: None,
            run_id: "test",
            chunk_id: "one",
            file_id: "one",
            path: "one",
            content: "é hello",
        };
        let result = classification(&input, "pii", "pii", &job(), false).unwrap();
        assert_eq!(result.evidence[0].end, 2);
        assert!(result.evidence[0].text.is_none());
        assert!(result.matched);
        let mut invalid = job();
        invalid["categories"]["pii"]["evidence_spans"][0]["end_byte"] = json!(1);
        assert!(classification(&input, "pii", "pii", &invalid, false).is_err());
    }
    #[test]
    fn incomplete_and_missing_categories_cannot_approve() {
        let input = ChunkInput {
            input_tokens: None,
            run_id: "test",
            chunk_id: "one",
            file_id: "one",
            path: "one",
            content: "é hello",
        };
        for state in ["running", "failed"] {
            let mut bad = job();
            bad["status"] = json!(state);
            assert!(classification(&input, "pii", "pii", &bad, false).is_err());
        }
        let mut bad = job();
        bad["completion"]["state"] = json!("degraded");
        assert!(classification(&input, "pii", "pii", &bad, false).is_err());
        assert!(classification(&input, "dlp", "dlp", &job(), false).is_err());
    }
}

#[cfg(test)]
mod hybrid_boundary_tests {
    use super::*;
    #[test]
    fn exact_boundary_and_prompt_routing() {
        for count in [1024, 1025] {
            let text = " hello".repeat(count);
            assert_eq!(input_tokens(&text), count);
            let input = ChunkInput {
                run_id: "runtime",
                chunk_id: "0",
                file_id: "0",
                path: "0",
                content: &text,
                input_tokens: None,
            };
            assert_eq!(
                local_route(ProviderMode::Hybrid, &input, false),
                count <= 1024
            );
            assert!(local_route(ProviderMode::Hybrid, &input, true));
            assert!(!local_route(ProviderMode::Api, &input, true));
            assert!(local_route(ProviderMode::Local, &input, false));
            let chunk = ChunkInput {
                content: "small chunk",
                input_tokens: Some(count),
                ..input
            };
            assert_eq!(
                local_route(ProviderMode::Hybrid, &chunk, false),
                count <= 1024
            );
        }
        assert!(input_tokens("<|endoftext|>") > 0);
    }

    #[test]
    fn hybrid_file_and_repo_chunks_use_the_same_token_boundary() {
        for count in [1_024, 1_025] {
            for run_id in ["file-scan", "repo-scan"] {
                let input = ChunkInput {
                    run_id,
                    chunk_id: "0",
                    file_id: "0",
                    path: "document.pdf",
                    content: "one small chunk",
                    input_tokens: Some(count),
                };
                assert_eq!(
                    local_route(ProviderMode::Hybrid, &input, false),
                    count <= 1_024
                );
            }
        }
    }
}

#[cfg(test)]
mod usage_limit_fallback_tests {
    use super::*;

    fn api_error(kind: patronus_api_client::ErrorKind) -> ScannerError {
        ScannerError::Api {
            kind,
            message: "bounded".into(),
            code: None,
            retry_after: Some(45),
            details: None,
        }
    }

    fn scanned() -> Result<AnalysisOutcome> {
        Ok(AnalysisOutcome {
            classifications: vec![],
            failures: vec![],
            degraded: false,
            notice: None,
        })
    }

    fn auth_error(code: Option<&str>) -> ScannerError {
        ScannerError::Api {
            kind: patronus_api_client::ErrorKind::Authentication,
            message: "bounded".into(),
            code: code.map(Into::into),
            retry_after: None,
            details: None,
        }
    }

    #[test]
    fn exhausted_api_quota_scans_locally_and_reports_why() {
        let outcome = with_api_fallback(
            ProviderMode::Api,
            || Err(api_error(patronus_api_client::ErrorKind::Quota)),
            scanned,
        )
        .unwrap();
        assert_eq!(
            outcome.notice,
            Some(ScanNotice::api_usage_limit("local", Some(45)))
        );
    }

    #[test]
    fn exhausted_rate_limit_also_scans_locally() {
        let outcome = with_api_fallback(
            ProviderMode::Hybrid,
            || Err(api_error(patronus_api_client::ErrorKind::RateLimit)),
            scanned,
        )
        .unwrap();
        assert_eq!(outcome.notice.unwrap().fallback, "local");
    }

    #[test]
    fn unavailable_local_model_keeps_the_usage_limit_error() {
        let error = with_api_fallback(
            ProviderMode::Api,
            || Err(api_error(patronus_api_client::ErrorKind::Quota)),
            || Err(ScannerError::Ark("model missing".into())),
        )
        .unwrap_err();
        assert_eq!(usage_limit_retry_after(&error), Some(Some(45)));
    }

    #[test]
    fn other_api_failures_never_fall_back() {
        let mut local_called = false;
        let error = with_api_fallback(
            ProviderMode::Hybrid,
            || Err(api_error(patronus_api_client::ErrorKind::Transport)),
            || {
                local_called = true;
                scanned()
            },
        )
        .unwrap_err();
        assert!(!local_called);
        assert_eq!(usage_limit_retry_after(&error), None);
    }

    #[test]
    fn successful_api_scans_carry_no_notice() {
        let outcome =
            with_api_fallback(ProviderMode::Api, scanned, || panic!("local not needed")).unwrap();
        assert_eq!(outcome.notice, None);
    }

    #[test]
    fn hybrid_scans_locally_when_the_login_expired_and_names_the_cause() {
        for (code, reason) in [
            (Some("authentication_expired"), "authentication_expired"),
            (Some("authentication_missing"), "authentication_missing"),
            (Some("server_code"), "authentication_rejected"),
            (None, "authentication_rejected"),
        ] {
            let outcome =
                with_api_fallback(ProviderMode::Hybrid, || Err(auth_error(code)), scanned).unwrap();
            assert_eq!(
                outcome.notice,
                Some(ScanNotice::api_authentication(reason, "local"))
            );
            assert_eq!(outcome.notice.unwrap().code, format!("api_{reason}"));
        }
    }

    #[test]
    fn analyzer_failures_map_to_fixed_public_codes() {
        use patronus_api_client::ErrorKind;
        for (kind, reason) in [
            (ErrorKind::Timeout, "api_timeout"),
            (ErrorKind::Transport, "api_unavailable"),
            (ErrorKind::Protocol, "api_invalid_response"),
            (ErrorKind::Validation, "api_request_rejected"),
        ] {
            assert_eq!(scan_failure_reason(&api_error(kind)), reason);
        }
        assert_eq!(
            scan_failure_reason(&ScannerError::Ark("PRIVATE model path".into())),
            "local_scanner_error"
        );
        assert_eq!(
            scan_failure_reason(&ScannerError::Config {
                source_name: "config".into(),
                message: "PRIVATE".into(),
            }),
            "configuration_unavailable"
        );
    }

    #[test]
    fn api_mode_keeps_authentication_failures() {
        let error = with_api_fallback(
            ProviderMode::Api,
            || Err(auth_error(Some("authentication_expired"))),
            || panic!("API mode must not scan locally after an authentication failure"),
        )
        .unwrap_err();
        assert_eq!(
            authentication_reason(&error),
            Some("authentication_expired")
        );
    }

    #[test]
    fn unavailable_local_model_keeps_the_authentication_error() {
        let error = with_api_fallback(
            ProviderMode::Hybrid,
            || Err(auth_error(Some("authentication_expired"))),
            || Err(ScannerError::Ark("model missing".into())),
        )
        .unwrap_err();
        assert_eq!(
            authentication_reason(&error),
            Some("authentication_expired")
        );
    }
}
