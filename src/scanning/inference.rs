use crate::{
    ark::{
        AnalysisOutcome, ArkAnalyzer, ChunkInput, ContentAnalyzer, Evidence, FinalClassification,
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
                || input.run_id != "runtime"
                || input
                    .input_tokens
                    .unwrap_or_else(|| input_tokens(input.content))
                    <= 1024))
}

type ScopedInference = std::collections::BTreeMap<String, (Box<Inference>, Option<Box<Inference>>)>;

pub struct Inference {
    local: Option<ArkAnalyzer>,
    config: Config,
    scoped: std::cell::RefCell<ScopedInference>,
}

impl Inference {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            local: if config.provider.mode != ProviderMode::Api {
                Some(ArkAnalyzer::with_policy(
                    &config.ark,
                    &config.analysis,
                    config.output.include_evidence_text,
                )?)
            } else {
                None
            },
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
        })
    }
}

impl ContentAnalyzer for Inference {
    fn prepare(&mut self) -> Result<()> {
        if let Some(local) = &mut self.local {
            local.prepare()?;
        }
        Ok(())
    }
    fn analyze(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        Ok(crate::plugin_policies::assess(
            self.analyze_text(input)?,
            &self.config.analysis.confidence,
        ))
    }
    fn analyze_user_prompt(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        Ok(crate::plugin_policies::assess(
            self.analyze_prompt(input)?,
            &self.config.analysis.confidence,
        ))
    }
    fn analyze_scoped(&self, input: ChunkInput<'_>, scope: &str) -> Result<AnalysisOutcome> {
        if !crate::plugin_policies::valid_scope(scope) {
            return Err(error("Invalid plugin policy scope"));
        }
        let profile = self
            .config
            .plugin_policies
            .get(scope)
            .cloned()
            .unwrap_or_else(|| {
                crate::plugin_policies::Profile::current(
                    &self.config,
                    scope.split_once('.').expect("validated scope").1,
                )
            });
        let local = local_route(
            self.config.provider.mode,
            &input,
            scope.ends_with(".user_input"),
        );
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
                .retain(|c| model_config.analysis.confidence.contains_key(c));
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
            let assessed = scan(models, input)?;
            outcome.classifications.extend(assessed.classifications);
            outcome.failures.extend(assessed.failures);
            outcome.degraded |= assessed.degraded;
        }
        Ok(outcome)
    }
}
impl Inference {
    fn analyze_text(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        if local_route(self.config.provider.mode, &input, false) {
            self.local
                .as_ref()
                .ok_or_else(|| error("Local inference unavailable"))?
                .analyze(input)
        } else {
            self.cloud(input, false)
        }
    }
    fn analyze_prompt(&self, input: ChunkInput<'_>) -> Result<AnalysisOutcome> {
        if self.config.provider.mode == ProviderMode::Api {
            self.cloud(input, true)
        } else {
            self.local
                .as_ref()
                .ok_or_else(|| error("Local inference unavailable"))?
                .analyze_user_prompt(input)
        }
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
}
