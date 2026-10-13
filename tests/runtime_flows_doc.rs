//! Keeps docs/runtime-flows.md binding: every hook event, runtime RPC method and
//! receipt status that exists in the code must be described there.
use std::path::Path;

fn read(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

fn strings(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn runtime_flows_document_every_event_method_and_status() {
    let doc = read("docs/runtime-flows.md");
    let schema: serde_json::Value =
        serde_json::from_str(&read("schemas/runtime-v1.schema.json")).unwrap();
    let defs = &schema["$defs"];
    let mut names = strings(&defs["request"]["properties"]["method"]["enum"]);
    names.extend(strings(&defs["status"]["properties"]["status"]["enum"]));
    names.extend(strings(
        &defs["disclosure_state"]["properties"]["status"]["enum"],
    ));
    names.extend(["redacted", "unavailable", "confirmation_required"].map(String::from));
    for plugin in ["claude", "codex"] {
        let hooks: serde_json::Value =
            serde_json::from_str(&read(&format!("plugins/{plugin}/hooks/hooks.json"))).unwrap();
        names.extend(hooks["hooks"].as_object().unwrap().keys().cloned());
    }
    let missing: Vec<_> = names
        .iter()
        .filter(|name| !doc.contains(&format!("`{name}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "docs/runtime-flows.md does not describe: {missing:?}"
    );
}
