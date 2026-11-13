# Configuration

The compiled defaults come from `config/defaults.toml`. Precedence is: compiled defaults, legacy per-user platform config, `~/.patronus-security-scanner/config.toml`, repository `.patronus-security-scanner.toml` for repo scans, explicit `--config`, then applicable CLI flags. Unknown keys and schema versions other than `1` are rejected. `--no-repo-config` skips repository configuration.

`provider.mode` accepts `local`, `api`, and `hybrid` and controls **Wolf model analysis**, not the native detectors. All L1 rules, PII, DLP and Cat run locally, with every selected native mode preserved. API mode sends text only for enabled Injection/Threat model stages (L2/L3). Hybrid keeps prompts and results/files of at most 2048 tokens local and can use the API for Wolf on larger results/files. Wolf API failures retain the existing usage-limit/authentication fallback behavior. Explicit URL/MCP service audits and explicitly requested API document uploads remain separate workflows; they are not automatic native-detector routing.

Reports default to `~/.patronus-security-scanner/output`; protocol journals and runtime sessions use the same shared user directory. `PATRONUS_DATA_DIR` relocates this root for tests or managed deployments. Explicit output/state overrides are honored. The old `.patronus-security-scanner/output` configuration default is normalized to the shared root; existing repository reports are not moved automatically.

Static `scan file`, `scan directory`, and `scan repo` commands omit analyzed chunk content by default. Pass `--activate-store-content` to retain it in `chunks.jsonl`; the CLI prints the existing sensitive-content warning when this opt-in is active.

Local static scans decode UTF-8 and BOM-marked UTF-16 text directly. PDF text and DOCX document XML are extracted locally with bounded decompression; image-only PDFs require OCR and are reported as unsupported documents.

`config print` emits the effective, recursively redacted configuration. Ark categories are `prompt_injection`, `dlp`, `pii` and `threat`; levels are L1 (rules), L2 (lightweight ML models) and L3 (deeper models). `threat` requires prepared L2/L3 assets; L1 cannot complete that category. Model downloads are off by default. Model-specific fixtures can remain clean under L1: coverage and the selected profile determine what a result establishes.

## Local request/response runtime

`serve --stdio` uses defaults, per-user configuration and an explicit `--config`. It does **not** implicitly load the current repository's config. The native plugin passes its `configPath` as `--config`. Its `stateDir` selects a private session-state root; each session's scanner receives a separate `<stateDir>/<session-hash>/scanner` directory through `--state-dir`.

```toml
schema_version = 1

[provider]
mode = "local"

[ark]
categories = ["prompt_injection", "dlp", "pii"]
max_level = "l1"
download_files = false

[runtime]
response_wait_ms = 1000
request_timeout_ms = 30000
scan_timeout_ms = 60000
retention_seconds = 2592000
max_payload_bytes = 10485760
max_store_bytes = 536870912
max_pending_jobs = 64
```

The runtime requires local mode and uses **Ark 0.1.16** with downloads disabled. The default L1 profile works without model downloads. Prepare assets required by an L2/L3 profile separately for that version. Missing required assets, a different provider or invalid limits prevent startup; the plugin does not install a scanner or change providers. Scanning never triggers model or tokenizer downloads.

| Runtime key | Meaning and valid range |
| --- | --- |
| `response_wait_ms` | Response scan wait after submission; 0 through `scan_timeout_ms`. Default 1000. Zero immediately yields a pending receipt. |
| `request_timeout_ms` | Request analyzer budget; 1 through `scan_timeout_ms`. It starts when the worker claims the job. Completed findings stop the turn; infrastructure failure or timeout continues with degraded context. |
| `scan_timeout_ms` | Response analyzer budget; 1–300000 ms. It starts when the worker claims the job, so queue contention cannot consume the scan budget. |
| `retention_seconds` | Payload/job and shared result-cache retention from acceptance; 1–2592000 seconds. Default 30 days. Cleanup runs while the service is active or on restart. |
| `max_payload_bytes` | Maximum serialized JSON payload; 1–67108864 bytes. Default 10 MiB. |
| `max_store_bytes` | Stored original, redacted and outcome data budget; at least `max_payload_bytes`. Default 512 MiB; not a hard filesystem quota for SQLite overhead. |
| `max_pending_jobs` | Combined queued/running jobs; 1–4096. Default 64. |

The response wait does not include process startup, submission/persistence or host processing. It is not a promise of 500-ms total latency: a local release cold start measured about 2.3 seconds. Requests use their own deadline. No timing setting turns a dangerous or pending verdict into approval. Infrastructure failures fall open with explicit degraded context and the original remains unverified. Runtime limits apply per scanner process; they are not an aggregate limit across sessions.

## Native DeepSeek options

Plugin configuration uses **camelCase**, while the CLI's TOML and protocol use **snake_case**.

| Plugin option | Purpose |
| --- | --- |
| `responseWaitMs` | Override the response wait in the adapter; otherwise use `hello.runtime.response_wait_ms`. The bundled profile explicitly sets 1000. |
| `requestTimeoutMs` | Override how long the adapter waits for request approval; otherwise use `hello.runtime.request_timeout_ms`. |
| `executable` | Absolute path to an explicitly trusted installed CLI; otherwise resolve the installed CLI on PATH, excluding repository-local candidates. |
| `configPath` | Explicit CLI configuration file. Use an absolute path for a stable setup. |
| `stateDir` | Private session-state root outside the repository. The adapter derives separate capability and scanner paths from each native session ID. |

Timing overrides are bounded integer milliseconds. They change adapter waiting only, not the runtime's server-side deadlines; align the TOML limits when extending a deadline. To use the CLI's response default, omit the profile override. An injectable `client` exists for integration tests and is not a normal installation option.

The plugin defaults to `~/.patronus-security-scanner/deepseek-sessions`. A SHA-256 hash of the native `SessionId` selects a private subdirectory containing `capability` and the `scanner/` store. Keep this root stable to resume an existing session's jobs. Different session IDs remain isolated even in the same working directory. Concurrent attempts to open the same session store are rejected by its process lock.

Agent disposal closes its scanner process; resuming the same session restores its capability and opens the store again. Scanner retention removes job payloads and metadata, not these session-state files. A manually started `serve --stdio` without `--state-dir` uses `~/.patronus-security-scanner/runtime`. Neither location should be confused with the static scanner's `output.root`.

See the [DeepSeek README](../plugins/deepseek/README.md) for installation and the [runtime text contract](runtime-text-contract.md) for protection rules. MB in progress output means decimal megabytes (1,000,000 bytes); the runtime sizes above are exact bytes.

## Shared plugin policy

The dashboard manages per-category levels, L1 detector switches, hook selection and per-chat pauses. `plugins.json` in the shared Patronus data directory stores hook switches and paused chats.

## Dashboard and policies

Run `patronus-security-scanner dashboard`. `[plugin_policies."<host>.<surface>"]` stores each plugin's granular L1 booleans and Injection/Threat assessment settings. Hosts: `claude`, `codex`, `deepseek`. Surfaces: `user_input`, `tool_result`, `mcp_result`. Assessment rules select `enabled` and `max_level` (`l2` or `l3`); Ark's calibrated `decision_candidate` determines acceptance. Legacy `min_confidence` values are accepted during migration but ignored and omitted when configuration is saved. No access-rule engine is involved.

`policy show`, `policy validate <policies.json>` and `policy import <policies.json>` manage the nine scopes. `policy rules` lists the L1 inventory. `policy check <check.json>` accepts `host`, `surface` and `text`. `assets prepare` includes levels required by plugin policies. Restart active sessions after saving settings.

The earlier `[analysis]` configuration still applies to file scans and clients without plugin scope metadata. Its `l1_rules` are direct Ark gates. `analysis.confidence` supports Injection/Threat model thresholds; the plugin UI manages the corresponding scoped settings instead.


## PII and DLP modes (CLI 0.1.7)

Every local PII/DLP rule is listed by `policy rules` and in the local dashboard's **Detection rules** page. Each category independently supports `strict`, `balanced` and `recall`. Strict retains structural rule acceptance; scored modes apply Ark's calibrated scoring and enable the rules marked as requiring a scored mode. A rule switch does not override its supported modes. New rules are migrated into existing profiles with their Ark defaults, preserving existing switches.

```toml
[analysis]
pii_mode = "recall"
dlp_mode = "balanced"

[analysis.l1_rules]
pii_imei = true
dlp_deepseek_key = true

# Add pii_mode = "strict" inside a complete existing
# [plugin_policies."codex.tool_result"] profile to override it.
# Omitted profile modes inherit the global analysis modes.
```

The mode keys are optional in saved plugin profiles. Global settings apply to ordinary CLI scans; plugin profiles select the host and user-input/tool-result/MCP-result scope. Changes take effect in new agent sessions. No scoring threshold is invented by the CLI.

PII/DLP scoring does not depend on the public API supporting these modes: they always execute locally. Selecting API or Hybrid for Wolf therefore does not disable or reject Balanced/Recall native detection. Only enabled Wolf model stages are submitted by the automatic CLI/plugin pipeline; native rule gates and scoring modes are not sent to that endpoint.

## Shell and Cedar

Cat K26 is prepared by `assets prepare`; the runtime refreshes a missing or stale pinned bundle in the background. The dashboard classifier only uses already prepared assets. The default model directory is the shared Patronus Desktop model directory unless `ark.model_dir` overrides it. The pinned manifest and bundle checksums are verified when loaded.

```toml
[shell.default]
ask_behavior = "low" # or "ask"
policy_dirs = []     # absolute local directories containing .cedar files

[shell.default.cedar_policies]
"kubectl.cedar" = '''
@id("user.no_kubectl_delete")
@decision("block")
@title("No kubectl deletes")
forbid (principal, action == Action::"segment", resource)
when { context.program == "kubectl" && context.verb == "DELETE" };
'''

[shell.hosts.claude]
ask_behavior = "ask"
# Host overrides are complete policies. Hosts without an override inherit shell.default.
```

An `allow` verdict runs; `ask` maps to low (runs without asking) by default or to medium (host approval) when configured as `ask`. Cat `block` remains medium, requesting host approval: Patronus does not introduce a new unconditional host block tier. Codex uses its existing held-command/one-time-token mechanism. The shell hook switch and per-chat pause still apply.

Named sources may contain one or more policies and are compiled against Ark's Cedar schema before configuration is saved. The dashboard imports `.cedar` files, edits sources and rejects invalid changes without replacing the saved configuration. `policy_dirs` are loaded in file-name order; keep them outside scanned/untrusted repositories. Source files are revalidated at startup. Invalid or unavailable runtime policy/model processing remains fail-open with an explicit unavailable reason.

`shell.default.rules` (and the equivalent host override) maps `cat.<policy id>` to booleans. `allowlist` maps a loaded bundle-default policy ID to `"ask"`; it cannot lower core policies or create an allow verdict. Preparing the pinned model is required to validate an allowlist. User sources, directories, allowlists and rule gates are local configuration, never sent to the hosted API.

Run `patronus-security-scanner dashboard` to edit all of this locally. The server binds only to loopback and keeps its existing token, origin, bounded-input and revision checks. Its Shell & Cedar command classifier never executes the submitted command and returns both Cat's decision and its mapped runtime action. The hosted MCP home only explains these settings and links to the official CLI installation guide; it cannot edit local settings.
