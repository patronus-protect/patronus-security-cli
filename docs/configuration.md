# Configuration

The compiled defaults come from `config/defaults.toml`. Precedence is: compiled defaults, legacy per-user platform config, `~/.patronus-security-scanner/config.toml`, repository `.patronus-security-scanner.toml` for repo scans, explicit `--config`, then applicable CLI flags. Unknown keys and schema versions other than `1` are rejected. `--no-repo-config` skips repository configuration.

`provider.mode` accepts `local`, `api`, and `hybrid`. API mode sends scan text to `https://control.patronus.studio/api/v1/scan`, using the environment variable named by `provider.api_key_env` or the CLI login token. Hybrid keeps file scans and user prompts local. Tool/MCP results with at most 1024 cl100k_base tokens run locally; larger results go to the API. Token counts sum all raw text blocks in the original result before chunking; envelope keys, metadata and media are excluded. Incomplete, failed, malformed and timed-out API results fail closed; there is no provider fallback. `config init --provider <mode>` selects an initial mode. The retired hosted-browser provider is rejected; its unused legacy origin field is discarded when loading old configuration.

Reports default to `~/.patronus-security-scanner/output`; protocol journals and runtime sessions use the same shared user directory. `PATRONUS_DATA_DIR` relocates this root for tests or managed deployments. Explicit output/state overrides are honored. The old `.patronus-security-scanner/output` configuration default is normalized to the shared root; existing repository reports are not moved automatically.

`config print` emits the effective, recursively redacted configuration. Ark categories are `prompt_injection`, `dlp`, `pii` and `threat`; levels are `l1`, `l2` and `l3`. `threat` requires prepared L2/L3 assets; L1 cannot complete that category. Model downloads are off by default. Model-specific fixtures can remain clean under L1: coverage and the selected profile determine what a result establishes.

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
response_wait_ms = 500
request_timeout_ms = 30000
scan_timeout_ms = 60000
retention_seconds = 2592000
max_payload_bytes = 10485760
max_store_bytes = 536870912
max_pending_jobs = 64
```

The runtime requires local mode and uses **Ark 0.1.6** with downloads disabled. The default L1 profile works without model downloads. Prepare assets required by an L2/L3 profile separately for that version. Missing required assets, a different provider or invalid limits prevent startup; the plugin does not install a scanner or change providers. Scanning never triggers model or tokenizer downloads.

| Runtime key | Meaning and valid range |
| --- | --- |
| `response_wait_ms` | Response scan wait after submission; 0 through `scan_timeout_ms`. Default 500; 300 is also supported. Zero immediately yields a pending receipt. |
| `request_timeout_ms` | Request job deadline; 1 through `scan_timeout_ms`. No approval by the deadline means no tool execution. |
| `scan_timeout_ms` | Response job deadline; 1–300000 ms. Queue time counts toward job deadlines. |
| `retention_seconds` | Payload/job and shared result-cache retention from acceptance; 1–2592000 seconds. Default 30 days. Cleanup runs while the service is active or on restart. |
| `max_payload_bytes` | Maximum serialized JSON payload; 1–67108864 bytes. Default 10 MiB. |
| `max_store_bytes` | Stored original, redacted and outcome data budget; at least `max_payload_bytes`. Default 512 MiB; not a hard filesystem quota for SQLite overhead. |
| `max_pending_jobs` | Combined queued/running jobs; 1–4096. Default 64. |

The response wait does not include process startup, submission/persistence or host processing. It is not a promise of 500-ms total latency: a local release cold start measured about 2.3 seconds. Requests always wait for complete approval and use their own deadline. No timing setting permits access to a dangerous, pending or failed original. Runtime limits apply per scanner process; they are not an aggregate limit across sessions.

## Native DeepSeek options

Plugin configuration uses **camelCase**, while the CLI's TOML and protocol use **snake_case**.

| Plugin option | Purpose |
| --- | --- |
| `responseWaitMs` | Override the response wait in the adapter; otherwise use `hello.runtime.response_wait_ms`. The bundled profile explicitly sets 500. |
| `requestTimeoutMs` | Override how long the adapter waits for request approval; otherwise use `hello.runtime.request_timeout_ms`. |
| `executable` | Absolute path to an explicitly trusted installed CLI; otherwise resolve the installed CLI on PATH, excluding repository-local candidates. |
| `configPath` | Explicit CLI configuration file. Use an absolute path for a stable setup. |
| `stateDir` | Private session-state root outside the repository. The adapter derives separate capability, quarantine and scanner paths from each native session ID. |

Timing overrides are bounded integer milliseconds. They change adapter waiting only, not the runtime's server-side deadlines; align the TOML limits when extending a deadline. To use the CLI's response default, omit the profile override. An injectable `client` exists for integration tests and is not a normal installation option.

The plugin defaults to `~/.patronus-security-scanner/deepseek-sessions`. A SHA-256 hash of the native `SessionId` selects a private subdirectory containing `capability`, an optional `quarantined` marker and the `scanner/` store. Keep this root stable to resume an existing session's jobs. Different session IDs remain isolated even in the same working directory. Concurrent attempts to open the same session store are rejected by its process lock.

Agent disposal closes its scanner process; resuming the same session restores its capability and opens the store again. Quarantine survives restarts and propagates to native forks that inherit the affected history. Scanner retention removes job payloads and metadata, not these session-state files. A manually started `serve --stdio` without `--state-dir` uses `~/.patronus-security-scanner/runtime`. Neither location should be confused with the static scanner's `output.root`.

See the [DeepSeek README](../plugins/deepseek/README.md) for installation and [runtime protocol](runtime-protocol.md) for status/release rules. MB in progress output means decimal megabytes (1,000,000 bytes); the runtime sizes above are exact bytes.

## Shared plugin policy

See [plugin settings](plugin-configuration.md) for per-category levels, L1 detector switches, hook selection, per-chat pauses and the shared home directory.

## Dashboard and policies

Run `patronus-security-scanner dashboard`. `[plugin_policies."<host>.<surface>"]` stores each plugin's granular L1 booleans and Injection/Threat assessment settings. Hosts: `claude`, `codex`, `deepseek`. Surfaces: `user_input`, `tool_result`, `mcp_result`. Assessment rules select `enabled`, `max_level` (`l2` or `l3`) and `min_confidence` (0–1). No access-rule engine is involved.

`policy show`, `policy validate <policies.json>` and `policy import <policies.json>` manage the nine scopes. `policy rules` lists the L1 inventory. `policy check <check.json>` accepts `host`, `surface` and `text`. `assets prepare` includes levels required by plugin policies. Restart active sessions after saving settings. See [local dashboard](local-dashboard.md).

The earlier `[analysis]` configuration still applies to file scans and clients without plugin scope metadata. Its `l1_rules` are direct Ark gates. `analysis.confidence` supports Injection/Threat model thresholds; the plugin UI manages the corresponding scoped settings instead.
