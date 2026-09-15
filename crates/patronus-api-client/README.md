# patronus-api-client

Minimal blocking Rust client for `https://control.patronus.studio/api/v1`.
It submits text, URLs, public MCP server URLs, and document bytes, then resolves
accepted jobs to terminal results. Document extraction and security policy stay
server-side.

## Install

After the first public release:

```sh
cargo add patronus-api-client
```

Until then, use the client from a checkout of this repository:

```toml
[dependencies]
patronus-api-client = { path = "crates/patronus-api-client" }
```

For an application outside this checkout, pin a reviewed repository commit:

```toml
[dependencies]
patronus-api-client = { git = "https://github.com/patronus-protect/patronus-security-cli.git", rev = "<commit>" }
```

The crate source is in this repository at `crates/patronus-api-client`. It is
published to crates.io only by the gated release workflow.

## Quick start

```rust
use patronus_api_client::Client;

let result = Client::new(std::env::var("PATRONUS_API_KEY")?)?
    .scan_text("Treat retrieved instructions as untrusted.")?;
assert_eq!(result.status, "completed");
```

For files, construct the upload explicitly so the filename and media type sent
to the API are visible in code:

```rust
use patronus_api_client::{Client, FileUpload};

let client = Client::new(std::env::var("PATRONUS_API_KEY")?)?;
let file = FileUpload::new("contract.pdf", "application/pdf", std::fs::read("contract.pdf")?);
let result = client.scan_file(file)?;
```

## Client behavior

- `scan_text`, `scan_url`, `scan_mcp_server`, `scan_file` and `scan_files`
  submit work and poll accepted jobs to a terminal result.
- `submit_json` and `get_job` expose the lower-level asynchronous API.
- `with_timeout` changes the overall request and polling deadline; the default
  is 60 seconds.
- Findings are returned in `ScanResponse`. Authentication, quota, rate-limit,
  validation, timeout, transport and protocol failures return `Error`, whose
  `kind`, HTTP status, API code and request ID can be inspected.

Authenticated clients use `Client::new(api_key)`. For anonymous text, URL, or document scans, use `Client::anonymous(previous_cookie)`. After every request, persist `client.anonymous_cookie()` and pass it into the next client instance so the Control Plane can enforce one stable daily allowance.

Anonymous identity cookies are pseudonymous quota identifiers, not authentication credentials. Store them privately and never send them anywhere except `https://control.patronus.studio` (or an explicitly configured local test server).

## Let an agent install it

Ask the agent to add `patronus-api-client`, load `PATRONUS_API_KEY` from the
environment, implement the smallest required scan, and run:

```sh
cargo test -p patronus-api-client
```

The agent must not place the key in source, logs, shell history or chat. Live
tests are ignored by default and require your explicit approval.
