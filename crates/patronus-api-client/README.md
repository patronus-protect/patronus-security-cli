# patronus-api-client

Minimal blocking Rust client for `https://control.patronus.studio/api/v1`.
It submits text, URLs, public MCP server URLs, and document bytes, then resolves
accepted jobs to terminal results. Document extraction and security policy stay
server-side.

```rust
use patronus_api_client::Client;

let result = Client::new(std::env::var("PATRONUS_API_KEY")?)?
    .scan_text("Treat retrieved instructions as untrusted.")?;
assert_eq!(result.status, "completed");
```
Authenticated clients use `Client::new(api_key)`. For anonymous text, URL, or document scans, use `Client::anonymous(previous_cookie)`. After every request, persist `client.anonymous_cookie()` and pass it into the next client instance so the Control Plane can enforce one stable daily allowance.

Anonymous identity cookies are pseudonymous quota identifiers, not authentication credentials. Store them privately and never send them anywhere except `https://control.patronus.studio` (or an explicitly configured local test server).
