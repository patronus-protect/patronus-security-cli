# Patronus API clients

The Rust, TypeScript, and Python packages expose the same small surface:

- `scanText` / `scan_text`
- `scanUrl` / `scan_url`
- `scanFile(s)` / `scan_file(s)`
- `scanMcpServer` / `scan_mcp_server`
- low-level submit and job lookup

The Control Plane remains authoritative for extraction, limits, scan units, and
result semantics. Remote MCP OAuth is handled by MCP hosts rather than these
API-key clients.

## Packages

| Language | Package | Source |
| --- | --- | --- |
| Rust | `patronus-api-client` | [`crates/patronus-api-client`](../crates/patronus-api-client/README.md) |
| TypeScript | `@patronus-protect/api-client` | [`sdk/typescript`](typescript/README.md) |
| Python | `patronus-api-client` | [`sdk/python`](python/README.md) |

The packages are published by the gated release workflow when a release tag is
approved. Before the first public release, install from this repository using
the source instructions in each package README; the registry commands below
will work after version `0.1.0` has been published.

## Registry installation

```sh
cargo add patronus-api-client
npm install @patronus-protect/api-client
pip install patronus-api-client
```

Release tags publish the clients through the gated release workflow. npm and
PyPI use GitHub OIDC trusted publishing; crates.io uses the protected
`CARGO_REGISTRY_TOKEN` secret.

## Agent-assisted installation

Give your coding agent the README for the language you use. It may add the
dependency, read the API key from the existing `PATRONUS_API_KEY` environment
variable, add a minimal scan call and run the deterministic package tests. It
must not ask you to paste the key into chat, commit it, print it, or run a live
scan unless you explicitly authorize network use and quota consumption.

## Tests

Deterministic contract tests cover every public client method without consuming
quota. Live tests perform one text scan per language using a dedicated key:

```sh
cp .env.example .env
# Set PATRONUS_API_KEY in .env, then run the language-specific live test.
cargo test -p patronus-api-client --test live -- --ignored
npm --prefix sdk/typescript run test:live
.venv/bin/python -m unittest discover -s sdk/python/tests -p live_client.py -v
```

GitHub Actions reads the same variable from the `PATRONUS_API_KEY` secret in the
`api-tests` GitHub Environment. Pull requests run deterministic tests only;
pushes to `main` and manual runs also execute the live suite.
