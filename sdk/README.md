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
| Rust | `patronus-api-client` | [README](../crates/patronus-api-client/README.md) · [agent install](../crates/patronus-api-client/INSTALL.md) |
| TypeScript | `@patronus-protect/api-client` | [README](typescript/README.md) · [agent install](typescript/INSTALL.md) |
| Python | `patronus-api-client` | [README](python/README.md) · [agent install](python/INSTALL.md) |

## Registry installation

```sh
cargo add patronus-api-client
npm install @patronus-protect/api-client
pip install patronus-api-client
```

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
