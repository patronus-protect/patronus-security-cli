# URL / file checker examples

Each example serves a small local page. The server uses its language's Patronus
SDK for `scanUrl` / `scanFile` or `scan_url` / `scan_file`. Set
`PATRONUS_API_KEY` in the server environment; the browser never receives it.
The page accepts one public HTTPS URL or one file per scan. Results are the SDK
response, including jobs, findings and coverage.

## TypeScript (Node.js 18+)

```sh
npm --prefix sdk/typescript install
npm --prefix sdk/typescript run build
cd examples/file-checker/typescript
npm install
npm run build
PATRONUS_API_KEY=your-key npm start
```

Open <http://127.0.0.1:8001>.

## Python (3.10+)

```sh
.venv/bin/python -m pip install -e sdk/python
PATRONUS_API_KEY=your-key .venv/bin/python examples/file-checker/python/app.py
```

Open <http://127.0.0.1:8002>.

## Live end-to-end check

After building the TypeScript app, place `PATRONUS_API_KEY` in the repository's
`.env` and run:

```sh
.venv/bin/python examples/file-checker/e2e.py
```

This starts both local servers and submits one TXT file and one public HTTPS URL
through each app. It performs four live API scans and prints only HTTP status and
job counts; it does not print the key or scan contents.

## CLI and dashboard

The CLI's URL and MCP commands call `remote_scan::scan`, which submits through
the Rust `patronus-api-client` SDK. Its anonymous file command calls the SDK's
`scan_files`. The dashboard's URL and MCP actions call the same `remote_scan::scan`
path. Dashboard file and text scans use the local scanner, whose remote analysis
requests also go through the Rust SDK. The CLI/dashboard do not need the
TypeScript or Python SDKs because they are Rust programs.
