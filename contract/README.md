# API contract fixtures

The published OpenAPI document remains authoritative and is maintained with the
Control Plane. These deliberately small response fixtures are consumed by every
client implementation so polling and result semantics cannot drift between
Rust, TypeScript, and Python.

Contract version: `1.2.0`

OpenAPI URL: `https://docs.patronus.studio/openapi.json`

`openapi.json` is the pinned copy of that version. `node contract/validate.mjs`
checks every fixture against it (the TypeScript test suite runs it too), and
`qa/integrations.mjs` lists the concrete changes when the published spec moves on.
