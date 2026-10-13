---
name: qa-dx
description: Developer-experience QA for Patronus — check that docs.patronus.studio is current and understandable, that SDK quick starts and examples work, and list what is missing. Use as part of the QA run or when asked to review docs or SDK usability.
---

# Developer experience QA

**Persona:** a developer who has never used Patronus, has 15 minutes, and wants to scan untrusted text from their app. Judge everything from that seat.

## 1. Deterministic baseline

Run `node qa/sdk.mjs`. It installs the *published* SDKs into empty directories and runs each README quick start against the QA key. Its findings already cover installability, version drift and broken quick starts.

## 2. Docs walk-through (docs.patronus.studio)

Read the site the way the persona would, using WebFetch or the built-in browser. Start at the landing page, then:
- Quick start
- Authentication / API keys
- Each SDK page (TypeScript, Python, Rust)
- API reference
- Runtime hooks / plugins (Claude, Codex, DeepSeek)
- Pricing / limits

For every page, record:
- **Correctness**: compare parameters, endpoints and examples against `https://docs.patronus.studio/openapi.json`, the SDK sources (`sdk/typescript/src`, `sdk/python/src`, `crates/patronus-api-client/src`) and `patronus-security-scanner --help` (plus `integration --help`). Note outdated names, removed flags, wrong defaults and wrong versions.
- **Runnable examples**: copy each code snippet into a scratch directory and run it with `PATRONUS_API_KEY` from `PATRONUS_QA_API_KEY`. A snippet that fails as written is a finding.
- **Links**: no 404s or redirects to other products.
- **Clarity score 1–5**. 5 means the persona succeeds without guessing. Explain anything below 4 in one sentence.
- **Missing**: what the persona needed and could not find. Typical gaps are an error-handling example, rate limits, scan_url / scan_mcp_server examples, a minimal hooks walkthrough, and troubleshooting for `degraded` / `inactive` hook messages.

## 3. In-repo docs and examples

Review these for the same criteria:
- `README.md`
- `docs/*.md`
- the SDK READMEs and `INSTALL.md` files
- `examples/file-checker/`

Simple examples should exist for:
- text,
- URL,
- file upload,
- MCP server scan,
- handling a pending result,
- handling errors and limits.

Each missing simple example is a `docs` finding with a proposed snippet in the suggestion.

## 4. Output

Write `~/.patronus-qa/runs/<date>/dx.json` in the report shape (see the qa-run skill). Use `metrics.pages` = `[{url, score, issues: n}]`, and give findings area `docs`, `sdk` or `ux`.

**Fixes:**
- In-repo docs, READMEs and examples are draft-PR candidates.
- Fixes to docs.patronus.studio are issues only. Quote the exact wrong text and the proposed replacement.
