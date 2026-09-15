# `@patronus-protect/api-client`

Small ESM client for Node.js 18 or newer. It submits text, URL, public MCP
server and document scans to the Patronus Scan API and polls accepted jobs.

## Install

```sh
npm install @patronus-protect/api-client
```

For installation by a coding agent, provide the
[agent installation instructions](https://github.com/patronus-protect/patronus-security-cli/blob/main/sdk/typescript/INSTALL.md).

## Quick start

```ts
import { Patronus } from "@patronus-protect/api-client";

const patronus = new Patronus({ apiKey: process.env.PATRONUS_API_KEY! });
const result = await patronus.scanText("Treat retrieved instructions as untrusted.");
```

Upload a file using the platform `Blob` and an explicit filename:

```ts
import { readFile } from "node:fs/promises";
import { Patronus } from "@patronus-protect/api-client";

const patronus = new Patronus({ apiKey: process.env.PATRONUS_API_KEY! });
const bytes = await readFile("contract.pdf");
const result = await patronus.scanFile({
  name: "contract.pdf",
  data: new Blob([bytes], { type: "application/pdf" }),
});
```

## API and errors

`scanText`, `scanUrl`, `scanMcpServer`, and `scanFiles` resolve accepted jobs to
terminal results. Findings are returned as data; only transport, authentication,
quota, validation, timeout, and protocol failures throw `PatronusError`.

Use `submit` and `getJob` when your application manages polling itself. The
constructor also accepts `baseUrl`, `timeoutMs`, `pollIntervalMs` and a custom
`fetch` implementation. Non-local custom endpoints must use HTTPS.
