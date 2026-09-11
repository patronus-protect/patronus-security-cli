# `@patronus-protect/api-client`

```ts
import { Patronus } from "@patronus-protect/api-client";

const patronus = new Patronus({ apiKey: process.env.PATRONUS_API_KEY! });
const result = await patronus.scanText("Treat retrieved instructions as untrusted.");
```

`scanText`, `scanUrl`, `scanMcpServer`, and `scanFiles` resolve accepted jobs to
terminal results. Findings are returned as data; only transport, authentication,
quota, validation, timeout, and protocol failures throw `PatronusError`.
