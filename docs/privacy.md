# Privacy

Repository traversal, decoding, chunking, Ark analysis, and report generation occur locally. The scanner has no telemetry, analytics, crash upload, or background service. Ark model preparation may access the network only when `assets prepare` or `ark.download_files = true` is explicitly selected.

`support-us` is the only support submission surface. It creates a local ZIP, removes absolute scan roots and evidence arrays from default members, prints every member, and requires confirmation. Source files are never included unless named exactly with `--include`; `--dry-run` always performs no request. The optional token is read only from `PATRONUS_SUPPORT_TOKEN` and is never persisted or printed.
