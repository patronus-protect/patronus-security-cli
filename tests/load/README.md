# Hybrid load smoke test

This opt-in test compares concurrent local and hybrid scans of synthetic benign
content. It never enables content storage and reports only aggregate timing,
status, and child-process CPU metrics.

```sh
set -a
source .env
set +a
.venv/bin/python tests/load/hybrid_load.py \
  --binary target/release/patronus-security-scanner \
  --mode compare --requests 8 --concurrency 4 --tokens 4096
```

`PATRONUS_API_KEY` is required for hybrid mode. The test is intentionally not
part of normal CI because it consumes the authenticated API and measures live
service behavior.
