# `patronus-api-client`

Synchronous, dependency-free client for Python 3.10 or newer. It supports text,
URL, public MCP server and file scans and polls accepted jobs automatically.

## Install

```sh
python -m pip install patronus-api-client
```

For installation by a coding agent, provide the
[agent installation instructions](https://github.com/patronus-protect/patronus-security-cli/blob/main/sdk/python/INSTALL.md).

## Quick start

```python
import os

from patronus_api_client import Patronus

client = Patronus(api_key=os.environ["PATRONUS_API_KEY"])
result = client.scan_file("contract.pdf")
```

Multiple files and optional context can be submitted together:

```python
result = client.scan_files(
    ["contract.pdf", "appendix.txt"],
    text="Review these files as one request.",
)
```

## API and errors

Use `scan_text`, `scan_url`, `scan_mcp_server`, `scan_file` or `scan_files` for
high-level scans. `submit` and `get_job` expose the lower-level job API. Findings
are returned as dictionaries. `PatronusError` represents authentication, quota,
rate-limit, validation, timeout, transport and protocol failures and exposes
`kind`, `status`, `code`, `request_id`, `retry_after` and `details`.

The constructor accepts `base_url`, `timeout` and `poll_interval`. Non-local
custom endpoints must use HTTPS.
