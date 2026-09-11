# `patronus-api-client`

```python
from patronus_api_client import Patronus

client = Patronus(api_key="...")
result = client.scan_file("contract.pdf")
```

The dependency-free client supports text, URL, public MCP server, and file scans.
Accepted jobs are polled automatically. Findings are returned as data.
