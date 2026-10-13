# Privacy

The Patronus tools send only the content explicitly mapped into Submit Scan
(text or a URL/MCP endpoint) to `https://control.patronus.studio/api/v1/scan`.
Get Scan Result sends a public job identifier. Connection validation sends a
reserved missing-job identifier. Requests authenticate with the API key stored
by Dify. Selected content is processed under the account's API service policy
and consumes the account allowance; this plugin does not provide local scanning.

The plugin does not create a local content database, log API keys, read unrelated
workflow data or send information to another analytics endpoint. Dify and the
Patronus service retain their own platform/account logging and retention policies.
Returned evidence can contain sensitive source excerpts and should be handled
as sensitive workflow output. Consult the repository's
[privacy documentation](https://github.com/patronus-protect/patronus-security-cli/blob/main/docs/privacy.md) and your service agreement
before sending sensitive data.
