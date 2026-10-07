Patronus API integrations for n8n, Make, Dify, Zapier and Activepieces, licensed
under Apache-2.0. Guard Input connects RAG/prompt text to an LLM and releases the
exact original text only after a complete allowed scan. No Patronus CLI is needed.

Assets include installable n8n/Activepieces packages, a Dify package, Make app
definitions with a provisioning command, a Zapier app source package, and SHA256
checksums. Source, build instructions, tests and dependency locks are in
`plugins/automations` in the public repository.

These assets have local package/SDK validation. They have not been installed in
all five production hosts or approved by their marketplaces. Make/Zapier public
app install links require publisher registration. The unsigned Dify package
requires an instance policy that permits it or the normal signing/review process.

A previous synthetic API check observed an L3 worker HTTP 500 and degraded
analysis despite an allow decision. Guard Input rejects degraded results. Healthy
live API behavior must be confirmed before presenting this as production-ready.
