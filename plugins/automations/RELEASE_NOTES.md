Patronus integrations for n8n, Make, Zapier, Dify and Activepieces, licensed under
Apache-2.0. Guard Input sits directly in front of an LLM step and releases the exact
original text only after a complete, allowed scan; blocked, review, incomplete or
degraded results stop the step. No Patronus CLI is needed.

Assets: installable n8n and Activepieces packages, a Dify package, the Make app
definitions with a provisioning command, the Zapier integration source package and
SHA256 checksums. Source, tests and dependency locks are in `plugins/automations`.

Verified end to end with chatbot and RAG examples (13/13 cases each) on n8n 2.42.4,
Make and Zapier. Dify and Activepieces packages are validated locally against their
SDKs. Make and Zapier are installed through the publisher's invite links or directory
listings; the unsigned Dify package requires an instance policy that permits it.
