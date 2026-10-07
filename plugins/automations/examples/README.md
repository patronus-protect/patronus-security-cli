# Patronus automation examples

A chatbot and a RAG example for **n8n**, **Make** and **Zapier**. Each puts the Patronus
Guard Input step directly in front of the LLM: allowed input reaches the LLM exactly as
guarded; blocked, review or unverified input never reaches it.

| Platform | Examples | How it runs | Verified |
|---|---|---|---|
| [n8n](n8n/README.md) | `chatbot.workflow.json`, `rag.workflow.json` (vector store + Ollama embeddings) | Locally without Docker, community node installed from the package | 13/13 |
| [Make](make/README.md) | `chatbot.blueprint.json`, `rag.blueprint.json` (keyword retrieval) | Private Make app, scenarios run via the Make API | 13/13 |
| [Zapier](zapier/README.md) | Chatbot and RAG Zaps (Catch Raw Hook + Code steps) | Private Zapier integration, Zaps triggered by webhook | 13/13 |

Shared test data lives in [`data/`](data): `cases.json` (6 chatbot and 7 RAG cases, clean
and malicious, including Unicode and JSON-like text) and `corpus/` (five clean and three
poisoned handbook pages with indirect prompt injection, a hidden HTML-comment instruction
and synthetic credentials). [`llm-stub/`](llm-stub/server.mjs) is a recording
OpenAI-compatible LLM service for local runs; it can forward to Ollama via `LLM_UPSTREAM`.

Every platform verifier proves the same contract: allowed cases reach the LLM step once
with exactly the guarded text, rejected cases never reach it, and RAG cases retrieved the
expected (clean or poisoned) document.

Pending: real-LLM runs on Make and Zapier (both use a logging LLM step), and publisher
registrations for public listings.
