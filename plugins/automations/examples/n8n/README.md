# n8n examples: chatbot and RAG with Patronus Guard

Two importable workflows that put **Patronus Guard Input** directly in front of the LLM:

| Workflow | Flow |
|---|---|
| `chatbot.workflow.json` | Chat Trigger / Webhook → Patronus Guard → Released? → LLM → Reply (otherwise → Rejected) |
| `rag.workflow.json` | Chat Trigger / Webhook → Corpus → Index (in-memory vector store, Ollama `nomic-embed-text`) → Retrieve top 2 → Compose prompt → Patronus Guard → Released? → LLM → Reply (otherwise → Rejected) |

The LLM node always sends `$('Patronus Guard').first().json.text`, the text released by
the guard, never the pre-guard input. Blocked or unverified input goes to **Rejected**
and the LLM node is not executed.

Both workflows use the same shared cases (`../data/cases.json`) and corpus
(`../data/corpus/`, five clean and three poisoned handbook pages).

## Run locally (no Docker)

Requirements: Node ≥ 24, Ollama with `nomic-embed-text` (RAG only), and
`PATRONUS_API_KEY` in the environment or the repository `.env`.

```sh
examples/n8n/run-local.sh setup   # n8n 2.42.4 runtime, Patronus node package, credentials, workflows
examples/n8n/run-local.sh stub    # terminal 1: recording LLM stub on 127.0.0.1:4100
examples/n8n/run-local.sh start   # terminal 2: n8n on http://localhost:5678
node examples/n8n/verify.mjs      # terminal 3: run all cases
```

`setup` installs the node exactly like a community package (`npm pack` of
`plugins/automations/n8n` installed into `~/.n8n/nodes` of `tmp/n8n-home`). n8n is
installed without native build scripts; `sqlite3` is rebuilt and the expression engine
is set to `legacy`, because `isolated-vm` does not compile on Node 25.

The chatbot is also available as n8n's hosted chat at
`http://localhost:5678/webhook/patronus-chatbot-chat/chat` (RAG: `patronus-rag-chat`).

## Using a real LLM

The stub can forward to Ollama and still record every call:

```sh
LLM_UPSTREAM=http://127.0.0.1:11434 examples/n8n/run-local.sh stub
```

Then set `llm_model` in the workflow's **Input** node to an installed model, for
example `qwen3.5:0.8b`.

## What `verify.mjs` checks

- allowed input: status `allowed`, exactly one LLM call for the case, and the LLM's
  last message equals the guarded text (chatbot: equals the chat message; RAG:
  contains the question)
- rejected input: status `blocked` or `unverified`, zero LLM calls
- RAG: the expected document was retrieved, so poisoned cases really fed poisoned context

## Results

| Date | n8n | Chatbot | RAG | Notes |
|---|---|---|---|---|
| 2026-10-07 | 2.42.4 (Node 25.9, no Docker) | 6/6 | 7/7 | Webhook runs via `verify.mjs`; chatbot also checked by hand in n8n's hosted chat (clean → LLM, injection → blocked) and RAG executions inspected in the n8n editor |
