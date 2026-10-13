# Zapier examples: chatbot and RAG with Patronus Guard

Two Zaps that put the Patronus **Guard Input** action directly in front of the LLM step.

| Zap | Steps |
|---|---|
| Chatbot | Webhooks by Zapier **Catch Raw Hook** → Code by Zapier (`parse-request.code.js`) → Patronus **Guard Input** (`message`) → LLM step |
| RAG | **Catch Raw Hook** → Code by Zapier (`rag-retrieve.code.js`: parse, keyword retrieval, prompt) → Storage `retrieved:{case_id}` → Patronus **Guard Input** (`prompt`) → LLM step |

The LLM step in both Zaps is Storage by Zapier **Set Value** with key `llm:{case_id}` and
the Guard's **Protected Text** as value, so every LLM input can be verified. To call a
real model, add your LLM action after Guard Input and map **Protected Text**. When Guard
Input blocks or cannot verify the input, the step errors and Zapier skips every later
step, so the LLM step never runs.

Zapier has no vector store, so the RAG Zap uses keyword retrieval over the shared corpus
(five clean and three poisoned handbook pages), generated into `rag-retrieve.code.js`.

## Build the Zaps

Requirements: a Zapier plan with multi-step Zaps and Webhooks (Professional or the trial),
the private Patronus integration, a Patronus API key and a Storage by Zapier secret.

1. Push the private integration from a copy of `plugins/automations/zapier` with a
   [deploy key](https://developer.zapier.com/partner-settings/deploy-keys/) in
   `ZAPIER_DEPLOY_KEY`: `zapier-platform register "Patronus"`, then `zapier-platform push`.
   A new integration must start at version 1.0.0; smaller versions are rejected.
2. Chatbot Zap: Catch Raw Hook → Run Javascript with `parse-request.code.js`
   (Input Data `raw_body` = Raw Body) → Patronus Guard Input (RAG / LLM Input = `Message`)
   → Storage Set Value (Key `llm:` + `Case Id`, Value = `Protected Text`).
3. RAG Zap: Catch Raw Hook → Run Javascript with `rag-retrieve.code.js` (`raw_body`) →
   Storage Set Value (`retrieved:` + `Case Id`, Value = `Retrieved`) → Guard Input
   (`Prompt`) → Storage Set Value (`llm:` + `Case Id`, Value = `Protected Text`).
4. Publish both Zaps and put the hook URLs into `ZAPIER_HOOK_CHATBOT` and `ZAPIER_HOOK_RAG`.

Regenerate the RAG code after corpus changes with `node examples/zapier/build-code-steps.mjs`.

## Verify

```sh
ZAPIER_HOOK_CHATBOT=… ZAPIER_HOOK_RAG=… ZAPIER_STORAGE_SECRET=… node examples/zapier/verify.mjs
```

The script posts every shared case to the hooks, then reads Storage by Zapier: allowed
cases must reach the LLM step with exactly the guarded text, rejected cases must never
reach it, and RAG cases must retrieve the expected document.

## Zapier platform notes found while testing

- The plain **Catch Hook** trigger expands JSON-looking string values into sub-fields,
  so a chat message such as `{"order": "NL-204"}` arrives empty. Guard Input then fails
  closed (nothing is released), but legitimate JSON-like prompts cannot pass. Use
  **Catch Raw Hook** and parse the body in a Code step.
- The Zapier runtime loads `index.js` from the package root and ignores `package.json`
  `main`; the package ships a root `index.js` that re-exports `dist/index.js`.

## Results

| Date | Plan | Chatbot | RAG | Notes |
|---|---|---|---|---|
| 2026-10-07 | Professional trial | 6/6 | 7/7 | Runs via Catch Raw Hook; blocked runs show as errored at Guard Input in Zap History with the LLM step skipped |
