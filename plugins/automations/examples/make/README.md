# Make examples: chatbot and RAG with Patronus Guard

Two Make scenarios that put the Patronus **Guard Input** module directly in front of the LLM step.

| Scenario | Flow |
|---|---|
| `chatbot.blueprint.json` | Scenario input `message` → Patronus Guard Input → LLM step → Return output (Guard error → rejection record → Return output → Ignore) |
| `rag.blueprint.json` | Scenario input `question` → Parse JSON (corpus) → Text aggregator with keyword filter (retrieval) → Set prompt → Patronus Guard Input → LLM step → Return output (Guard error → rejection record → …) |

The LLM step records the exact text released by Patronus Guard (`{{guard.text}}`) in the
**Patronus example LLM log** data store, keyed by case id. To call a real model, add an
LLM module (for example OpenAI or Make AI Toolkit) after Guard Input and map it to the
Guard's `text` output. A blocked or unverified input raises a Guard error; the error
handler writes a `rejected` record and no later module runs, so the LLM is never called.

Make has no vector store, so the RAG example uses keyword retrieval over
`../data/corpus.json`: a document is retrieved when the lower-cased question contains one
of its keywords. The corpus contains five clean and three poisoned handbook pages.

## Run

Requirements: a Make account (the free plan works), `MAKE_API_TOKEN` with all scopes,
`MAKE_ZONE` (for example `eu1.make.com`) and `MAKE_TEAM_ID` in the environment or the
repository `.env`.

```sh
node make/install.mjs --zone eu1.make.com --apply        # private Patronus app, prints its name, e.g. patronus-6yqdb3
```

Create the Patronus connection once in the Make editor (add **Patronus → Guard Input** to
any scenario and choose **Create a connection**), then note its id from
`GET /api/v2/connections?teamId=…`.

```sh
node examples/make/build-blueprints.mjs --app patronus-6yqdb3
node examples/make/run.mjs deploy --connection <connection id>   # creates/updates scenarios and the LLM log store
node examples/make/run.mjs verify                                # runs all shared cases
```

`run.mjs` keeps the scenario and data store ids in `tmp/make-examples.json` and updates
existing scenarios on later deploys.

## Make platform notes found while testing

- Private apps get a suffixed name (`patronus-6yqdb3`) and are addressed as
  `app#patronus-6yqdb3` in blueprints and connections.
- Module names must be alphanumeric (`guardInput`), and mappable inputs belong in the
  module's `expect` section.
- Connection checks must answer with 2xx; any 4xx fails before `valid` is evaluated.
- IML compares `===`/`!==` loosely (`1 !== true` is false) and `createJSON()` returns no
  value for numbers. The Guard release condition avoids both.
- `POST /scenarios/{id}/run` with `responsive: true` returns only `executionId` and
  `status`, not the scenario outputs; verification therefore reads the LLM log store.

## Results

| Date | Zone | Chatbot | RAG | Notes |
|---|---|---|---|---|
| 2026-10-07 | eu1.make.com (free plan) | 6/6 | 7/7 | Runs via the Make API; allowed and rejected executions inspected in Make's scenario history |
