# Patronus for Make

Native Make custom-app definitions using a basic API-key connection and action
modules. Requests go directly to the account API. There is no executable plugin
runtime and no Patronus CLI dependency.

## Provision the app without manual JSON assembly

For publisher/fork-maintainer setup, unpack the Make release archive and run:

```sh
node install.mjs --app-name patronus-yourcompany --zone eu1.make.com
```

This is a dry run. It shows the complete native API plan and performs no writes.
To create the app, set `MAKE_API_TOKEN` in your environment with Make's
`sdk-apps:write` scope, then add `--apply`. Use your actual Make zone. The installer
creates a new private app, its base, an API-key connection and all five modules,
including their parameters and output interfaces. It binds the connection name
returned by Make and stops on any error; it does not overwrite an existing app.
A failed setup can leave a partial private app in the owner account.

The Make SDK token is a publisher credential. End users subsequently enter their
**Patronus API key** in the native Make connection. They should install through
the publisher's verified app invite/listing link, not run this developer setup.
That public link is not yet registered. See [public distribution](../PUBLISHING.md).

The installer follows [Make SDK app](https://developers.make.com/api-documentation/api-reference/sdk-apps),
[connection](https://developers.make.com/api-documentation/api-reference/sdk-apps/connections)
and [module](https://developers.make.com/api-documentation/api-reference/sdk-apps/modules)
contracts. It requires Node.js 22+ and no additional npm dependency. Original JSON
components remain editable Open Source files for forks and contributions.

## Connection and scenario

Create the connection with an account API key carrying `scan:write` and
`scan:read`. The password field masks the key. The connection checks read access
via GET of a missing job: authenticated 404 is expected and no billable scan is
submitted. Base masks Authorization, request bodies and response bodies in the
custom app's communication logs. Scenario outputs can still contain evidence.

Submit Text / URL / MCP Scan sends the exact mapped Content. The API body is
returned unchanged: an accepted submission contains `jobs[].job_id`; an immediate
flat completion contains `job_id`. Both fields appear in the module interface.
Map the appropriate ID to Get Scan Result. For multiple jobs, use an Iterator
and evaluate each job. Delay/repeat with a bounded scenario flow while running;
enforce [the completed-result policy](../README.md#workflow-behavior) using a
Router/filter before the downstream consumer. 401/403 fail the connection/request;
429 raises a rate-limit error. Apply `Retry-After` and do not blindly resubmit a
timed-out POST.

Local tests validate definitions and request mapping. Make's proprietary IML
runtime and an installed scenario still require testing in your Make account.

## Guard Input: connect directly before the LLM

Choose **Guard Input** and map the exact assembled RAG/prompt text into Content.
The step submits and polls internally, then releases only fully approved text.
Map the output `text` into the downstream LLM; in Dify use `protected_text`.
Blocked, review, incomplete, quota and timeout results stop the step without
returning the original input. Keep stop-on-error and do not use a source fallback.

The older Submit/Get actions are diagnostic operations. For the directly
connected protection path use Guard Input. See [the shared flow and test guide](../README.md#connect-rag--llm-input).

Guard Input uses only native IML built-ins and an internal POST/GET/validation sequence. It does not require custom IML-function enablement or a separate guard service.
