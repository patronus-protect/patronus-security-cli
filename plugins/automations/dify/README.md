# Patronus for Dify

Native Python tool provider with Submit Scan and Get Scan Result. Requires Python
3.12+ and `dify-plugin==0.10.2`. The repository build bundles the existing Python
API client as `patronus_api_client/`; no Patronus SDK publication or CLI install
is required in Dify.

## Install and connect

Build/package from [the parent directory](../README.md). The generated
`patronus-dify-0.1.1.difypkg` is an **unsigned development package**. Install it via
Plugins → Install from local file on an instance whose existing plugin policy
permits such packages. Instances requiring trusted signatures need their normal
signing/review process; this change does not alter signature verification or
publish to Dify Marketplace. The package format follows the
[official daemon packager](https://github.com/langgenius/dify-plugin-daemon/blob/main/pkg/plugin_packager/packager/packager.go).

Configure the provider with an account API key carrying `scan:write` and
`scan:read`. The field is a required `secret-input`. Validation checks read
access with a missing-job GET, sending no workflow content and consuming no scan
units. Write access is checked by Submit Scan.

## Use in a workflow

Place Submit Scan after the input/source node. Select the scan type and map the
exact text or public HTTPS URL into Content. The tool emits a JSON submission
with public job IDs. For accepted jobs, call Get Scan Result in a bounded delayed
loop, then use an IF/ELSE node to enforce
[the completed-result policy](../README.md#workflow-behavior) before the LLM node.
Pin this sequence in the workflow rather than relying on an agent to choose
whether to run the tool. API evidence is untrusted input.

Provider/API failures raise sanitized errors; they never yield a clean verdict.
These tools are explicit workflow actions and do not automatically inspect all
Dify prompts or tool results. All scan content goes to the account API.

## Guard Input: connect directly before the LLM

Choose **Guard Input** and map the exact assembled RAG/prompt text into Content.
The step submits and polls internally, then releases only fully approved text.
Map the output `text` into the downstream LLM; in Dify use `protected_text`.
Blocked, review, incomplete, quota and timeout results stop the step without
returning the original input. Keep stop-on-error and do not use a source fallback.

The older Submit/Get actions are diagnostic operations. For the directly
connected protection path use Guard Input. See [the shared flow and test guide](../README.md#connect-rag--llm-input).
