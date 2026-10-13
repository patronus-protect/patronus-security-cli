#!/usr/bin/env node
// Generates the Make scenario blueprints for the chatbot and RAG examples.
// The Patronus module id depends on the private app name Make assigned at install time:
//   node examples/make/build-blueprints.mjs --app patronus-6yqdb3
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { loadCorpus } from '../data/build-corpus.mjs';

const { values: args } = parseArgs({ options: { app: { type: 'string', default: 'patronus' } } });
const here = new URL('.', import.meta.url);
// Private (custom) apps are addressed as app#<name> in blueprints and connections.
const guardModule = `app#${args.app}:guardInput`;

const at = (x, y = 0) => ({ designer: { x, y } });
const scenarioMetadata = {
  instant: false, version: 1,
  scenario: { roundtrips: 1, maxErrors: 3, autoCommit: true, autoCommitTriggerLast: true, sequential: false, confidential: false, dataloss: false, dlq: false, freshVariables: false },
  designer: { orphans: [] },
};

function setVariables(id, x, variables) {
  return {
    id, module: 'util:SetVariables', version: 1, parameters: { scope: 'roundtrip' },
    mapper: { variables: Object.entries(variables).map(([name, value]) => ({ name, value })), scope: 'roundtrip' },
    metadata: at(x),
  };
}

function returnData(id, x, fields, y = 0) {
  return { id, module: 'scenario-service:ReturnData', version: 2, parameters: {}, mapper: fields, metadata: at(x, y) };
}

// Guard → LLM step → output. The LLM step records the exact released text in the
// "Patronus example LLM log" data store, keyed by case id, so runs can be verified from
// Make and from the API. A Guard error (blocked or unverified) goes to the error handler,
// which records the rejection and skips every later module, including the LLM step.
function logRecord(id, x, y, status, llmInput, retrieved = '') {
  return {
    id, module: 'datastore:AddRecord', version: 1, parameters: { datastore: '{{DATASTORE_ID}}' },
    mapper: { key: '{{var.input.case_id}}', overwrite: true, data: { case_id: '{{var.input.case_id}}', status, llm_input: llmInput, retrieved } },
    metadata: at(x, y),
  };
}

function guardedTail(firstId, x, contentExpression, extraOutputs = {}) {
  const guardId = firstId;
  const llmId = firstId + 1;
  return [
    {
      id: guardId, module: guardModule, version: 1, parameters: { __IMTCONN__: '{{CONNECTION_ID}}' },
      mapper: { content: contentExpression }, metadata: at(x),
      onerror: [
        logRecord(firstId + 3, x, 250, 'rejected', '', extraOutputs.retrieved),
        returnData(firstId + 4, x + 300, {
          status: 'rejected', output: 'Patronus did not release this input. The LLM was not called.',
          error: `{{${guardId}.error.message}}`, case_id: '{{var.input.case_id}}', llm_input: '', ...extraOutputs,
        }, 250),
        { id: firstId + 5, module: 'builtin:Ignore', version: 1, parameters: {}, mapper: {}, metadata: at(x + 600, 250) },
      ],
    },
    // LLM step: records exactly the text released by Patronus Guard. To call a real model,
    // add an LLM module (for example OpenAI or Make AI Toolkit) here mapped to {{guardId.text}}.
    logRecord(llmId, x + 300, 0, 'llm_called', `{{${guardId}.text}}`, extraOutputs.retrieved),
    returnData(firstId + 2, x + 600, {
      status: 'allowed', output: '[llm-stub] received the guarded text', error: '',
      case_id: '{{var.input.case_id}}', llm_input: `{{${guardId}.text}}`, ...extraOutputs,
    }),
  ];
}

function chatbot() {
  return {
    name: 'Patronus example – Chatbot (message → Guard → LLM)',
    flow: guardedTail(1, 0, '{{var.input.message}}'),
    metadata: scenarioMetadata,
  };
}

function rag(documents) {
  // Keyword retrieval over the shared corpus: each document lists its keywords; a document is
  // retrieved when the lower-cased question contains one of them.
  const corpus = JSON.stringify(documents);
  return {
    name: 'Patronus example – RAG (question → retrieval → prompt → Guard → LLM)',
    flow: [
      { id: 1, module: 'json:ParseJSON', version: 1, parameters: { type: '' }, mapper: { json: corpus }, metadata: at(0) },
      {
        id: 2, module: 'util:TextAggregator', version: 1, parameters: { feeder: 1, rowSeparator: '' },
        mapper: { value: '[{{1.id}}]\n{{1.text}}\n\n' }, metadata: at(300),
        filter: {
          name: 'Retrieve matching documents',
          conditions: [[
            { a: '{{lower(var.input.question)}}', b: '{{get(1.keywords; 1)}}', o: 'text:contain' },
          ], [
            { a: '{{lower(var.input.question)}}', b: '{{get(1.keywords; 2)}}', o: 'text:contain' },
          ]],
        },
      },
      setVariables(3, 600, {
        prompt: 'You are the company handbook assistant. Answer the question using only the context below.\n\nContext:\n{{trim(2.text)}}\n\nQuestion: {{var.input.question}}',
      }),
      ...guardedTail(4, 900, '{{3.prompt}}', { retrieved: '{{trim(2.text)}}' }),
    ],
    metadata: scenarioMetadata,
  };
}

const io = {
  chatbot: { input: [{ name: 'case_id', type: 'text', required: false }, { name: 'message', type: 'text', required: true }] },
  rag: { input: [{ name: 'case_id', type: 'text', required: false }, { name: 'question', type: 'text', required: true }] },
};
const output = ['status', 'output', 'error', 'case_id', 'llm_input'].map(name => ({ name, type: 'text' }));

const files = { chatbot: chatbot(), rag: rag(await loadCorpus()) };
for (const [name, blueprint] of Object.entries(files)) {
  const scenarioInterface = { input: io[name].input, output: name === 'rag' ? [...output, { name: 'retrieved', type: 'text' }] : output };
  await writeFile(new URL(`${name}.blueprint.json`, here), `${JSON.stringify({ blueprint, interface: scenarioInterface }, null, 2)}\n`);
  console.log(`wrote examples/make/${name}.blueprint.json`);
}
