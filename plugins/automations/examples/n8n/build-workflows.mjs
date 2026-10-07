#!/usr/bin/env node
// Generates the importable n8n example workflows from the shared test corpus.
// Run after changing examples/data/corpus: node examples/n8n/build-workflows.mjs
import { writeFile } from 'node:fs/promises';
import { loadCorpus } from '../data/build-corpus.mjs';

const here = new URL('.', import.meta.url);

const PATRONUS_CREDENTIAL = { patronusApi: { id: 'patronusLocalApi', name: 'Patronus API' } };
const OLLAMA_CREDENTIAL = { ollamaApi: { id: 'ollamaLocal', name: 'Ollama (local)' } };
const LLM_URL = 'http://127.0.0.1:4100/v1/chat/completions';
const LLM_MODEL = 'llm-stub';

const corpus = async () => (await loadCorpus()).map(({ id, text }) => ({ id, text }));

const node = (name, type, typeVersion, position, parameters, extra = {}) => ({
  id: `patronus-${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`, name, type, typeVersion, position, parameters, ...extra,
});
const assign = (name, value, type = 'string') => ({ id: name, name, value, type });
const set = (name, position, assignments) => node(name, 'n8n-nodes-base.set', 3.4, position, {
  assignments: { assignments }, options: {},
});
const main = (...targets) => ({ main: targets.map(list => list.map(target => ({ node: target, type: 'main', index: 0 }))) });
const ai = (type, target) => ({ [type]: [[{ node: target, type, index: 0 }]] });

function entryNodes(flow, title) {
  return [
    node('Chat', '@n8n/n8n-nodes-langchain.chatTrigger', 1.5, [0, 0], {
      public: true, mode: 'hostedChat', options: { responseMode: 'lastNode', title, inputPlaceholder: 'Type a message…' },
    }, { webhookId: `patronus-${flow}-chat` }),
    node('Webhook', 'n8n-nodes-base.webhook', 2.1, [0, 200], {
      httpMethod: 'POST', path: `patronus-${flow}`, responseMode: 'lastNode', options: {},
    }, { webhookId: `patronus-${flow}-webhook` }),
  ];
}

function guardNodes(x, contentExpression, extraOutputs) {
  return [
    node('Patronus Guard', 'n8n-nodes-patronus.patronus', 1, [x, 100], { operation: 'guard', content: contentExpression },
      { credentials: PATRONUS_CREDENTIAL, onError: 'continueRegularOutput' }),
    node('Released?', 'n8n-nodes-base.if', 2.2, [x + 220, 100], {
      conditions: {
        options: { caseSensitive: true, leftValue: '', typeValidation: 'strict', version: 2 },
        combinator: 'and',
        conditions: [{ id: 'released', leftValue: '={{ $json.patronus?.status }}', rightValue: 'allowed', operator: { type: 'string', operation: 'equals' } }],
      },
      options: {},
    }),
    // The LLM receives the text released by Patronus Guard, never the pre-guard input.
    node('LLM', 'n8n-nodes-base.httpRequest', 4.2, [x + 440, 0], {
      method: 'POST', url: "={{ $('Input').first().json.llm_url }}",
      sendHeaders: true, headerParameters: { parameters: [{ name: 'x-case-id', value: "={{ $('Input').first().json.case_id }}" }] },
      sendBody: true, specifyBody: 'json',
      jsonBody: "={{ JSON.stringify({ model: $('Input').first().json.llm_model, user: $('Input').first().json.case_id, messages: [{ role: 'user', content: $('Patronus Guard').first().json.text }] }) }}",
      options: { timeout: 120000 },
    }),
    set('Reply', [x + 660, 0], [
      assign('output', '={{ $json.choices[0].message.content }}'),
      assign('status', 'allowed'),
      assign('case_id', "={{ $('Input').first().json.case_id }}"),
      assign('llm_input', "={{ $('Patronus Guard').first().json.text }}"),
      assign('patronus_job_ids', "={{ $('Patronus Guard').first().json.patronus.job_ids }}", 'array'),
      ...extraOutputs,
    ]),
    set('Rejected', [x + 440, 200], [
      assign('output', "=Patronus did not release this input ({{ $('Patronus Guard').first().json.status }}). The LLM was not called."),
      assign('status', "={{ $('Patronus Guard').first().json.status }}"),
      assign('error', "={{ $('Patronus Guard').first().json.error }}"),
      assign('case_id', "={{ $('Input').first().json.case_id }}"),
      ...extraOutputs,
    ]),
  ];
}

function guardConnections() {
  return {
    'Patronus Guard': main(['Released?']),
    'Released?': main(['LLM'], ['Rejected']),
    LLM: main(['Reply']),
  };
}

function inputNode(field) {
  return set('Input', [220, 100], [
    assign('case_id', '={{ $json.body?.case_id ?? $json.sessionId }}'),
    assign(field, `={{ $json.body?.${field} ?? $json.chatInput }}`),
    assign('llm_url', LLM_URL),
    assign('llm_model', LLM_MODEL),
  ]);
}

function chatbot() {
  return {
    name: 'Patronus example – Chatbot (message → Guard → LLM)',
    nodes: [...entryNodes('chatbot', 'Patronus Guard Chatbot'), inputNode('message'), ...guardNodes(440, '={{ $json.message }}', [])],
    connections: { Chat: main(['Input']), Webhook: main(['Input']), Input: main(['Patronus Guard']), ...guardConnections() },
    settings: { executionOrder: 'v1' },
    pinData: {},
  };
}

function rag(documents) {
  const retrieved = assign('retrieved', "={{ $('Compose prompt').first().json.retrieved }}", 'array');
  const loader = (name, position) => node(name, '@n8n/n8n-nodes-langchain.documentDefaultDataLoader', 1.1, position, {
    dataType: 'json', jsonMode: 'expressionData', jsonData: '={{ $json.text }}', textSplittingMode: 'custom',
    options: { metadata: { metadataValues: [{ name: 'doc_id', value: '={{ $json.id }}' }] } },
  });
  const embeddings = (name, position) => node(name, '@n8n/n8n-nodes-langchain.embeddingsOllama', 1, position,
    { model: 'nomic-embed-text:latest' }, { credentials: OLLAMA_CREDENTIAL });
  const memoryKey = { __rl: true, mode: 'id', value: 'patronus_rag_example' };
  return {
    name: 'Patronus example – RAG (question → retrieval → prompt → Guard → LLM)',
    nodes: [
      ...entryNodes('rag', 'Patronus Guard RAG'),
      inputNode('question'),
      node('Corpus', 'n8n-nodes-base.code', 2, [440, 100], {
        jsCode: `// Example handbook corpus (clean and poisoned documents), generated from examples/data/corpus.\nreturn ${JSON.stringify(documents, null, 2)}.map(json => ({ json }));`,
      }),
      node('Index corpus', '@n8n/n8n-nodes-langchain.vectorStoreInMemory', 1.3, [660, 100], { mode: 'insert', memoryKey, clearStore: true }),
      embeddings('Embeddings (index)', [600, 320]),
      loader('Document loader', [760, 320]),
      node('Splitter', '@n8n/n8n-nodes-langchain.textSplitterRecursiveCharacterTextSplitter', 1, [760, 500], { chunkSize: 2000, chunkOverlap: 0, options: {} }),
      node('Retrieve', '@n8n/n8n-nodes-langchain.vectorStoreInMemory', 1.3, [960, 100], {
        mode: 'load', memoryKey, prompt: "={{ $('Input').first().json.question }}", topK: 2, includeDocumentMetadata: true,
      }, { executeOnce: true }),
      embeddings('Embeddings (query)', [960, 320]),
      node('Compose prompt', 'n8n-nodes-base.code', 2, [1180, 100], {
        jsCode: [
          "const question = $('Input').first().json.question;",
          'const hits = $input.all().map(item => item.json.document);',
          "const context = hits.map((doc, i) => `[${i + 1}] (${doc.metadata.doc_id})\\n${doc.pageContent}`).join('\\n\\n');",
          "const prompt = `You are the company handbook assistant. Answer the question using only the context below.\\n\\nContext:\\n${context}\\n\\nQuestion: ${question}`;",
          'return [{ json: { prompt, retrieved: hits.map(doc => doc.metadata.doc_id) } }];',
        ].join('\n'),
      }),
      ...guardNodes(1400, '={{ $json.prompt }}', [retrieved]),
    ],
    connections: {
      Chat: main(['Input']), Webhook: main(['Input']), Input: main(['Corpus']), Corpus: main(['Index corpus']),
      'Index corpus': main(['Retrieve']), Retrieve: main(['Compose prompt']), 'Compose prompt': main(['Patronus Guard']),
      'Embeddings (index)': ai('ai_embedding', 'Index corpus'),
      'Document loader': ai('ai_document', 'Index corpus'),
      Splitter: ai('ai_textSplitter', 'Document loader'),
      'Embeddings (query)': ai('ai_embedding', 'Retrieve'),
      ...guardConnections(),
    },
    settings: { executionOrder: 'v1' },
    pinData: {},
  };
}

const workflows = {
  'chatbot.workflow.json': { id: 'patronusChatbot1', workflow: chatbot() },
  'rag.workflow.json': { id: 'patronusRagFlow1', workflow: rag(await corpus()) },
};
for (const [file, { id, workflow }] of Object.entries(workflows)) {
  await writeFile(new URL(file, here), `${JSON.stringify({ id, active: false, ...workflow }, null, 2)}\n`);
  console.log(`wrote examples/n8n/${file}`);
}
