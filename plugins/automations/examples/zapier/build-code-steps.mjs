#!/usr/bin/env node
// Generates the Code by Zapier (JavaScript) step used by the RAG Zap from the shared corpus.
// Paste examples/zapier/rag-retrieve.code.js into the Code step; map Input Data `raw_body`.
import { writeFile } from 'node:fs/promises';
import { loadCorpus } from '../data/build-corpus.mjs';

const corpus = (await loadCorpus()).map(({ id, keywords, text }) => ({ id, keywords, text }));
const code = `// Patronus RAG example for a "Catch Raw Hook" trigger: parse the request, run keyword
// retrieval over the example handbook corpus and assemble the prompt.
// Input Data: raw_body (map "Raw Body" from step 1).
// Output: case_id, question, prompt (map into Patronus Guard Input) and retrieved (document ids).
const corpus = ${JSON.stringify(corpus)};
const body = JSON.parse(inputData.raw_body || '{}');
const question = typeof body.question === 'string' ? body.question : '';
const lower = question.toLowerCase();
const hits = corpus.filter(doc => doc.keywords.some(keyword => lower.includes(keyword)));
const context = hits.map(doc => '[' + doc.id + ']\\n' + doc.text).join('\\n\\n');
const prompt = 'You are the company handbook assistant. Answer the question using only the context below.\\n\\nContext:\\n' + context + '\\n\\nQuestion: ' + question;
output = { case_id: typeof body.case_id === 'string' ? body.case_id : '', question, prompt, retrieved: hits.map(doc => doc.id).join(',') };
`;
await writeFile(new URL('rag-retrieve.code.js', import.meta.url), code);
console.log('wrote examples/zapier/rag-retrieve.code.js');
