#!/usr/bin/env node
// Writes corpus.json (id, keywords, text) from corpus/*.md for platforms without a
// vector store (Make, Zapier). Front matter labels stay out of the indexed text.
import { readdir, readFile, writeFile } from 'node:fs/promises';

const dir = new URL('./corpus/', import.meta.url);

export async function loadCorpus() {
  const files = (await readdir(dir)).filter(name => name.endsWith('.md')).sort();
  return Promise.all(files.map(async name => {
    const raw = await readFile(new URL(name, dir), 'utf8');
    const match = /^---\n([\s\S]*?)\n---\n/.exec(raw);
    const field = key => new RegExp(`^${key}:\\s*(.+)$`, 'm').exec(match?.[1] ?? '')?.[1]?.trim();
    return {
      id: field('id') ?? name.replace(/\.md$/, ''),
      keywords: (field('keywords') ?? '').split(',').map(word => word.trim().toLowerCase()).filter(Boolean),
      text: raw.slice(match ? match[0].length : 0).trim(),
    };
  }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await writeFile(new URL('./corpus.json', import.meta.url), `${JSON.stringify(await loadCorpus(), null, 2)}\n`);
  console.log('wrote examples/data/corpus.json');
}
