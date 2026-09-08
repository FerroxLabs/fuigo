// Read only synthetic corpus and explicitly supplied local model assets.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
const [murage, model, corpusPath, output] = process.argv.slice(2);
if (!output) throw Error('Usage: export-vectors.mjs MURAGE_CHECKOUT LOCAL_MODEL CORPUS OUTPUT');
const root = resolve(murage);
const { MemoryEmbeddings } = await import(pathToFileURL(join(root, 'server/memory/embeddings.ts')));
const manifest = JSON.parse(readFileSync(join(root, 'shared/memory-model-manifest.json')));
const corpus = JSON.parse(readFileSync(corpusPath));
const texts = new Set([...corpus.sources.map(s => s.text), ...corpus.queries.map(q => q.query)]);
const max = Math.max(...corpus.queries.map(q => q.distractorCount ?? 0));
for (let n=0;n<max;n++) texts.add(`Unrelated inventory item ${n}: warehouse shelf and packing material.`);
const provider = new MemoryEmbeddings(resolve(model), manifest);
const vectors = {};
try {
  await provider.load(); // Verifies all file hashes; remote download disabled.
  const all = [...texts];
  for (let i=0;i<all.length;i+=16) {
    const batch=all.slice(i,i+16), embedded=await provider.embed(batch);
    batch.forEach((text,n) => { vectors[text]=embedded[n]; });
  }
  writeFileSync(output, JSON.stringify({corpus,identity:provider.identity,dimensions:manifest.dimensions,manifest,vectors}), {mode:0o600,flag:'wx'});
  console.log(`Exported ${all.length} real local vectors; no API calls`);
} finally { await provider.close(); }
