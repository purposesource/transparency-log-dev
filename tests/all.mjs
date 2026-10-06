// `node --test tests/`: from Node 21 on the test runner treats each argument as a file or glob,
// so the directory is loaded as a package and its main is this file, which loads every
// *.test.mjs here. (Node 20 searches the directory itself and runs the same files.)

import { readdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
for (const file of readdirSync(here).filter((f) => f.endsWith('.test.mjs')).sort()) {
  await import(pathToFileURL(`${here}/${file}`).href);
}
