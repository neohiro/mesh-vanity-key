#!/usr/bin/env node
// Syntax-checks every JS snippet the browser smoke test passes to
// page.evaluate().
//
// These snippets are assembled from adjacent Python string literals, so a
// misplaced bracket is invisible until Playwright evaluates it -- which only
// happens in CI. That cost a failed required job on a stray closing paren, so
// the same parse now runs locally as part of the pytest suite.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = readFileSync(join(repoRoot, 'tools', 'smoke_browser.py'), 'utf8');

// Every adjacent string-literal group passed to page.evaluate(...).
const groups = src.matchAll(
    /page\.evaluate\(\s*((?:"(?:[^"\\]|\\.)*"\s*)+)\)/g
);

let checked = 0;
const bad = [];
for (const m of groups) {
    const parts = [...m[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1]);
    const js = parts.join('').replace(/\\'/g, "'").replace(/\\"/g, '"');
    const line = src.slice(0, m.index).split('\n').length;
    try {
        // Wrapped so an arrow-function body parses as an expression.
        new Function(`return (${js})`);
        checked++;
    } catch (e) {
        bad.push({ line, message: e.message, js });
    }
}

for (const { line, message, js } of bad) {
    console.error(`  smoke_browser.py:${line}: ${message}`);
    console.error(`    ${js.replace(/\s+/g, ' ').slice(0, 160)}`);
}
console.log(`page.evaluate snippets: ${checked} parsed, ${bad.length} invalid`);
process.exit(bad.length ? 1 : 0);