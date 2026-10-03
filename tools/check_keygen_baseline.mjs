// Compare a measured keygen-scaling run against the committed baseline.
//
// This is NOT a pass/fail gate on absolute keys/s. GitHub's shared runners
// vary substantially between invocations - the same job can land on a busy or
// an idle host - so any fixed absolute threshold would be flaky by
// construction and would eventually train everyone to ignore it.
//
// What IS meaningful is a same-runner comparison against a baseline recorded
// on the same runner class. That catches the failure that matters: throughput
// collapsing because of a wasm change, a dependency bump, or a regression in
// the worker loop.
//
// A large DROP fails. A large RISE is reported but passes, because a
// genuinely faster baseline should be adopted deliberately (it means the
// scaling table needs re-measuring) rather than by a machine that picked a
// quieter host.
//
// Usage: node tools/check_keygen_baseline.mjs [measured-output-file]

import fs from 'node:fs';
import path from 'node:path';

const REPORT = process.argv[2];
const BASELINE = path.join(process.cwd(), 'tools', 'keygen_baseline.json');

// Fail below this fraction of baseline. Loose on purpose: this is a smoke
// alarm for "the maths got much slower", not a performance budget.
const DROP_TOLERANCE = 0.6;
// Report above this, but do not fail.
const RISE_NOTICE = 1.5;

function parseReport(text) {
    const rates = new Map();
    for (const line of text.split(/\r?\n/)) {
        const m = line.match(/^\s*(\d+)\s+thread\(s\):\s*([\d,]+)\s+keys\/s/);
        if (m) rates.set(Number(m[1]), Number(m[2].replace(/,/g, '')));
    }
    return rates;
}

if (!REPORT) {
    console.error('usage: node tools/check_keygen_baseline.mjs <bench output file>');
    process.exit(2);
}
if (!fs.existsSync(REPORT)) {
    console.error(`no benchmark output at ${REPORT}`);
    process.exit(2);
}

const measured = parseReport(fs.readFileSync(REPORT, 'utf8'));
if (measured.size === 0) {
    console.error('could not parse any "N thread(s): R keys/s" lines from the benchmark');
    console.error('--- raw output ---');
    console.error(fs.readFileSync(REPORT, 'utf8'));
    process.exit(2);
}

console.log('parsed measured rates:');
for (const [n, r] of measured) console.log(`  ${n} thread(s): ${Math.round(r).toLocaleString()} keys/s`);

if (!fs.existsSync(BASELINE)) {
    // First run: record rather than fail, so enabling the schedule cannot turn
    // the branch red before there is anything to compare against.
    fs.writeFileSync(BASELINE, JSON.stringify({
        _note: 'Recorded from tools/bench_keygen_scaling.mjs on a GitHub-hosted ' +
            'ubuntu runner. Updated by hand or by deleting the file and letting ' +
            'the next run rewrite it. Only drop-detection is enforced; a rise ' +
            'should be reviewed so the scaling table can be re-measured.',
        recorded_on: new Date().toISOString(),
        rates: Object.fromEntries(measured),
    }, null, 2) + '\n', 'utf8');
    console.log(`\nno baseline found - wrote ${BASELINE}. Re-run to compare.`);
    process.exit(0);
}

const baseline = JSON.parse(fs.readFileSync(BASELINE, 'utf8')).rates || {};

let worst = null;
const notes = [];
for (const [n, r] of measured) {
    const b = baseline[n];
    if (!b) { notes.push(`  ${n} thread(s): no baseline to compare`); continue; }
    const ratio = r / b;
    const line = `  ${n} thread(s): ${(ratio * 100).toFixed(0)}% of baseline `
        + `(${Math.round(r).toLocaleString()} vs ${Math.round(b).toLocaleString()})`;
    if (ratio < DROP_TOLERANCE) {
        if (!worst || ratio < worst.ratio) worst = { n, ratio, b, r };
    } else if (ratio > RISE_NOTICE) {
        notes.push(line + '  <- notably faster; consider re-measuring the scaling table');
    }
}

if (notes.length) {
    console.log('\nnotes:');
    for (const n of notes) console.log(n);
}

if (worst) {
    console.error(
        `\nFAIL: ${worst.n} thread(s) produced only ${(worst.ratio * 100).toFixed(0)}% `
        + `of the baseline (${Math.round(worst.r).toLocaleString()} vs `
        + `${Math.round(worst.b).toLocaleString()} keys/s). Real keygen got much `
        + 'slower - check for a wasm, dependency or worker-loop regression.');
    process.exit(1);
}

console.log('\nOK: throughput within tolerance of the baseline.');
