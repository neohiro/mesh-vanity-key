// Real-keygen scaling: aggregate keys/s vs thread count, using the ACTUAL
// libsodium.wasm that ships with the page.
//
// WHY THIS EXISTS. tools/bench_worker_scaling.mjs uses a synthetic ALU+table
// workload, because a Node thread pool cannot reproduce Web Worker scheduling.
// That synthetic probe measured ~6x at 8 threads, and it is misleading: the
// workload is ILP-friendly with a small working set. This bench runs the same
// crypto the browser runs, so it captures SMT contention for the REAL workload.
//
// Measured on the calibration host (i3-10105, 4 physical / 8 logical):
//
//     1 thread    23,934 keys/s   1.00x
//     2 threads   47,157 keys/s   1.97x
//     4 threads   81,885 keys/s   3.42x
//     8 threads   97,555 keys/s   4.08x   (19% better than 4)
//
// Two things follow. First, saturating every LOGICAL core is correct - SMT
// siblings still add ~19%, so detectOptimalWorkers() using hardwareConcurrency
// is right and there is no headroom left on this axis. Second, real keygen
// scales ~4x, NOT the 2.3x recorded in WORKER_SCALE_MEASURED and not the ~6x the
// synthetic probe suggests; see the MEASUREMENT BASIS comment in index.html.
//
// It is still NOT a browser measurement (no event loop, no UI thread, no
// postMessage per report), so it corroborates rather than replaces a browser
// run.
//
// Usage: node tools/bench_keygen_scaling.mjs [libsodium.js]

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { isMainThread, parentPort, workerData, Worker } from 'node:worker_threads';
import os from 'node:os';
import path from 'node:path';

const ENTRY = fileURLToPath(import.meta.url);
const TRIAL_MS = 2000;
const TRIALS = 3;

if (isMainThread) {
    const libPath = path.resolve(process.argv[2] || 'libsodium.js');
    const require = createRequire(import.meta.url);
    // Prove the module loads in the parent before spawning anything.
    const s = require(libPath);
    await s.ready;

    const logical = os.cpus().length;
    console.log(`logical CPUs: ${logical}`);
    console.log('workload: real crypto_sign_seed_keypair, N OS threads\n');

    const counts = [1, 2, 4, 8].filter((n) => n <= logical);
    if (!counts.includes(1)) counts.unshift(1);

    async function runConcurrent(count) {
        const t0 = Date.now();
        const results = await Promise.all(
            Array.from({ length: count }, () => new Promise((resolve, reject) => {
                const w = new Worker(ENTRY, { workerData: { libPath, ms: TRIAL_MS } });
                w.on('message', (m) => { resolve(m); w.terminate(); });
                w.on('error', reject);
            }))
        );
        const elapsed = (Date.now() - t0) / 1000;
        const keys = results.reduce((a, m) => a + m.keys, 0);
        return { keys, elapsed, rate: keys / elapsed };
    }

    const rates = new Map();
    for (const n of counts) {
        await runConcurrent(n);                    // warm up
        let best = 0;
        for (let t = 0; t < TRIALS; t++) {
            const r = await runConcurrent(n);
            if (r.rate > best) best = r.rate;
        }
        rates.set(n, best);
        console.log(`  ${String(n).padStart(2)} thread(s): ${Math.round(best).toLocaleString()} keys/s`);
    }

    const one = rates.get(1);
    console.log('\nscaling vs a single thread:');
    let bestN = 1, bestRate = one;
    for (const n of counts) {
        if (n === 1) continue;
        const f = rates.get(n) / one;
        console.log(`  ${String(n).padStart(2)} threads: ${f.toFixed(2)}x`);
        if (rates.get(n) > bestRate) { bestRate = rates.get(n); bestN = n; }
    }
    console.log(`\n  fastest: ${bestN} thread(s) at ${Math.round(bestRate).toLocaleString()} keys/s`);
    const eight = rates.get(8);
    if (eight) {
        const four = rates.get(4);
        if (four) {
            const d = ((eight / four - 1) * 100).toFixed(1);
            console.log(`  8 threads vs 4: ${d}% ${eight >= four ? 'faster' : 'SLOWER'}`);
        }
    }
    process.exit(0);
}

// ---- worker thread ----
{
    const { createRequire: cr } = await import('node:module');
    const req = cr(import.meta.url);
    const sodium = req(workerData.libPath);
    await sodium.ready;

    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = (i * 7 + 3) & 0xff;

    let keys = 0;
    const t0 = Date.now();
    const deadline = t0 + workerData.ms;
    while (Date.now() < deadline) {
        // Match the page's hot loop: keygen plus a trivial prefix check.
        for (let i = 0; i < 16; i++) {
            const kp = sodium.crypto_sign_seed_keypair(seed);
            if (kp.publicKey[0] === 0xff && kp.publicKey[31] === 0xff) keys++;
            keys++;
            seed[0] = (seed[0] + 1) & 0xff;
        }
    }
    parentPort.postMessage({ keys });
}