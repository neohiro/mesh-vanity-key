// Throughput benchmark for the browser mining hot loop.
//
// Isolates OUR loop overhead from libsodium's cost by stubbing the keygen, so
// the number answers "how much work does the wrapper cost per candidate?".
// A wrapper that dominates (hex strings, BigInt, per-batch timers) shows up
// immediately as a low keys/s figure even though the stub is nearly free.
//
// Usage: bun tools/bench_worker.mjs [path-to-extracted-worker.js]

import fs from 'node:fs';
import vm from 'node:vm';

const workerJsPath = process.argv[2];
if (!workerJsPath) {
    console.error('usage: bun tools/bench_worker.mjs <extracted-worker.js>');
    process.exit(2);
}

const raw = fs.readFileSync(workerJsPath, 'utf8');
const src = raw.replace(/\$\{new URL\([^)]*\)\.href\}/g, 'https://example.test/libsodium.js');

// A deliberately cheap "keygen": one array write. Whatever throughput we
// measure is therefore essentially pure wrapper overhead per candidate.
const KEYGEN_CALLS = { n: 0 };

function runBench({ prefix, suffix, matchPrefix, matchSuffix, ms }) {
    const posted = [];
    let resolveReady;
    const readyPromise = Promise.resolve();

    const workerGlobal = {
        console: { log() {}, error() {} },
        BigInt, Date, Math, Uint8Array, setTimeout, clearTimeout, Promise, isFinite,
        sodium: undefined,
        libsodium: undefined,
        crypto: { getRandomValues(buf) { for (let i = 0; i < buf.length; i++) buf[i] = (i * 13 + 7) & 0xff; return buf; } },
        postMessage(msg) { posted.push(msg); },
        importScripts() {
            const g = workerGlobal;
            g.libsodium = { ready: readyPromise };
            g.sodium = {
                crypto_sign_seed_keypair(seed) {
                    KEYGEN_CALLS.n++;
                    // Derive a "public key" that matches the requested prefix
                    // on a low fixed offset so the search terminates quickly but
                    // only after real work.
                    const pk = new Uint8Array(32);
                    const off = KEYGEN_CALLS.n % 4096;
                    pk[0] = parseInt(prefix.slice(0, 2), 16) || 0;
                    pk[1] = parseInt(prefix.slice(2, 4), 16) || 0;
                    pk[31] = off & 0xff;
                    return { publicKey: pk, privateKey: new Uint8Array(64) };
                },
            };
        },
    };
    workerGlobal.self = workerGlobal;
    workerGlobal.globalThis = workerGlobal;

    vm.createContext(workerGlobal);
    vm.runInContext(src, workerGlobal, { filename: 'worker.js' });

    return new Promise((resolve) => {
        const before = KEYGEN_CALLS.n;
        const t0 = Date.now();
        workerGlobal.onmessage({ data: { prefix, suffix, matchPrefix, matchSuffix } });
        const poll = setInterval(() => {
            const found = posted.find((m) => m.type === 'found');
            const err = posted.find((m) => m.type === 'error');
            if (found || err || Date.now() - t0 > ms) {
                clearInterval(poll);
                const dt = (Date.now() - t0) / 1000;
                const done = KEYGEN_CALLS.n - before;
                resolve({ keys: done, seconds: dt, rate: dt > 0 ? done / dt : 0, posted, found, err });
            }
        }, 10);
    });
}

const r = await runBench({ prefix: 'abffff', suffix: '', matchPrefix: true, matchSuffix: false, ms: 1500 });

if (r.err) {
    console.error('worker error:', r.err.message);
    process.exit(1);
}
console.log(`stub-keygen throughput: ${Math.round(r.rate).toLocaleString()} keys/s`);
console.log(`  candidates: ${r.keys.toLocaleString()} in ${r.seconds.toFixed(2)}s`);
if (r.found) console.log(`  matched after ${r.found.attempts.toLocaleString()} attempts`);

// Regression gate.
//
// The threshold is deliberately set far below the observed ~10-14M keys/s but
// far ABOVE the 9,182 keys/s of the original per-16-candidate-yield loop. A
// very low gate (the previous 200k) could only catch a catastrophic
// regression, so an ordinary 5-20x slowdown would have shipped green. 3M still
// leaves ~3x headroom for slower CI runners while catching a genuine
// regression in the wrapper.
const MIN_KEYS_PER_SEC = 3_000_000;
if (r.rate < MIN_KEYS_PER_SEC) {
    console.error(
        `\nFAILED: wrapper throughput ${Math.round(r.rate).toLocaleString()} keys/s `
        + `is below the ${MIN_KEYS_PER_SEC.toLocaleString()} keys/s floor. `
        + 'The mining wrapper has regressed (per-candidate overhead).'
    );
    process.exit(1);
}
console.log(`  regression floor: ${MIN_KEYS_PER_SEC.toLocaleString()} keys/s — OK`);
process.exit(0);