// Real libsodium.js key-derivation rate for the browser miner.
//
// WHY THIS FILE IS SMALL: two earlier versions of it produced numbers that
// were internally impossible - a loop CONTAINING the keygen measured faster
// than the keygen alone, by up to 250x. Two separate JIT effects were
// responsible:
//
//   * Discarding crypto_sign_seed_keypair's result let the optimiser delete
//     the call entirely, so "keygen only" measured a function that was not
//     running.
//   * Whichever measurement ran FIRST was penalised by progressive WASM
//     optimisation of the freshly-loaded module, so ordering alone changed
//     the answer by ~18x.
//
// Both are avoided here: the walk state is incremented before every keygen so
// no two calls share an input, and every result is folded into a checksum so
// none can be eliminated. Even so, this file deliberately reports ONLY the
// key-derivation rate. It does NOT attempt to attribute a percentage to the
// loop's own overhead, because that ratio could not be measured reliably here
// and publishing it would be worse than omitting it.
//
// The conclusion this DOES support is the one that matters: the browser worker
// is bound by libsodium's WASM Ed25519 keygen, and the wrapper overhead is far
// below it (see tools/bench_worker.mjs, which measures the wrapper against a
// stubbed keygen at ~10M keys/s - three orders of magnitude cheaper than a real
// derivation). Worker COUNT is therefore the only meaningful lever.
//
// Run: bun tools/bench_real_browser.mjs
//
// ASSUMPTION: Bun's V8 is close enough to a browser's engine that the order of
// magnitude transfers. Absolute keys/s will differ between runtimes.

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const sodium = require('../libsodium.js');
await sodium.ready;

const walk = new Uint8Array(32);
crypto.getRandomValues(walk);

function incrementSeed(seed) {
    for (let i = 31; i >= 0; i--) {
        const next = (seed[i] + 1) & 0xff;
        seed[i] = next;
        if (next !== 0) return;
    }
}

let sink = 0;
const TRIALS = 5;
const PER_TRIAL = 2000;
const rates = [];

console.log('libsodium.js Ed25519 keygen rate (real WASM, per worker core):');

for (let t = 0; t < TRIALS; t++) {
    // Warm: the module is compiled and optimised on first real use.
    for (let i = 0; i < 1000; i++) {
        incrementSeed(walk);
        const pair = sodium.crypto_sign_seed_keypair(walk);
        sink = (sink + pair.publicKey[0]) | 0;
    }
    const t0 = performance.now();
    for (let i = 0; i < PER_TRIAL; i++) {
        incrementSeed(walk);
        const pair = sodium.crypto_sign_seed_keypair(walk);
        sink = (sink + pair.publicKey[0]) | 0;
    }
    const dt = performance.now() - t0;
    const rate = PER_TRIAL / (dt / 1000);
    rates.push(rate);
    console.log(`  trial ${t + 1}: ${Math.round(rate).toLocaleString().padStart(12)}/s`);
}

rates.sort((a, b) => a - b);
const median = rates[Math.floor(rates.length / 2)];
console.log('');
console.log(`  median: ${Math.round(median).toLocaleString()} keys/s per core`);
console.log(`  spread: ${Math.round(rates[0]).toLocaleString()} .. `
    + `${Math.round(rates[rates.length - 1]).toLocaleString()} `
    + `(${((rates[rates.length - 1] / rates[0] - 1) * 100).toFixed(0)}% - JIT warm-up)`);
console.log(`  checksum ${sink & 0xff} (non-zero => calls really executed)`);
console.log('');
console.log('  A browser worker cannot beat this per core. Worker COUNT is the lever.');