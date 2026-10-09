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

function runBench({ prefix, suffix, matchPrefix, matchSuffix, ms, keyType, maxAttempts }) {
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

    // `maxAttempts` bounds the loop and makes the worker post a 'calibrated'
    // message carrying its own count and elapsed time. That is how the
    // derivation-free modes are measured below, because their candidate count is
    // not observable any other way - the only thing that counts them is the
    // wrapper itself.
    return new Promise((resolve) => {
        const before = KEYGEN_CALLS.n;
        const t0 = Date.now();
        const data = { prefix, suffix, matchPrefix, matchSuffix, keyType };
        if (maxAttempts) data.maxAttempts = maxAttempts;
        workerGlobal.onmessage({ data });
        const poll = setInterval(() => {
            const found = posted.find((m) => m.type === 'found');
            const err = posted.find((m) => m.type === 'error');
            const done_ = posted.find((m) => m.type === 'calibrated');
            if (found || err || done_ || Date.now() - t0 > ms) {
                clearInterval(poll);
                const dt = (Date.now() - t0) / 1000;
                // Prefer the worker's own count when it reported one; it is
                // exact and excludes the harness's polling latency.
                const done = done_ ? done_.attempts : (KEYGEN_CALLS.n - before);
                const seconds = done_ ? done_.elapsed : dt;
                resolve({
                    keys: done, seconds, rate: seconds > 0 ? done / seconds : 0,
                    posted, found, err, capped: !!done_,
                });
            }
        }, 10);
    });
}

// Take several trials and keep the best.
//
// A single short sample is not a stable measurement: the first run of the
// extracted worker pays for module parsing and JIT warm-up, and a shared CI
// vCPU can be descheduled part-way through for reasons that have nothing to do
// with the code. Either effect can drag one trial well under the runner's real
// steady-state throughput, which is how a run measuring 921,735/s failed a
// 1,000,000/s floor on a commit whose worker source was byte-identical to
// main (verified by sha256 over the extracted template literal).
//
// The BEST trial is the right statistic here, not the mean: the question is
// "what is the wrapper capable of", and warm-up and contention can only ever
// make a trial slower, never faster. A real regression - per-candidate hex
// building, yielding far too often - lowers every trial, so it still fails.
const TRIALS = 3;
const TRIAL_MS = 1500;
const rates = [];
let last = null;
for (let t = 0; t < TRIALS; t++) {
    last = await runBench({ prefix: 'abffff', suffix: '', matchPrefix: true, matchSuffix: false, ms: TRIAL_MS });
    if (last.err) {
        console.error('worker error:', last.err.message);
        process.exit(1);
    }
    rates.push(last.rate);
    console.log(`  trial ${t + 1}/${TRIALS}: ${Math.round(last.rate).toLocaleString()} keys/s`);
}
const r = { ...last, rate: Math.max(...rates) };

console.log(`stub-keygen throughput: ${Math.round(r.rate).toLocaleString()} keys/s (best of ${TRIALS})`);
console.log(`  candidates: ${r.keys.toLocaleString()} in ${r.seconds.toFixed(2)}s`);
if (r.found) console.log(`  matched after ${r.found.attempts.toLocaleString()} attempts`);

// The two no-derivation modes are benchmarked too, for a different reason.
//
// For a device key the gate above protects against wrapper overhead becoming
// VISIBLE next to libsodium, which is the only thing it could threaten: keygen
// costs ~13,500/s in a real browser, so any wrapper at or above that rate is
// already invisible.
//
// A channel PSK and a node ID derive nothing at all. Their entire cost IS the
// wrapper - an increment and a nibble compare - so the same overhead that is
// invisible for a device key is the whole cost here. If the matcher ever grew a
// per-candidate allocation or a string build, these two modes would feel it in
// full and no amount of real keygen would hide it. Measuring them is the only
// way the regression gate covers the new hot paths.
//
// The candidate count is bounded by maxAttempts rather than a wall clock, and
// the rate comes from the worker's own elapsed time. Both matter here: these
// loops finish in a few hundred milliseconds, so a harness-side stopwatch would
// measure the harness, and a 1.5s budget against a ~50M/s loop is mostly
// scheduler noise.
const DERIVATION_FREE_ATTEMPTS = 4_000_000;
console.log('');
let pskRate = 0;
let nodeidRate = 0;
for (const [label, keyType] of [['channel PSK', 'psk'], ['node ID', 'nodeid']]) {
    let best = 0;
    let lastRun = null;
    for (let t = 0; t < TRIALS; t++) {
        const run = await runBench({
            // Unmatchable-by-construction for the bounded run: 6 hex digits on a
            // value whose counter is walked from a fixed stub start would
            // otherwise end the trial early on a lucky hit.
            prefix: 'ffffffffffff', suffix: '', matchPrefix: true, matchSuffix: false,
            ms: 30000, keyType, maxAttempts: DERIVATION_FREE_ATTEMPTS,
        });
        if (run.err) {
            console.error(`${label} worker error:`, run.err.message);
            process.exit(1);
        }
        if (!run.capped) {
            console.error(`${label} did not reach its attempt cap in 30s`);
            process.exit(1);
        }
        lastRun = run;
        best = Math.max(best, run.rate);
        console.log(`  ${label} trial ${t + 1}/${TRIALS}: ${Math.round(run.rate).toLocaleString()} keys/s`);
    }
    console.log(`${label} throughput: ${Math.round(best).toLocaleString()} keys/s (best of ${TRIALS})`);
    console.log(`  candidates: ${lastRun.keys.toLocaleString()} in ${lastRun.seconds.toFixed(3)}s`);
    if (keyType === 'psk') pskRate = best; else nodeidRate = best;
}

// A lower floor than the device-key gate, and deliberately so: these modes do
// no derivation, so their achievable rate is set by loop overhead rather than by
// crypto, and it is bounded by the 32-bit/256-bit counter walk rather than by
// any external cost. 5M/s is comfortably above the device-key gate's 1M/s and
// three orders of magnitude above the 9,182/s catastrophic cliff it shares.
const MIN_DERIVATION_FREE_KEYS_PER_SEC = 5_000_000;
for (const [label, rate] of [['channel PSK', pskRate], ['node ID', nodeidRate]]) {
    if (rate < MIN_DERIVATION_FREE_KEYS_PER_SEC) {
        console.error(
            `\nFAILED: ${label} throughput ${Math.round(rate).toLocaleString()} keys/s `
            + `is below the ${MIN_DERIVATION_FREE_KEYS_PER_SEC.toLocaleString()} keys/s floor. `
            + 'These modes derive nothing, so the wrapper IS the whole cost.'
        );
        process.exit(1);
    }
    console.log(`  ${label} regression floor: `
        + `${MIN_DERIVATION_FREE_KEYS_PER_SEC.toLocaleString()} keys/s — OK`);
}

// Regression gate.
//
// Chosen from OBSERVED numbers, not optimism:
//   catastrophic regression (per-16-candidate yield + hex churn): ~9,182/s
//   development machine                                              ~10-13M/s
//   GitHub Actions shared runner                        2,733,763/s (observed)
// A floor of 3M was set from the dev-machine figure and turned CI red four
// times in a row: a shared vCPU is several times slower than a workstation, and
// an absolute threshold tuned on one machine does not transfer.
//
// What does this gate actually protect? Real key derivation runs at only
// ~13,500/s in a browser (tools/bench_real_browser.mjs), so the wrapper is
// already ~1000x cheaper than the work it wraps. At 1M/s it would still be 74x
// faster than the keygen, i.e. entirely invisible to users. The regression
// that mattered was 9,182/s - right at keygen cost, which is why mining felt
// catastrophically slow.
//
// So the floor belongs far above that functional cliff, not near the
// dev-machine figure. 1M is 109x above 9,182/s and leaves ~2.7x headroom below
// the slowest observed runner, so ordinary runner variance cannot fail a build
// while a real wrapper regression still fails hard.
//
// Headroom is not infinite, though: a single-trial measurement on a shared
// vCPU was observed at 921,735/s - under this floor - on a commit whose
// extracted worker source was byte-identical to main (sha256 03a8ce1c...). That
// is contention, not a regression, and the fix is the best-of-N above rather
// than lowering the floor: lowering it would erode the ~109x margin that makes
// this gate worth having, and a genuine regression is orders of magnitude away
// from the cliff, so it fails under any of these settings.
const MIN_KEYS_PER_SEC = 1_000_000;
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