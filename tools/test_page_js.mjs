#!/usr/bin/env node
/**
 * Behaviour tests for the inline JS of index.html.
 *
 * `node --check` only validates syntax; this harness actually EXECUTES the
 * extracted page script against a minimal DOM so logic regressions (bad time
 * formatting, wrong pluralisation, corrupt-history handling) fail loudly.
 *
 * Usage:
 *     node tools/test_page_js.mjs <path-to-extracted-main.js> [path-to-extracted-worker.js]
 *
 * The caller is responsible for extracting the JS first, e.g.:
 *     python tools/check_inline_js.py --out-dir /tmp/inline-js
 *     node tools/test_page_js.mjs /tmp/inline-js/main.js /tmp/inline-js/worker.js
 */

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const mainJsPath = process.argv[2];
if (!mainJsPath) {
    console.error('usage: node tools/test_page_js.mjs <extracted-main.js>');
    process.exit(2);
}
const source = fs.readFileSync(mainJsPath, 'utf8');

// ---- Minimal DOM mock ------------------------------------------------------

function makeEl(id = '') {
    let text = '';
    const el = {
        id,
        value: '',
        innerHTML: '',
        className: '',
        disabled: false,
        style: {},
        children: [],
        // Real DOM: assigning textContent replaces all child nodes.
        get textContent() { return text; },
        set textContent(v) { text = v === undefined || v === null ? '' : String(v); this.children = []; },
        classList: {
            _s: new Set(),
            add(...c) { c.forEach((x) => this._s.add(x)); },
            remove(...c) { c.forEach((x) => this._s.delete(x)); },
            contains(c) { return this._s.has(c); },
            toggle(c, on) { if (on === undefined) { this._s.has(c) ? this._s.delete(c) : this._s.add(c); } else if (on) { this._s.add(c); } else { this._s.delete(c); } },
        },
        appendChild(child) { this.children.push(child); return child; },
        removeChild(child) { this.children = this.children.filter((c) => c !== child); },
        addEventListener() {},
        getBoundingClientRect() { return { height: 40, width: 100, top: 0, left: 0 }; },
        scrollIntoView() {},
        click() {},
    };
    return el;
}

const els = new Map();
function getElementById(id) {
    if (!els.has(id)) els.set(id, makeEl(id));
    return els.get(id);
}

const alerts = [];
const storage = new Map();

const documentMock = {
    getElementById,
    createElement: (tag) => makeEl(tag),
    body: makeEl('body'),
    currentScript: null,
    addEventListener() {},
};

// Mutable core-count so detectOptimalWorkers() can be exercised.
const navigatorMock = {
    hardwareConcurrency: 4,
    clipboard: null,
    serviceWorker: undefined,
};

const windowMock = {
    addEventListener() {},
    liveEstimateShown: false,
};

// Minimal localStorage: supports the quota-exceeded path via a setter.
const localStorageMock = {
    _data: storage,
    getItem(k) { return storage.has(k) ? storage.get(k) : null; },
    setItem(k, v) {
        if (this.throwOnSet) {
            const e = new Error('QuotaExceededError');
            e.name = 'QuotaExceededError';
            e.code = 22;
            throw e;
        }
        storage.set(k, String(v));
    },
    removeItem(k) { storage.delete(k); },
    get throwOnSet() { return this._throw; },
    set throwOnSet(v) { this._throw = v; },
    _throw: false,
};

const sandbox = {
    document: documentMock,
    navigator: navigatorMock,
    window: windowMock,
    console,
    localStorage: localStorageMock,
    performance,
    setTimeout,
    clearTimeout,
    Promise,
    Math,
    Number,
    JSON,
    Date,
    isFinite,
    isNaN,
    parseInt,
    parseFloat,
    String,
    Object,
    Array,
    Error,
    BigInt,
    Uint8Array,
    crypto: globalThis.crypto,
    location: { href: 'https://example.test/index.html' },
    URL,
    Blob: class {},
    Worker: class { constructor() { throw new Error('not used in these tests'); } },
};
sandbox.globalThis = sandbox;
sandbox.self = sandbox;

// Expose the script's top-level bindings for assertions. The page script uses
// classic (non-module) top-level function declarations, so a function-scoped
// wrapper lets us return them.
vm.createContext(sandbox);
vm.runInContext(
    `${source}\n;globalThis.__api = { formatElapsed, detectOptimalWorkers, updateEstimate, ratePerWorker, validateHex, checkReservedPrefix, validateForm, loadHistory, persistHistory, addKeyToHistory, renderHistory, currentPatternDesc, isQuotaError, sodiumIsUsable, awaitSodium, csvCell, HISTORY_KEY, MAX_SAVED_KEYS, resetForm, getSavedKeys: () => savedKeys };`,
    sandbox,
    { filename: 'index.html:main.js' }
);

const api = sandbox.__api;

// ---- Tiny test runner ------------------------------------------------------

let passed = 0;
const failures = [];

function check(name, fn) {
    try {
        fn();
        passed++;
    } catch (e) {
        failures.push(`${name}: ${e.message}`);
    }
}

function eq(actual, expected, msg = '') {
    if (actual !== expected) {
        throw new Error(`${msg} expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    }
}

function ok(cond, msg = 'expected truthy') {
    if (!cond) throw new Error(msg);
}

// ---- formatElapsed ---------------------------------------------------------

check('formatElapsed: sub-minute keeps tenths', () => {
    eq(api.formatElapsed(0), '0.0s');
    eq(api.formatElapsed(0.04), '0.0s');
    eq(api.formatElapsed(45.23), '45.2s');
    eq(api.formatElapsed(1.5), '1.5s');
});

check('formatElapsed: minutes', () => {
    eq(api.formatElapsed(60), '1m 0s');
    eq(api.formatElapsed(129.62), '2m 10s');   // the reported case
    eq(api.formatElapsed(119), '1m 59s');
    eq(api.formatElapsed(59.4), '59.4s', 'still under a minute:');
});

check('formatElapsed: hours include minutes and seconds', () => {
    eq(api.formatElapsed(3600), '1h 0m 0s');
    eq(api.formatElapsed(7389), '2h 3m 9s');
    eq(api.formatElapsed(86400), '24h 0m 0s');
});

check('formatElapsed: non-finite and negative degrade to "unknown"', () => {
    eq(api.formatElapsed(NaN), 'unknown');
    eq(api.formatElapsed(Infinity), 'unknown');
    eq(api.formatElapsed(-1), 'unknown');
    eq(api.formatElapsed(undefined), 'unknown');
    eq(api.formatElapsed(null), 'unknown');
    eq(api.formatElapsed('nope'), 'unknown');
});

// ---- detectOptimalWorkers --------------------------------------------------

check('detectOptimalWorkers: leaves a core for the UI, clamps to 16', () => {
    const set = (n) => { navigatorMock.hardwareConcurrency = n; };
    set(1); eq(api.detectOptimalWorkers(), 1, '1 core ->');
    set(2); eq(api.detectOptimalWorkers(), 1, '2 cores ->');
    set(4); eq(api.detectOptimalWorkers(), 3, '4 cores ->');
    set(8); eq(api.detectOptimalWorkers(), 7, '8 cores ->');
    set(17); eq(api.detectOptimalWorkers(), 16, '17 cores ->');
    set(64); eq(api.detectOptimalWorkers(), 16, '64 cores ->');
    set(undefined); eq(api.detectOptimalWorkers(), 3, 'unknown cores ->');
});

// ---- updateEstimate: singular / plural -------------------------------------

check('updateEstimate: uses "1 worker" (singular) when one core is available', () => {
    navigatorMock.hardwareConcurrency = 2;   // -> 1 worker
    getElementById('prefix').value = 'ab';
    getElementById('suffix').value = '';
    api.updateEstimate();
    const txt = getElementById('estimate').textContent;
    ok(txt.includes('1 worker,'), `expected "1 worker," in: ${txt}`);
    ok(!txt.includes('1 workers'), `must not say "1 workers": ${txt}`);
    ok(!txt.includes('workers'), `must not use plural at all: ${txt}`);
});

check('updateEstimate: uses "N workers" (plural) for multiple cores', () => {
    navigatorMock.hardwareConcurrency = 8;   // -> 7 workers
    api.updateEstimate();
    const txt = getElementById('estimate').textContent;
    ok(txt.includes('7 workers,'), `expected "7 workers," in: ${txt}`);
    ok(txt.includes('Expected attempts: 256'), `expected 256 attempts in: ${txt}`);
});

check('updateEstimate: clears itself when both inputs are empty', () => {
    getElementById('prefix').value = '';
    getElementById('suffix').value = '';
    api.updateEstimate();
    eq(getElementById('estimate').textContent, '');
});

// ---- hex validation --------------------------------------------------------

check('validateHex: rejects non-hex, accepts empty', () => {
    const el = getElementById('prefix');
    el.value = 'zz';
    eq(api.validateHex(el), false);
    eq(getElementById('prefix-error').textContent, 'Invalid hex characters');
    el.value = 'deadBEEF01';
    eq(api.validateHex(el), true);
    el.value = '';
    eq(api.validateHex(el), true);
});

check('checkReservedPrefix: flags 00/ff only', () => {
    const el = getElementById('prefix');
    el.value = '00ab'; eq(api.checkReservedPrefix(el), true);
    el.value = 'FF12'; eq(api.checkReservedPrefix(el), true, 'uppercase');
    el.value = '0';   eq(api.checkReservedPrefix(el), false, 'too short');
    el.value = 'ab'; eq(api.checkReservedPrefix(el), false);
});

// ---- history rendering with hostile / corrupt data -------------------------

function seedHistory(entries) {
    storage.set(api.HISTORY_KEY, JSON.stringify(entries));
}

check('loadHistory: drops malformed entries and non-objects', () => {
    seedHistory([
        null,
        'a string',
        42,
        { publicKey: 'short', privateKey: 'also-short' },
        { publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 7, attempts: 5, elapsed: 1 },
    ]);
    api.loadHistory();
    api.renderHistory(false);
    const rendered = getElementById('results').children;
    eq(rendered.length, 1, 'only the valid entry should render');
    ok(getElementById('results').children[0].children[0].textContent.includes('Key 7'),
        'expected the preserved sequence number in the heading');
});

check('renderHistory: never prints NaN/undefined for missing numbers', () => {
    seedHistory([
        { publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 'not-a-number', attempts: 'x', elapsed: 'y' },
        { publicKey: 'c'.repeat(64), privateKey: 'd'.repeat(64), attempts: 1234, elapsed: 129.62 },
    ]);
    api.loadHistory();
    api.renderHistory(false);
    const frames = getElementById('results').children;
    eq(frames.length, 2);
    const texts = JSON.stringify(frames.map((f) => f.children.map((c) => c.textContent)));
    ok(!texts.includes('NaN'), `NaN leaked into history: ${texts}`);
    ok(!texts.includes('undefined'), `undefined leaked into history: ${texts}`);
    // Humanized elapsed: 129.62s -> "2m 10s", never the raw "129.62s".
    ok(texts.includes('2m 10s'), `elapsed should be humanized: ${texts}`);
    ok(!texts.includes('129.62s'), `raw float elapsed leaked: ${texts}`);
    ok(texts.includes('1,234'), `attempts should be grouped: ${texts}`);
    // Missing pattern falls back instead of printing "undefined".
    ok(texts.includes('unknown pattern'), `pattern fallback missing: ${texts}`);
});

// ---- csv escaping ----------------------------------------------------------

check('csvCell: quotes and escapes correctly', () => {
    eq(api.csvCell('plain'), '"plain"');
    eq(api.csvCell('say "hi"'), '"say ""hi"""');
    eq(api.csvCell(null), '""');
    eq(api.csvCell(undefined), '""');
    eq(api.csvCell(12), '"12"');
});

// ---- quota handling --------------------------------------------------------

check('persistHistory: quota error is detected', () => {
    ok(api.isQuotaError({ name: 'QuotaExceededError' }));
    ok(api.isQuotaError({ code: 22 }));
    ok(api.isQuotaError({ code: 1014 }));
    ok(!api.isQuotaError({ name: 'SecurityError' }));
    ok(!api.isQuotaError(null));
});

// ---- readiness guards ------------------------------------------------------

check('sodiumIsUsable: false when libsodium is absent', () => {
    eq(api.sodiumIsUsable(), false, 'no libsodium global in this sandbox:');
});

check('awaitSodium: rejects with a helpful message when libsodium is missing', async () => {
    // Exercised synchronously via the returned promise being rejected; the
    // runner below awaits it.
    let threw = false;
    try {
        await api.awaitSodium();
    } catch (e) {
        threw = /libsodium did not load/.test(e.message);
    }
    if (!threw) failures.push('awaitSodium: expected a "libsodium did not load" rejection');
    else passed++;
});

// ---- worker readiness sequencing ------------------------------------------
// Regression for the shipped bug: "sodium.crypto_sign_seed_keypair is not a
// function". libsodium.js is an Emscripten build whose crypto namespace only
// exists after `libsodium.ready` resolves; the worker must gate all work on it.

async function runWorker(workerJsPath, { resolveReadyImmediately = true } = {}) {
    const raw = fs.readFileSync(workerJsPath, 'utf8');
    // Resolve the `${new URL(...)}` template interpolation done by the page.
    const src = raw.replace(
        /\$\{new URL\([^)]*\)\.href\}/g,
        'https://example.test/libsodium.js'
    );

    const posted = [];
    let resolveReady;
    const readyPromise = new Promise((r) => { resolveReady = r; });

    const workerGlobal = {
        console,
        BigInt,
        Date,
        Math,
        Uint8Array,
        setTimeout,
        clearTimeout,
        Promise,
        isFinite,
        // Deterministic pseudo-keygen: public key always starts with "abcd".
        sodium: undefined,
        libsodium: undefined,
        crypto: {
            getRandomValues(buf) {
                for (let i = 0; i < buf.length; i++) buf[i] = (i * 7 + 3) & 0xff;
                return buf;
            },
        },
        postMessage(msg) { posted.push(msg); },
        importScripts() {
            const g = workerGlobal;
            g.libsodium = {
                ready: resolveReadyImmediately ? Promise.resolve() : readyPromise,
            };
            g.sodium = {};
            if (resolveReadyImmediately) {
                g.sodium.crypto_sign_seed_keypair = () => {
                    const pk = new Uint8Array(32);
                    pk[0] = 0xab; pk[1] = 0xcd;
                    return { publicKey: pk, privateKey: new Uint8Array(64), keyType: 'ed25519' };
                };
            } else {
                // Deferred: crypto API absent until ready resolves, exactly
                // like the real Emscripten build.
                g.libsodium.ready.then(() => {
                    g.sodium.crypto_sign_seed_keypair = () => {
                        const pk = new Uint8Array(32);
                        pk[0] = 0xab; pk[1] = 0xcd;
                        return { publicKey: pk, privateKey: new Uint8Array(64), keyType: 'ed25519' };
                    };
                });
            }
        },
    };
    workerGlobal.self = workerGlobal;
    workerGlobal.globalThis = workerGlobal;

    vm.createContext(workerGlobal);
    vm.runInContext(src, workerGlobal, { filename: 'worker.js' });

    // Let the boot IIFE start and (if immediate) settle.
    await new Promise((r) => setTimeout(r, 0));
    return { workerGlobal, posted, resolveReady };
}

const workerJsPath = process.argv[3];
if (workerJsPath) {
    // 1. Happy path: libsodium ready by the time work arrives.
    await (async () => {
        try {
            const { workerGlobal, posted } = await runWorker(workerJsPath);
            ok(posted.some((m) => m.type === 'ready'), `worker never reported ready: ${JSON.stringify(posted)}`);

            workerGlobal.onmessage({
                data: { prefix: 'ab', suffix: '', matchPrefix: true, matchSuffix: false },
            });
            // Let the readyPromise gate + the mining loop run.
            for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 0));

            const err = posted.find((m) => m.type === 'error');
            ok(!err, `worker reported an error: ${JSON.stringify(err)}`);
            const found = posted.find((m) => m.type === 'found');
            ok(found, `worker never reported a match: ${JSON.stringify(posted)}`);
            ok(found.publicKey.startsWith('ab'), `bad publicKey: ${found.publicKey}`);
            ok(/^[0-9a-f]{64}$/.test(found.privateKey), `privateKey must be 64 hex: ${found.privateKey}`);
            passed++;
        } catch (e) {
            failures.push(`worker happy path: ${e.message}`);
        }
    })();

    // 2. Race path: work arrives BEFORE libsodium.ready resolves. The worker
    //    must neither crash nor process work; it waits, then mines normally.
    await (async () => {
        try {
            const { workerGlobal, posted, resolveReady } = await runWorker(workerJsPath, {
                resolveReadyImmediately: false,
            });
            ok(!posted.some((m) => m.type === 'ready'), 'ready must not fire before libsodium.ready');

            // Fire the work message while the crypto API does not exist yet.
            workerGlobal.onmessage({
                data: { prefix: 'ab', suffix: '', matchPrefix: true, matchSuffix: false },
            });
            await new Promise((r) => setTimeout(r, 5));

            ok(!posted.some((m) => m.type === 'found' || m.type === 'error'),
                `work must wait for readiness, got: ${JSON.stringify(posted)}`);

            // Now let libsodium finish initializing.
            resolveReady();
            for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 0));

            const err = posted.find((m) => m.type === 'error');
            ok(!err, `worker reported an error after readiness: ${JSON.stringify(err)}`);
            ok(posted.find((m) => m.type === 'found'),
                `queued work should run once ready: ${JSON.stringify(posted)}`);
            passed++;
        } catch (e) {
            failures.push(`worker readiness race: ${e.message}`);
        }
    })();
}

// ---- report ----------------------------------------------------------------

if (failures.length) {
    console.error(`\nFAILED ${failures.length} of ${failures.length + passed} checks:\n`);
    for (const f of failures) console.error('  - ' + f);
    process.exit(1);
}
console.log(`page JS OK: ${passed} behaviour checks passed`);
