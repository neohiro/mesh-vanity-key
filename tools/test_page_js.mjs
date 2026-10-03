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
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const mainJsPath = process.argv[2];
if (!mainJsPath) {
    console.error('usage: node tools/test_page_js.mjs <extracted-main.js>');
    process.exit(2);
}
const source = fs.readFileSync(mainJsPath, 'utf8');

// The page itself, so tests can assert on markup (event-handler wiring) that
// never reaches the extracted JS. Resolved from this script's own location so
// it works regardless of the caller's working directory.
const pageHtmlPath = process.env.PAGE_HTML
    || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'index.html');

// ---- Minimal DOM mock ------------------------------------------------------

function makeEl(id = '') {
    let text = '';
    const el = {
        id,
        value: '',
        innerHTML: '',
        className: '',
        disabled: false,
        hidden: false,   // mirrors the HTML hidden property (see setStatusText)
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
        // Real DOM derives these from the child list.
        get firstElementChild() { return this.children[0] ?? null; },
        get lastElementChild() { return this.children[this.children.length - 1] ?? null; },
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
const confirms = [];
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

// Worker lifecycle mock. Mining workers run an unbounded `while (true)`, so
// the only correct way to stop one is terminate(); these counters let the tests
// assert that every worker is actually torn down on stop/found/error.
const workerStats = { created: 0, terminated: 0, live: 0, revokedUrls: 0 };

const urlStats = { objectURLs: new Set(), blobText: new Map() };
// Callable as a constructor as well as a namespace: the page builds a real URL
// (`new URL('libsodium.js', location.href)`) when it assembles the worker
// source, so a plain object left `URL is not a constructor` and every
// mining-lifecycle test failed before reaching its assertions.
function URLMock(input, base) {
    const href = base ? new URL(String(input), String(base)).href : String(input);
    this.href = href;
    this.toString = () => href;
}
URLMock.createObjectURL = function (blob) {
    const u = `blob:mock/${urlStats.objectURLs.size}`;
    urlStats.objectURLs.add(u);
    // Remember the source so the Worker mock can tell the two worker kinds
    // apart. The mining worker calls crypto_sign_seed_keypair; the export
    // worker builds CSV. Classifying from the real source beats guessing from
    // the URL, which is a counter in the mock.
    const parts = (blob && blob.parts) || [];
    urlStats.blobText.set(u, parts.map((p) => (typeof p === 'string' ? p : String(p))).join(''));
    return u;
};
URLMock.revokeObjectURL = function (u) {
    if (urlStats.objectURLs.delete(u)) workerStats.revokedUrls++;
};

// Minimal in-memory IndexedDB: enough for the obfuscation secret store. Tests
// the real async code path (open -> transaction -> get -> put) without a DOM.
const OBF_DB = 'meshcoreVanityObf';
const OBF_STORE = 'secrets';
const idbData = new Map();   // dbName -> Map(store -> Map(key -> value))
let idbAvailable = true;

function makeIndexedDB() {
    return {
        open(name, version) {
            const req = {
                onsuccess: null, onerror: null, onblocked: null,
                onupgradeneeded: null, result: null,
            };
            queueMicrotask(() => {
                if (!idbAvailable) {
                    if (req.onerror) req.onerror(new Error('unavailable'));
                    return;
                }
                const existed = idbData.has(name);
                if (!existed) idbData.set(name, new Map());
                const stores = idbData.get(name);

                const db = {
                    // Faithful to the real API: the object store only exists
                    // after createObjectStore during onupgradeneeded. An earlier
                    // mock pre-created it, which hid a real bug where the page
                    // never created the store and Chromium returned None.
                    objectStoreNames: {
                        contains: (s) => stores.has(s),
                    },
                    createObjectStore(s) { stores.set(s, new Map()); },
                    close() {},
                    onversionchange: null,
                    transaction(storeName) {
                        if (!stores.has(storeName)) {
                            // Real IndexedDB throws NotFoundError here.
                            throw new Error('NotFoundError: no object store ' + storeName);
                        }
                        const data = stores.get(storeName);
                        return {
                            objectStore() {
                                return {
                                    get(key) {
                                        const r = { onsuccess: null, onerror: null, result: undefined };
                                        queueMicrotask(() => {
                                            r.result = data.get(key);
                                            if (r.onsuccess) r.onsuccess(r);
                                        });
                                        return r;
                                    },
                                    put(value, key) {
                                        const r = { onsuccess: null, onerror: null };
                                        queueMicrotask(() => {
                                            data.set(key, value);
                                            if (r.onsuccess) r.onsuccess(r);
                                        });
                                        return r;
                                    },
                                };
                            },
                        };
                    },
                };
                req.result = db;
                if (!existed && req.onupgradeneeded) req.onupgradeneeded({ target: req });
                if (req.onsuccess) req.onsuccess(req);
            });
            return req;
        },
    };
}

// Timer bookkeeping.
//
// Mining arms one init-timeout watchdog PER WORKER, and the bug this exists to
// catch was a stale worker clearing the wrong one. Counting live timers cannot
// see that: clearTimeout() on an already-cleared handle is a no-op and leaves
// the array length unchanged, so a cross-search clear is invisible to a length
// check. Recording every handle as it is armed, and every handle passed to
// clearTimeout, makes it directly observable.
const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const timerLog = { armed: [], cleared: [] };
function armTrackingTimeouts() {
    sandbox.setTimeout = (fn, ms, ...rest) => {
        const h = realSetTimeout(fn, ms, ...rest);
        timerLog.armed.push(h);
        return h;
    };
    sandbox.clearTimeout = (h) => {
        if (h !== undefined && h !== null) timerLog.cleared.push(h);
        return realClearTimeout(h);
    };
    sandbox.__timerLog = timerLog;
}

// Controllable worker pool. The page assigns onmessage/onerror to each worker
// and calls terminate(); the pool keeps them addressable so a test can deliver
// an event to a worker the page has ALREADY terminated, which is exactly the
// ordering that used to disarm a later search's watchdog.
//
// The export worker is tagged and kept in a separate list. It is NOT part of a
// mining pool and must never be terminated by terminateAllWorkers(), so mixing
// the two would make the mining worker-count assertions meaningless.
const workerPool = [];
const exportPool = [];
const WorkerMock = class {
    constructor(url) {
        this.url = url;
        this.terminated = false;
        this.posted = [];
        // Classify from the real worker source: the mining worker calls
        // crypto_sign_seed_keypair, the export worker builds CSV. The export
        // worker is not part of a mining pool and must never be torn down by
        // terminateAllWorkers(), so mixing them would make the mining
        // worker-count assertions meaningless.
        const src = urlStats.blobText.get(String(url)) || '';
        this.isExport = /csvCell|type: 'done'/.test(src) && !/crypto_sign_seed_keypair/.test(src);
        this.index = (this.isExport ? exportPool : workerPool).length;
        (this.isExport ? exportPool : workerPool).push(this);
        if (!this.isExport) {
            workerStats.created++;
            workerStats.live++;
        }
    }
    postMessage(msg) { this.posted.push(msg); }
    terminate() {
        if (!this.terminated) {
            this.terminated = true;
            if (!this.isExport) {
                workerStats.terminated++;
                workerStats.live--;
            }
        }
    }
    // --- test-only helpers ---
    deliver(data) { if (this.onmessage) this.onmessage({ data }); }
    raiseError(message) { if (this.onerror) this.onerror({ message }); }
    hasHandler(kind) { return typeof this[kind] === 'function'; }
};

const sandbox = {
    document: documentMock,
    navigator: navigatorMock,
    window: windowMock,
    console,
    // Validation failures report via alert(); capture instead of blocking.
    alert(msg) { alerts.push(String(msg)); },
    // Auto-accept: the found path asks before persisting a key, and an
    // unstubbed confirm() throws in a vm context.
    confirm() { confirms.push(true); return true; },
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
    location: { href: 'https://example.test/index.html', origin: 'https://example.test' },
    URL: URLMock,
    Blob: class { constructor(parts) { this.parts = parts; } },
    // History obfuscation derives its key from a SHA-256 of a machine
    // fingerprint, so the harness must provide WebCrypto digests and the
    // TextEncoder/TextDecoder the page uses.
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    // History obfuscation base64-encodes its payload; these are browser
    // built-ins that the vm context does not provide.
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    indexedDB: makeIndexedDB(),
    Worker: WorkerMock,
};
sandbox.globalThis = sandbox;
sandbox.self = sandbox;
armTrackingTimeouts();

// Expose the script's top-level bindings for assertions. The page script uses
// classic (non-module) top-level function declarations, so a function-scoped
// wrapper lets us return them.
vm.createContext(sandbox);
vm.runInContext(
    `${source}\n;globalThis.__api = { formatElapsed, detectOptimalWorkers, updateEstimate, ratePerWorker, validateHex, checkReservedPrefix, validateForm, loadHistory, persistHistory, addKeyToHistory, renderHistory, currentPatternDesc, isQuotaError, sodiumIsUsable, awaitSodium, csvCell, HISTORY_KEY, MAX_SAVED_KEYS, resetForm, getSavedKeys: () => savedKeys, resetRateSmoothing, smoothRate, getSmoothedRate, invalidHexChars, escapeHtml, updatePatternNotice, createMiningWorker, terminateAllWorkers, stopMining, startMining, miningState: () => mining, startingState: () => starting, resetForm, liveWorkerCount: () => workers.length, initTimeoutCount: () => initTimeouts.length, __trackWorker: (w) => workers.push(w), clearHistory, isHistoryUnreadable: () => historyUnreadable, machineFingerprint, deriveObfuscationKeys, getOrCreateObfuscationSecret, legacyFingerprintV1, formatProgressLine, progressEtaClause, formatDayHint, formatEta, etaParts, renderEta, setEtaMessage, pad2, resetLiveLogs, reportActualWorkers, encryptHistoryData, decryptHistoryData, __resetObfKeyCache: () => { obfKeyPromise = null; }, workerScale, smoothEta, resetEtaSmoothing, ETA_MIN_SAMPLES, ETA_SMOOTHING_ALPHA, WORKER_SCALE_MEASURED, WORKER_SCALE_POINTS, WORKER_SCALE_MAX, recordLiveRate, resetLiveRates, liveAggregateKeysPerSecond, liveRateIsComplete, LIVE_RATE_MIN_SAMPLES, setStatusText, clearStatusText, pushRateGraphSample, resetRateGraph, decimateSamples, rateGraphState: () => rateGraph.map((s) => ({ t: s.t, v: s.v })), RATE_GRAPH_POINTS, RATE_GRAPH_WINDOW_MS, getStatusText: () => document.getElementById('progress-text').textContent, getStatusHidden: () => document.getElementById('progress-text').hidden, getLiveEtaText: (id) => { const el = document.getElementById(id); return el ? el.textContent : null; }, getEstimateText: () => document.getElementById('estimate').textContent, exportHistory, exportHistoryInWorker, downloadFile };`,
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
    // Precision follows magnitude: 2dp below 10s, 1dp from 10s to a minute.
    eq(api.formatElapsed(0), '0.00s');
    eq(api.formatElapsed(0.04), '0.04s', 'a 40ms search must not read as 0.0s');
    eq(api.formatElapsed(9.99), '9.99s');
    eq(api.formatElapsed(10), '10.0s');
    eq(api.formatElapsed(45.23), '45.2s');
    eq(api.formatElapsed(1.5), '1.50s');
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

check('detectOptimalWorkers: uses every core, capped at 32', () => {
    const set = (n) => { navigatorMock.hardwareConcurrency = n; };
    set(1); eq(api.detectOptimalWorkers(), 1, '1 core ->');
    set(2); eq(api.detectOptimalWorkers(), 2, '2 cores ->');
    set(4); eq(api.detectOptimalWorkers(), 4, '4 cores ->');
    set(8); eq(api.detectOptimalWorkers(), 8, '8 cores ->');
    set(32); eq(api.detectOptimalWorkers(), 32, '32 cores ->');
    set(64); eq(api.detectOptimalWorkers(), 32, '64 cores -> capped');
    // 0 is falsy, so the documented fallback of 4 applies.
    set(0); eq(api.detectOptimalWorkers(), 4, 'unknown/0 cores -> fallback 4');
    set(undefined); eq(api.detectOptimalWorkers(), 4, 'undefined cores -> fallback 4');
});

// ---- updateEstimate: singular / plural -------------------------------------

check('updateEstimate: uses "1 worker" (singular) when one core is available', () => {
    navigatorMock.hardwareConcurrency = 1;   // -> 1 worker
    getElementById('prefix').value = 'ab';
    getElementById('suffix').value = '';
    api.updateEstimate();
    const txt = getElementById('estimate').textContent;
    ok(txt.includes('1 worker,'), `expected "1 worker," in: ${txt}`);
    ok(!txt.includes('1 workers'), `must not say "1 workers": ${txt}`);
    // The estimate no longer carries the "workers share cores" caveat, so the
    // plural check no longer needs a carve-out for it - every bare "workers"
    // must be the count, and it must be singular.
    ok(!/\bworkers\b/.test(txt),
        `must not use the plural at all for one worker: ${txt}`);
});

check('updateEstimate: uses "N workers" (plural) for multiple cores', () => {
    navigatorMock.hardwareConcurrency = 8;   // -> 8 workers
    api.updateEstimate();
    const txt = getElementById('estimate').textContent;
    ok(txt.includes('8 workers,'), `expected "8 workers," in: ${txt}`);
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

async function asyncCheck(name, fn) {
    try {
        await fn();
        passed++;
    } catch (e) {
        failures.push(`${name}: ${e.message}`);
    }
}

await asyncCheck('loadHistory: drops malformed entries and non-objects', async () => {
    seedHistory([
        null,
        'a string',
        42,
        { publicKey: 'short', privateKey: 'also-short' },
        { publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 7, attempts: 5, elapsed: 1 },
    ]);
    await api.loadHistory();
    api.renderHistory(false);
    const rendered = getElementById('results').children;
    eq(rendered.length, 1, 'only the valid entry should render');
    ok(getElementById('results').children[0].children[0].textContent.includes('Key 7'),
        'expected the preserved sequence number in the heading');
});

await asyncCheck('renderHistory: never prints NaN/undefined for missing numbers', async () => {
    seedHistory([
        { publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 'not-a-number', attempts: 'x', elapsed: 'y' },
        { publicKey: 'c'.repeat(64), privateKey: 'd'.repeat(64), attempts: 1234, elapsed: 129.62 },
    ]);
    await api.loadHistory();
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

// ---- rate smoothing (EMA) --------------------------------------------------
// The headline rate must not flicker with raw per-batch samples, but it must
// still converge on the true rate (a stuck/slow filter would hide real speed).

check('EMA smoothing: starts at first sample, then converges toward it', () => {
    api.resetRateSmoothing();
    // First sample seeds the average (no smoothing on a cold filter).
    api.smoothRate(1000);
    eq(Math.round(api.getSmoothedRate()), 1000, 'first sample seeds the EMA:');

    // A spike pulls the average up but not all the way -> proves smoothing.
    api.smoothRate(9000);
    const afterSpike = api.getSmoothedRate();
    ok(afterSpike > 1000 && afterSpike < 9000,
        `EMA must sit between the samples, got ${afterSpike}`);

    // Repeated identical samples converge to that sample (no permanent lag).
    for (let i = 0; i < 60; i++) api.smoothRate(5000);
    ok(Math.abs(api.getSmoothedRate() - 5000) < 1,
        `EMA must converge on a steady rate, got ${api.getSmoothedRate()}`);

    // reset clears state so the next search starts fresh.
    api.resetRateSmoothing();
    eq(api.getSmoothedRate(), null, 'reset must clear the smoothed rate:');
    api.resetRateSmoothing();
});

// ---- newest key renders on top ---------------------------------------------
// History is stored oldest-first, so the view must reverse: the newest result
// appears at the top and the list scroll position stays at the top.

await asyncCheck('renderHistory: newest key first, newest at the top of the list', async () => {
    seedHistory([
        { publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1, attempts: 1, elapsed: 1 },
        { publicKey: 'c'.repeat(64), privateKey: 'd'.repeat(64), n: 2, attempts: 2, elapsed: 2 },
        { publicKey: 'e'.repeat(64), privateKey: 'f'.repeat(64), n: 3, attempts: 3, elapsed: 3 },
    ]);
    await api.loadHistory();
    api.renderHistory(false);

    const frames = getElementById('results').children;
    eq(frames.length, 3, 'all three entries render:');
    const headings = frames.map((f) => f.children[0].textContent);
    eq(headings[0], 'Key 3 Found!', 'newest (Key 3) is first:');
    eq(headings[1], 'Key 2 Found!', 'middle (Key 2) is second:');
    eq(headings[2], 'Key 1 Found!', 'oldest (Key 1) is last:');

    // The stored order must be untouched: reversing is a view concern only.
    const stored = api.getSavedKeys().map((e) => e.n);
    eq(JSON.stringify(stored), JSON.stringify([1, 2, 3]),
        'storage order stays oldest-first:');
});

await asyncCheck('renderHistory: scrolls to the newest (first) frame, not the oldest', async () => {
    seedHistory([
        { publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1, attempts: 1, elapsed: 1 },
        { publicKey: 'c'.repeat(64), privateKey: 'd'.repeat(64), n: 2, attempts: 2, elapsed: 2 },
    ]);
    await api.loadHistory();

    // Track which frame renderHistory asks to scroll into view.
    const list = getElementById('results');
    const created = [];
    const origAppend = list.appendChild.bind(list);
    list.appendChild = (child) => {
        const r = origAppend(child);
        child.scrollIntoView = () => { created.push(child); };
        return r;
    };

    api.renderHistory(true);
    list.appendChild = origAppend;

    eq(created.length, 1, 'exactly one frame is scrolled into view:');
    eq(created[0].children[0].textContent, 'Key 2 Found!',
        'must scroll to the newest key at the top of the list:');
});

// ---- pattern notice: what may I type, and why -----------------------------
// One shared orange frame explains every problem with the pattern, instead of a
// bare red "Invalid hex characters" with no rationale.

check('invalidHexChars: reports unique non-hex characters in order', () => {
    eq(JSON.stringify(api.invalidHexChars('')), '[]');
    eq(JSON.stringify(api.invalidHexChars('deadBEEF01')), '[]', 'valid hex is empty');
    eq(JSON.stringify(api.invalidHexChars('abg')), '["g"]');
    eq(JSON.stringify(api.invalidHexChars('zxy')), '["z","x","y"]', 'first-seen order');
    eq(JSON.stringify(api.invalidHexChars('gag')), '["g"]', 'deduplicated');
    eq(JSON.stringify(api.invalidHexChars('0x')), '["x"]', 'the 0x prefix form');
});

check('escapeHtml: neutralises markup from user input', () => {
    eq(api.escapeHtml('<script>'), '&lt;script&gt;');
    eq(api.escapeHtml('"'), '&quot;');
    eq(api.escapeHtml("'"), '&#39;');
    eq(api.escapeHtml('a&b'), 'a&amp;b');
});

check('updatePatternNotice: invalid hex shows the allowed set and the reason', () => {
    const notice = getElementById('reserved-notice');
    getElementById('prefix').value = 'abg';
    getElementById('suffix').value = '';
    api.updatePatternNotice();

    eq(notice.style.display, 'block', 'notice is shown');
    const html = notice.innerHTML;
    ok(html.includes('Only hexadecimal characters are allowed'),
        `must state the rule: ${html}`);
    ok(html.includes('0 1 2 3 4 5 6 7 8 9 a b c d e f'),
        `must list the allowed digits: ${html}`);
    ok(html.includes('64 hexadecimal digits'),
        `must explain why (key size): ${html}`);
    ok(html.includes('can never occur'), `must say why it cannot match: ${html}`);
    ok(html.includes('<code>g</code>'), `must name the offender: ${html}`);
    ok(html.includes('Prefix'), 'must say which field is wrong');
});

check('updatePatternNotice: names both fields and escapes injected markup', () => {
    const notice = getElementById('reserved-notice');
    getElementById('prefix').value = 'ab<';
    getElementById('suffix').value = 'cd!';
    api.updatePatternNotice();

    const html = notice.innerHTML;
    ok(html.includes('Prefix') && html.includes('Suffix'), `both fields named: ${html}`);
    ok(html.includes('<code>&lt;</code>'), `< must be escaped: ${html}`);
    ok(html.includes('<code>!</code>'), 'offending symbol still reported');
    ok(!html.includes('ab<'), 'raw user markup must not reach innerHTML');
});

check('updatePatternNotice: falls back to the reserved 00/FF warning', () => {
    const notice = getElementById('reserved-notice');
    getElementById('prefix').value = '00ab';
    getElementById('suffix').value = '';
    api.updatePatternNotice();

    eq(notice.style.display, 'block');
    ok(notice.innerHTML.includes('reserved'), `reserved text: ${notice.innerHTML}`);
    ok(!notice.innerHTML.includes('Only hexadecimal'),
        'valid-but-reserved must not claim a hex problem');
});

check('updatePatternNotice: the notice retires as soon as the boxes are cleared', () => {
    const notice = getElementById('reserved-notice');
    const prefix = getElementById('prefix');
    const suffix = getElementById('suffix');

    // Trigger each of the three notices in turn, then clear and confirm the
    // notice AND its text go away - not just the styling.
    prefix.value = '00ab'; suffix.value = '';
    api.updatePatternNotice();
    ok(notice.style.display !== 'none', 'reserved notice shown');

    prefix.value = '';
    api.updatePatternNotice();
    eq(notice.style.display, 'none', 'clearing the prefix retires the notice');
    ok(notice.hidden === true, 'notice must also be hidden from assistive tech');
    ok(!notice.innerHTML || notice.innerHTML === '',
        `stale text must not linger: ${notice.innerHTML}`);

    // Same for the impossible-pattern notice.
    prefix.value = 'ab'.repeat(40); suffix.value = 'cd'.repeat(40);
    api.updatePatternNotice();
    ok(notice.style.display !== 'none', 'impossible-pattern notice shown');

    prefix.value = ''; suffix.value = '';
    api.updatePatternNotice();
    eq(notice.style.display, 'none', 'clearing both retires it');
    ok(!notice.innerHTML || notice.innerHTML === '', 'text cleared');

    // And the invalid-hex notice.
    prefix.value = 'zz'; suffix.value = '';
    api.updatePatternNotice();
    ok(notice.style.display !== 'none', 'invalid-hex notice shown');
    prefix.value = '';
    api.updatePatternNotice();
    eq(notice.style.display, 'none', 'clearing retires the hex notice too');
});

check('refreshPatternUI is the single path used by both inputs', () => {
    // The inputs used to inline validateHex/updateEstimate/updatePatternNotice.
    // They now call refreshPatternUI() so programmatic clears cannot drift from
    // typed ones. Assert the attribute really points at the shared helper.
    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    const inputs = html.match(/id="(prefix|suffix)"[^>]*oninput="([^"]*)"/g) || [];
    eq(inputs.length, 2, 'both inputs declare an oninput handler:');
    for (const el of inputs) {
        ok(/oninput="refreshPatternUI\(\)"/.test(el),
            `input must use refreshPatternUI(): ${el}`);
    }
});

check('resetForm clears the notice through the shared path', () => {
    const notice = getElementById('reserved-notice');
    getElementById('prefix').value = '00ab';
    getElementById('suffix').value = '';
    api.updatePatternNotice();
    ok(notice.style.display !== 'none', 'precondition: notice is shown');

    api.resetForm();

    eq(getElementById('prefix').value, '', 'resetForm clears the prefix');
    eq(notice.style.display, 'none', 'resetForm must retire the notice');
    ok(!notice.innerHTML || notice.innerHTML === '', 'and clear its text');
});

check('updatePatternNotice: hidden when the pattern is fine', () => {
    const notice = getElementById('reserved-notice');
    getElementById('prefix').value = 'ab';
    getElementById('suffix').value = 'cd';
    api.updatePatternNotice();
    eq(notice.style.display, 'none');
});

// ---- impossible patterns ---------------------------------------------------
// A key is 64 hex digits. Prefix + suffix longer than that must overlap and
// can never both match, so the search would spin on every core forever.
// validateForm() must refuse to start one.

check('updatePatternNotice: flags a pattern longer than a key', () => {
    const notice = getElementById('reserved-notice');
    getElementById('prefix').value = 'ab'.repeat(40);
    getElementById('suffix').value = 'cd'.repeat(40);
    api.updatePatternNotice();

    eq(notice.style.display, 'block', 'impossible pattern is shown');
    const html = notice.innerHTML;
    ok(html.includes('Impossible pattern'), `must name the problem: ${html}`);
    ok(html.includes('160'), `must give the total: ${html}`);
    ok(html.includes('64'), 'must state the real key length');
});

check('updatePatternNotice: a 64-digit prefix alone is still allowed', () => {
    const notice = getElementById('reserved-notice');
    getElementById('prefix').value = 'ab'.repeat(32);
    getElementById('suffix').value = '';
    api.updatePatternNotice();
    eq(notice.style.display, 'none', 'exactly 64 digits is satisfiable');
});

check('validateForm: blocks prefix+suffix longer than 64 hex digits', () => {
    getElementById('prefix').value = 'ab'.repeat(40);
    getElementById('suffix').value = 'cd'.repeat(40);
    eq(api.validateForm(), false, 'an impossible search must not start');
});

check('validateForm: allows a satisfiable prefix+suffix pair', () => {
    // 32 + 32 = 64 hex digits: exactly one full key, so it is satisfiable.
    getElementById('prefix').value = 'ab'.repeat(16);
    getElementById('suffix').value = 'cd'.repeat(16);
    eq(api.validateForm(), true, '32+32 = 64 digits is fine');
});

check('validateForm: still requires some input and rejects bad hex', () => {
    getElementById('prefix').value = '';
    getElementById('suffix').value = '';
    eq(api.validateForm(), false, 'empty form rejected');

    getElementById('prefix').value = 'zz';
    getElementById('suffix').value = '';
    eq(api.validateForm(), false, 'non-hex rejected');

    getElementById('prefix').value = '';
    getElementById('suffix').value = '';
});

// ---- csv escaping ----------------------------------------------------------

check('csvCell: quotes and escapes correctly', () => {
    eq(api.csvCell('plain'), '"plain"');
    eq(api.csvCell('say "hi"'), '"say ""hi"""');
    eq(api.csvCell(null), '""');
    eq(api.csvCell(undefined), '""');
    eq(api.csvCell(12), '"12"');
});

// ---- progress past 100% ----------------------------------------------------
// The expected attempt count is the mean of a geometric distribution, so ~37%
// of searches legitimately exceed it. Clamping at 100% hid how far into the
// tail a long search actually was; the display must overshoot with a "+".

// ---- progress-line rendering ----------------------------------------------
// Past the expected mean the naive remaining-time figure goes negative, which
// used to blank the ETA entirely. The overshoot must be reported instead, and
// formatted with human units like everything else.

check('formatProgressLine: reports overshoot instead of hiding the ETA', () => {
    const under = api.formatProgressLine(500, 10, 1000);
    ok(under.includes('Progress: 50.00%'), `under 100%: ${under}`);
    ok(under.includes('ETA:'), `ETA expected while under the mean: ${under}`);
    ok(!under.includes('+50'), 'no + prefix below the mean');

    const exact = api.formatProgressLine(1000, 10, 1000);
    ok(exact.includes('Progress: 100.00%'), `exactly 100%: ${exact}`);
    ok(!exact.includes('+100'), '100% itself is not an overshoot');

    const over = api.formatProgressLine(1500, 10, 1000);
    ok(over.includes('Progress: +150.00%'), `overshoot must carry a +: ${over}`);
    ok(/past expected/.test(over), `must say it is past the mean: ${over}`);
    ok(!/ETA: -/.test(over), 'a negative ETA must never be rendered');
    // 1500 attempts where 1000 were expected: half the elapsed time was spent
    // beyond the mean, so the overshoot share is 33% (500 of 1500).
    ok(/33% past expected/.test(over), `overshoot percentage: ${over}`);
    ok(/50\.0s over/.test(over), `overshoot duration: ${over}`);
});

check('formatProgressLine: humanises long times', () => {
    const s = api.formatProgressLine(1000, 100, 1000000);
    ok(s.includes('ETA: 2h 46m 30s'), `eta should be humanized: ${s}`);
    ok(!/\d+\.\d+s\b/.test(s), `no raw float seconds: ${s}`);
});

check('formatProgressLine: handles an unknown total without NaN', () => {
    const s = api.formatProgressLine(500, 10, Infinity);
    ok(!/NaN|undefined/.test(s), `must degrade cleanly: ${s}`);
});

check('formatProgressLine: a display rate can override the raw one', () => {
    const raw = api.formatProgressLine(1000, 100, 10000);
    const smoothed = api.formatProgressLine(1000, 100, 10000, 87);
    ok(raw.includes('Rate: 100/s'), `raw rate: ${raw}`);
    ok(smoothed.includes('Rate: 87/s'), `EMA rate must be used for display: ${smoothed}`);
    // Progress maths must stay on the raw sample so it matches the attempts.
    ok(raw.split('Progress:')[1] === smoothed.split('Progress:')[1],
        'smoothing the rate must not change the progress figure');
});

check('progressEtaClause: returns only the trailing clause', () => {
    eq(api.progressEtaClause(500, 10, 1000), 'ETA: 50.0s');
    ok(/past expected/.test(api.progressEtaClause(1500, 10, 1000)),
        `overshoot clause: ${api.progressEtaClause(1500, 10, 1000)}`);
    eq(api.progressEtaClause(0, 0, 0), '', 'no clause when there is nothing to report');
});

check('formatDayHint: half-day steps, and withheld when meaningless', () => {
    eq(api.formatDayHint(30), '', 'under a day: nothing added');
    eq(api.formatDayHint(86400 - 1), '', 'just under a day: nothing added');
    eq(api.formatDayHint(86400), ' (~1 day)', 'exactly one day');
    eq(api.formatDayHint(86400 * 1.4), ' (~1.5 days)', 'half-day rounding');
    eq(api.formatDayHint(86400 * 2.5), ' (~2.5 days)', 'two and a half days');
    eq(api.formatDayHint(86400 * 9.9), ' (~10 days)', 'just inside the window');
    eq(api.formatDayHint(86400 * 10.5), '', 'past 10 days: withheld as false precision');
    eq(api.formatDayHint(0), '', 'zero');
    eq(api.formatDayHint(-5), '', 'negative');
    eq(api.formatDayHint(NaN), '', 'NaN');
    eq(api.formatDayHint(Infinity), '', 'infinite');
});

check('formatEta: human duration with the day hint appended', () => {
    eq(api.formatEta(30), '30.0s');
    eq(api.formatEta(86400), '24h 0m 0s (~1 day)');
    eq(api.formatEta(86400 * 2.5), '60h 0m 0s (~2.5 days)');
    eq(api.formatEta(3600), '1h 0m 0s', 'sub-day gets no hint');
});

// ---- ETA smoothing ---------------------------------------------------------
// The ETA is the most eye-catching number on the page and the least stable, so
// it must not chase every per-batch rate sample.
check('smoothEta: withheld until enough samples, then eased in', () => {
    api.resetEtaSmoothing();
    // Early batches are slower while WASM warms up; showing an ETA off them
    // would be misleading, so the first few samples produce nothing at all.
    for (let i = 1; i < api.ETA_MIN_SAMPLES; i++) {
        eq(api.smoothEta(1000), null,
            `sample ${i} should still be withheld`);
    }
    const first = api.smoothEta(1000);
    ok(first !== null, 'the ETA appears once enough samples exist');
    eq(first, 1000, 'the first shown value is the first sample, unmodified');
});

check('smoothEta: damps a spike instead of tracking it linearly', () => {
    api.resetEtaSmoothing();
    for (let i = 0; i < api.ETA_MIN_SAMPLES; i++) api.smoothEta(1000);
    const before = api.smoothEta(1000);
    // A 10x jump in the underlying rate must NOT move the ETA by 10x; that
    // hopping is exactly what this smoothing exists to remove. The EMA moves a
    // fraction of the way toward the new sample, so compare against the linear
    // response it is deliberately not giving.
    const after = api.smoothEta(10000);
    ok(after > before, 'the ETA does respond, just gently');
    ok(after < before * 10,
        `ETA tracked the spike linearly (${before} -> ${after})`);
    ok(after < before * 3,
        `ETA still moved too eagerly (${before} -> ${after})`);
});

check('smoothEta: converges toward the true value without overshooting', () => {
    api.resetEtaSmoothing();
    for (let i = 0; i < api.ETA_MIN_SAMPLES; i++) api.smoothEta(0);
    let v = 0;
    for (let i = 0; i < 40; i++) {
        v = api.smoothEta(1000);
        ok(v <= 1000, 'must not overshoot the target');
    }
    ok(v > 990, `after 40 samples should be near 1000, got ${v}`);
});

check('smoothEta: rejects non-finite and non-positive input', () => {
    api.resetEtaSmoothing();
    for (let i = 0; i < api.ETA_MIN_SAMPLES; i++) api.smoothEta(1000);
    const stable = api.smoothEta(1000);
    eq(api.smoothEta(NaN), null, 'NaN is rejected, not folded in');
    eq(api.smoothEta(Infinity), null, 'Infinity is rejected');
    eq(api.smoothEta(0), null, 'zero is rejected');
    eq(api.smoothEta(-5), null, 'negative is rejected');
    // Rejected samples must be dropped, not folded in as NaN/0/Infinity.
    eq(api.smoothEta(1000), stable, 'rejected samples leave the held value unchanged');
});

// ---- Worker scaling model --------------------------------------------------
check('workerScale: anchored to the measured 8-thread ceiling', () => {
    // The anchor is now 4.08x, measured with the real primitive
    // (tools/bench_keygen_scaling.mjs). It used to be 2.3x from an older
    // browser measurement; measuring the actual wasm primitive on the same
    // hardware topology showed the crypto scales to roughly 4x, so the old
    // anchor made every ETA about 1.8x too pessimistic.
    eq(api.WORKER_SCALE_MEASURED[8], 4.08, 'the measurement is recorded');
    eq(Math.round(api.workerScale(8) * 100) / 100, 4.08,
        '8 workers must reproduce the measured 4.08x');
    eq(api.workerScale(1), 1, 'one worker is 1x');
    eq(api.workerScale(0), 1, 'zero workers is 1x');
});

check('workerScale: concave and sublinear', () => {
    // Linear scaling (speedup == workers) is the bug being fixed.
    for (const n of [2, 4, 8, 16, 32]) {
        ok(api.workerScale(n) < n,
            `${n} workers scaled ${api.workerScale(n)}x; expected less than ${n}x`);
        ok(api.workerScale(n) > 1,
            `${n} workers should still be faster than one`);
    }
    // Per-worker efficiency must fall as workers are added; that is precisely
    // what "workers share cores" means. (A power law has a *constant* gain per
    // doubling, so the giveaway is efficiency, not diminishing doublings.)
    const eff2 = api.workerScale(2) / 2;
    const eff8 = api.workerScale(8) / 8;
    const eff32 = api.workerScale(32) / 32;
    ok(eff2 > eff8 && eff8 > eff32,
        `per-worker efficiency must fall: ${eff2.toFixed(2)} > ${eff8.toFixed(2)} > ${eff32.toFixed(2)}`);
});

check('workerScale: the measured table drives the curve exactly', () => {
    // The model is now a table of MEASURED points rather than one power law
    // through an 8-thread anchor. Measuring the real primitive showed scaling is
    // near-linear to 2 threads and then flattens sharply, which a single-anchor
    // law cannot represent - it mispredicted 4 threads by a factor of two.
    const pts = api.WORKER_SCALE_POINTS;
    ok(Array.isArray(pts) && pts.length >= 3,
        'the scaling model must be a table of measured points');
    ok(pts.length > 0 && pts[0][0] === 1 && pts[0][1] === 1,
        'the table must start at 1 thread / 1.00x');

    // Strictly ascending in both axes, with falling marginal gain, or the
    // interpolation below is meaningless.
    for (let i = 1; i < pts.length; i++) {
        ok(pts[i][0] > pts[i - 1][0], `thread counts must ascend (index ${i})`);
        ok(pts[i][1] > pts[i - 1][1],
            `measured speedups must ascend (index ${i}); the curve is concave `
            + 'and never flat or falling');
        ok(pts[i][1] / pts[i - 1][1] < pts[i][0] / pts[i - 1][0],
            `marginal gain must fall between ${pts[i - 1][0]} and ${pts[i][0]} `
            + `threads (${(pts[i][1] / pts[i - 1][1]).toFixed(2)}x vs `
            + `${pts[i][0] / pts[i - 1][0]}x) - that is the point of the table`);
    }

    // Exact at every measured point.
    for (const [n, v] of pts) {
        eq(api.workerScale(n).toFixed(3), v.toFixed(3),
            `workerScale(${n}) must return its measured ${v}`);
    }

    // Log-linear between points: smooth, strictly between the endpoints.
    for (let i = 1; i < pts.length; i++) {
        const [nLo, vLo] = pts[i - 1];
        const [nHi, vHi] = pts[i];
        for (const frac of [0.25, 0.5, 0.75]) {
            const n = Math.exp(Math.log(nLo) + frac * (Math.log(nHi) - Math.log(nLo)));
            const v = api.workerScale(n);
            ok(v > vLo && v < vHi,
                `workerScale(${n.toFixed(2)}) = ${v.toFixed(3)} must fall strictly `
                + `between ${vLo} and ${vHi}`);
        }
    }

    // Never below 1, and defined for nonsense input.
    for (const bad of [0, -1, NaN, undefined, null, 'x']) {
        eq(api.workerScale(bad), 1, `workerScale(${bad}) must fall back to 1`);
    }
});

check('workerScale: clamps at the measured ceiling instead of extrapolating', () => {
    // Extra threads cannot beat what was observed on 4 physical cores, and an
    // unbounded extrapolation would promise throughput nobody has seen. This
    // matters because detectOptimalWorkers caps at 32, so a 16- or 32-thread
    // machine would otherwise be told it is nearly twice as fast as measured.
    const last = api.WORKER_SCALE_POINTS[api.WORKER_SCALE_POINTS.length - 1];
    for (const n of [last[0], last[0] + 1, 16, 32, 64, 1024]) {
        eq(api.workerScale(n), last[1],
            `workerScale(${n}) must clamp to the measured ${last[1]}x ceiling`);
    }
    eq(api.workerScale(8), api.WORKER_SCALE_MEASURED[8],
        'the 8-thread lookup must agree with the measured value');
    eq(api.WORKER_SCALE_MAX, last[1], 'WORKER_SCALE_MAX must be the top measured point');
});

check('workerScale: the README table matches the code', () => {
    // The README's "Model says" column is a claim about this code, and a table
    // that stops describing workerScale() is exactly how the stale 0.457 /
    // 1.37x / 1.87x figures survived unnoticed in the first place.
    //
    // Split on newlines before matching: the file is CRLF, and an `^` anchor
    // would sit after the \n leaving a stray \r on the end of each row.
    const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
    const rows = readme.split(/\r?\n/);
    for (const n of [1, 2, 3, 4, 6, 8]) {
        const want = api.workerScale(n).toFixed(2) + 'x';
        // Rows may be bolded (|**8**|), so allow ** around the worker count.
        const rowRe = new RegExp(`^\\|\\s*\\**${n}\\**\\s*\\|`);
        const row = rows.find((l) => rowRe.test(l.trim()));
        ok(row !== undefined, `the README scaling table must have a row for ${n} workers`);
        if (row === undefined) continue;
        ok(row.includes(want),
            `the README's scaling table must show workerScale(${n}) = ${want}, `
            + `got row ${JSON.stringify(row.trim())}; the documented figures have `
            + 'drifted from the code');
    }
});

check('live rate: ignores the first reports, then sums every worker', () => {
    // The self-calibration's contract: only trust a worker once it has reported
    // enough times, and only produce a figure once EVERY live worker is
    // trustworthy. Partial data would understate the aggregate and so overstate
    // the ETA, which is the failure that matters.
    const need = api.LIVE_RATE_MIN_SAMPLES;
    ok(need >= 2, `the warm-up floor must exclude the noisy first report, got ${need}`);

    api.resetLiveRates();
    eq(api.liveAggregateKeysPerSecond(4), null, 'no data means no figure');

    // One worker reporting a lot must not be enough for a 4-worker search.
    for (let k = 0; k < need * 5; k++) api.recordLiveRate(0, 100);
    eq(api.liveAggregateKeysPerSecond(4), null,
        'a single reporting worker must not stand in for four');

    // Three of four workers still incomplete.
    for (let k = 0; k < need; k++) api.recordLiveRate(1, 200);
    for (let k = 0; k < need; k++) api.recordLiveRate(2, 300);
    for (let k = 0; k < need - 1; k++) api.recordLiveRate(3, 400);
    eq(api.liveAggregateKeysPerSecond(4), null, 'three of four is still partial');

    // The last worker completes: now the aggregate is the SUM of all four.
    api.recordLiveRate(3, 400);
    const total = api.liveAggregateKeysPerSecond(4);
    ok(total !== null, 'all workers reporting must yield a figure');
    eq(total, 100 + 200 + 300 + 400, 'the aggregate must be the sum across workers');
    api.resetLiveRates();
});

check('live rate: replaces a worker\'s own sample instead of accumulating', () => {
    api.resetLiveRates();
    const need = api.LIVE_RATE_MIN_SAMPLES;
    for (let k = 0; k < need; k++) api.recordLiveRate(0, 100);
    eq(api.liveAggregateKeysPerSecond(1), 100, 'the first sample is the figure');
    // A newer report from the same worker supersedes the old one.
    for (let k = 0; k < 5; k++) api.recordLiveRate(0, 250);
    eq(api.liveAggregateKeysPerSecond(1), 250,
        'a worker must hold its newest rate, not a running total of its rates');
    api.resetLiveRates();
});

check('live rate: rejects nonsense and never reports a non-positive figure', () => {
    api.resetLiveRates();
    const need = api.LIVE_RATE_MIN_SAMPLES;
    for (const bad of [0, -1, NaN, Infinity, 'x', null, undefined]) {
        for (let k = 0; k < need * 2; k++) api.recordLiveRate(0, bad);
    }
    eq(api.liveAggregateKeysPerSecond(1), null,
        'a worker that only ever reports nonsense must yield no figure');
    eq(api.liveRateIsComplete(1), false,
        'and must not count as complete');
    api.resetLiveRates();
});

check('live rate: a zero or nonsensical worker count is never complete', () => {
    api.resetLiveRates();
    for (const n of [0, -1, NaN, undefined, null, 'x']) {
        eq(api.liveRateIsComplete(n), false, `liveRateIsComplete(${n}) must be false`);
        eq(api.liveAggregateKeysPerSecond(n), null,
            `liveAggregateKeysPerSecond(${n}) must be null`);
    }
    api.resetLiveRates();
});

check('the grey estimate flips from estimated to measured', () => {
    // The point of the whole exercise: after a moment of running, the figure the
    // user plans around is a measurement of THIS machine, not a table measured
    // on someone else's.
    navigatorMock.hardwareConcurrency = 4;
    getElementById('prefix').value = 'ab';
    getElementById('suffix').value = '';
    api.resetLiveRates();

    api.updateEstimate();
    const modelled = api.getEstimateText();
    ok(/keys\/s (estimated|calibrated)\)/.test(modelled),
        `with no live data the line must not claim to be measured: ${modelled}`);

    const need = api.LIVE_RATE_MIN_SAMPLES;
    for (let k = 0; k < need; k++) {
        api.recordLiveRate(0, 1000);
        api.recordLiveRate(1, 1000);
        api.recordLiveRate(2, 1000);
        api.recordLiveRate(3, 1000);
    }
    api.updateEstimate();
    const measured = api.getEstimateText();
    ok(/keys\/s measured\)/.test(measured),
        `with full live data the line must be labelled measured: ${measured}`);
    // 4 workers x 1000 keys/s = 4000, which is far above what the table models.
    ok(/up to 4,000 keys\/s/.test(measured),
        `the measured aggregate must drive the headline, not the model: ${measured}`);

    api.resetLiveRates();
    navigatorMock.hardwareConcurrency = 8;
});
check('the grey estimate reports the worker count its rate describes', () => {
    // The line must never contradict itself. Pre-flight the count is the PLANNED
    // one; once the rate is measured it is the number actually running. Saying
    // "8 workers" beside a figure derived from six - because two failed to
    // initialise - would be exactly the invented precision this line exists to
    // avoid.
    navigatorMock.hardwareConcurrency = 8;
    getElementById('prefix').value = 'ab';
    api.resetLiveRates();
    api.updateEstimate();
    ok(/\(8 workers,/.test(api.getEstimateText()),
        `pre-flight must report the planned worker count: ${api.getEstimateText()}`);

    // Stand in six running workers using the existing test hook, so no
    // test-only production code is needed just to control the worker count.
    api.terminateAllWorkers();
    for (let i = 0; i < 6; i++) api.__trackWorker({ terminate() {} });

    const need = api.LIVE_RATE_MIN_SAMPLES;
    for (let k = 0; k < need; k++) {
        for (let w = 0; w < 6; w++) api.recordLiveRate(w, 1000);
    }
    api.updateEstimate();
    const txt = api.getEstimateText();
    ok(/\(6 workers,/.test(txt),
        `a measured rate over 6 workers must be labelled 6, not 8: ${txt}`);
    ok(/up to 6,000 keys\/s measured/.test(txt),
        `and the figure must be the sum over those same 6 workers: ${txt}`);

    api.terminateAllWorkers();
    api.resetLiveRates();
    navigatorMock.hardwareConcurrency = 8;
});

check('live rate: a dead worker is excluded from the aggregate', () => {
    // Regression. liveWorkerRates is keyed by worker index and is never pruned
    // during a run, so an entry survives its worker. The aggregate used to sum
    // the whole map, which kept counting a worker that had died since it last
    // reported: with one of four workers failing it reported 4000 keys/s for
    // three working at 1000 each - 33% inflation, and an ETA that looked better
    // than the search actually was.
    const need = api.LIVE_RATE_MIN_SAMPLES;
    api.resetLiveRates();
    for (let k = 0; k < need; k++) {
        for (let w = 0; w < 4; w++) api.recordLiveRate(w, 1000);
    }
    eq(api.liveAggregateKeysPerSecond(4), 4000, 'all four reporting');

    // Worker 3 dies: the main thread's worker count drops, the map does not.
    eq(api.liveAggregateKeysPerSecond(3), 3000,
        'the aggregate must count only the workers still running');
    eq(api.liveAggregateKeysPerSecond(2), 2000,
        'and shrink again as more workers go away');
    eq(api.liveAggregateKeysPerSecond(1), 1000,
        'down to a single worker');

    // Completeness is now judged over the LIVE slice. A worker that never
    // reported at all must still block the figure, even if dead workers filled
    // the map to a sufficient size.
    api.resetLiveRates();
    for (let k = 0; k < need; k++) api.recordLiveRate(7, 5000);
    eq(api.liveAggregateKeysPerSecond(2), null,
        'an unreported live worker must block the figure even when the map is full');
    api.resetLiveRates();
});

check('live rate: a worker that never reported blocks the figure', () => {
    // The companion case to the above: the map can be large because many
    // workers reported over the run, but if the LOWEST-indexed workers are not
    // among them, there is no trustworthy aggregate.
    const need = api.LIVE_RATE_MIN_SAMPLES;
    api.resetLiveRates();
    for (let k = 0; k < need; k++) api.recordLiveRate(1, 1000);
    for (let k = 0; k < need; k++) api.recordLiveRate(2, 1000);
    eq(api.liveAggregateKeysPerSecond(3), null,
        'worker 0 never reported, so a 3-worker figure is not trustworthy');
    for (let k = 0; k < need; k++) api.recordLiveRate(0, 1000);
    eq(api.liveAggregateKeysPerSecond(3), 3000,
        'once every live worker has reported, the figure appears');
    api.resetLiveRates();
});
check('resetLiveRates drops the measurements with the run', () => {
    // A stale aggregate must not survive into the next search, or the estimate
    // would keep claiming to be measured after the workers that produced it are
    // gone.
    const need = api.LIVE_RATE_MIN_SAMPLES;
    api.resetLiveRates();
    for (let k = 0; k < need; k++) api.recordLiveRate(0, 500);
    ok(api.liveAggregateKeysPerSecond(1) !== null, 'precondition: data present');
    api.resetLiveRates();
    eq(api.liveAggregateKeysPerSecond(1), null,
        'after a reset there must be no measured rate');
});
// ---- Live ETA layout ------------------------------------------------------
// As one string the ETA reflowed whenever a field changed digit count, so the
// figures visibly hopped. It is now split into slots that each reserve their
// width.
check('live ETA: slots reserve their width so the digits cannot shift', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    // Every slot is a real element rather than part of one text blob.
    for (const id of ['live-eta-days', 'live-eta-h', 'live-eta-m', 'live-eta-s']) {
        ok(html.includes(`id="${id}"`), `missing ETA slot #${id}`);
    }

    // Tabular figures are what stop a digit changing width at all.
    ok(/\.eta-fields\s*\{[^}]*font-variant-numeric:\s*tabular-nums/.test(html),
        'the ETA must use tabular figures, or digit widths still vary');

    // Hours are the hours WITHIN the day (0-23) because the days slot now carries
    // the magnitude, so two digits is the widest case for hours as well as for
    // minutes and seconds.
    ok(/\.eta-num\s*\{[^}]*min-width:\s*2ch/.test(html),
        'hours must reserve two digits now that days carry the magnitude');
    // Narrow screens still need a fixed hour slot, just no smaller than that.
    const narrow = html.slice(html.indexOf('@media (max-width: 420px)'));
    ok(/@media \(max-width: 420px\)[\s\S]*?\.eta-num\s*\{[^}]*min-width:\s*\d+\s*ch/.test(narrow),
        'narrow screens must keep a fixed hour slot');
    ok(/\.eta-num-2\s*\{[^}]*min-width:\s*2ch/.test(html),
        'minutes and seconds must reserve exactly two digits');

    // The day estimate sits in front of the hours.
    const days = html.indexOf('id="live-eta-days"');
    const hours = html.indexOf('id="live-eta-h"');
    ok(days !== -1 && hours !== -1 && days < hours,
        'the day estimate must come before the hours');

    // Its own full-width row, so the slots are not cramped into one column.
    ok(/\.live-cell-eta\s*\{[^}]*grid-column:\s*1 \/ -1/.test(html),
        'the ETA must span the full width of the panel');
});

check('etaParts: splits a duration into padded display fields', () => {
    eq(api.etaParts(0).hours, 0);
    eq(api.etaParts(0).minutes, 0);
    eq(api.etaParts(0).seconds, 0);

    // 116h 27m 22s -- the multi-week case this layout exists for. It must read as
    // "4d 20h", not "116h": days carry the magnitude so the figure is legible
    // at a glance, and the hours slot can then be two digits wide.
    let p = api.etaParts(116 * 3600 + 27 * 60 + 22);
    eq(p.days, 4);
    eq(p.hours, 20);
    eq(p.minutes, 27);
    eq(p.seconds, 22);
    ok(/\(~5 days\)/.test(p.dayHint), 'the day estimate is still attached');

    // The day figure must never be withheld, which is what it previously was:
    // formatDayHint() returns nothing past ~10 days, so the longest searches
    // were the only ones with no day unit anywhere.
    eq(api.etaParts(40 * 86400).days, 40, '40 days must still report 40');
    eq(api.etaParts(400 * 86400).days, 400, '400 days must still report 400');
    eq(api.etaParts(86400).days, 1, 'exactly one day');
    eq(api.etaParts(86400).hours, 0, 'exactly one day has zero hours');
    eq(api.etaParts(2 * 86400 + 3600).hours, 1, 'hours roll into the day');

    // Single digits must be padded, or "05m" is one glyph narrower than "15m".
    eq(api.pad2(0), '00');
    eq(api.pad2(7), '07');
    eq(api.pad2(42), '42');
    eq(api.pad2(60), '60');
    for (const n of [0, 7, 42, 59]) {
        eq(api.pad2(n).length, 2, `${n} must render as exactly two digits`);
    }

    // Degenerate input must not produce NaN in the DOM.
    const bad = api.etaParts(NaN);
    eq(bad.hours, 0, 'NaN hours');
    eq(bad.minutes, 0, 'NaN minutes');
    eq(bad.seconds, 0, 'NaN seconds');
    eq(api.etaParts(-5).hours, 0, 'negative input clamps to zero');
});

check('renderEta: writes padded digits into the slots', () => {
    api.renderEta(116 * 3600 + 7 * 60 + 5);
    eq(api.getLiveEtaText('live-eta-days'), '4d', 'days carry the magnitude');
    eq(api.getLiveEtaText('live-eta-h'), '20');
    eq(api.getLiveEtaText('live-eta-m'), '07', 'minutes padded to two');
    eq(api.getLiveEtaText('live-eta-s'), '05', 'seconds padded to two');

    // Under a day there is no day figure, and the slot must be blank rather
    // than showing a stale "4d" from the previous longer ETA.
    api.renderEta(65);
    eq(api.getLiveEtaText('live-eta-days'), '');
    eq(api.getLiveEtaText('live-eta-h'), '0');
    eq(api.getLiveEtaText('live-eta-m'), '01');
    eq(api.getLiveEtaText('live-eta-s'), '05');

    // A message state blanks the slots but must not leave stale digits behind.
    api.renderEta(116 * 3600);
    api.setEtaMessage('sampling...');
    eq(api.getLiveEtaText('live-eta-days'), 'sampling...');
    eq(api.getLiveEtaText('live-eta-h'), '');
    eq(api.getLiveEtaText('live-eta-m'), '');
    eq(api.getLiveEtaText('live-eta-s'), '');

    // ...and switching back to a real duration must restore them.
    api.renderEta(65);
    eq(api.getLiveEtaText('live-eta-days'), '');
    eq(api.getLiveEtaText('live-eta-h'), '0');
    eq(api.getLiveEtaText('live-eta-m'), '01');
    eq(api.getLiveEtaText('live-eta-s'), '05');
});

check('visitor counter: static image badge, centred under the info frame', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    // No script: a counter must not add JS to a page that mines with every core.
    ok(!/freevisitorcounters\.com/.test(html),
        'the retired JS-dependent counter must not come back');
    ok(/api\.visitorbadge\.io\/api\/visitors\?path=github\.com%2Fneohiro%2Fmeshcore-vanity-key/.test(html),
        'the badge must point at this repo visitor-counter path');
    ok(/visitorbadge\.io\/status\?path=github\.com%2Fneohiro%2Fmeshcore-vanity-key/.test(html),
        'the badge must link to the stats page for this repo');
    ok(/referrerpolicy="no-referrer"/.test(html),
        'the badge must not leak the referring URL');

    // Placed after the info frame, and centred.
    const info = html.indexOf('class="info"');
    const badge = html.indexOf('class="visitor-counter"');
    ok(info !== -1 && badge !== -1 && badge > info,
        'the counter must come after the info frame');
    ok(/\.visitor-counter\s*\{[^}]*text-align:\s*center/.test(html),
        'the counter must be centred');
    ok(/\.visitor-counter\s*\{[^}]*margin-top:/.test(html),
        'the counter needs spacing so it reads as a footer');
});

check('background: subtle gradient and rare star flickers, reduced-motion safe', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    ok(/radial-gradient/.test(html), 'the backdrop should use a subtle gradient');
    // The starfield must be decorative only, and must not animate for anyone
    // who asked for reduced motion.
    ok(/class="starfield" aria-hidden="true"/.test(html),
        'the starfield must be hidden from assistive tech');
    ok(/@media \(prefers-reduced-motion: reduce\)[\s\S]*?\.starfield[\s\S]*?display:\s*none/.test(html),
        'the starfield must be disabled under prefers-reduced-motion');
    // A fixed layer that spans the viewport needs to stay out of the way.
    ok(/\.starfield\s*\{[^}]*pointer-events:\s*none/.test(html),
        'the starfield must not intercept clicks');
    ok(/z-index:\s*0/.test(html) && /\.container, \.info\s*\{[^}]*z-index:\s*1/.test(html),
        'content must sit above the starfield');
});

check('estimate: shows only measurements, not the scaling model', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    // The grey line carries only actual measurements: expected attempts,
    // estimated time, worker count, measured keys/s.
    //
    // Both halves of the old parenthetical are now gone. The provenance
    // ("scale derived from 2.3x at 8 threads") went first because it named a
    // measurement made on a different host; the multiplier itself
    // ("improvement is only ~2.3x at 8 threads") went next because it is a
    // property of the extrapolation model rather than a measurement of the
    // machine actually running the search.
    //
    // The model still drives totalRate and therefore the ETA. It is just not
    // advertised - WORKER_SCALE_MEASURED and the README's "Worker scaling"
    // section remain the documented home for it.
    ok(!/scale derived from 2\.3x at 8 threads/.test(html),
        "the estimate must not print the scaling factor's provenance inline");
    // Strip comments before scanning for the removed wording: the rationale
    // comment above updateEstimate quotes the old text on purpose, and a
    // whole-file scan would flag its own explanation.
    const code = html.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
    ok(!/improvement is only ~/.test(code),
        'the estimate must not advertise the scaling multiplier');
    ok(!/workers share cores/.test(code),
        'the cores-sharing caveat must not appear in the estimate');
    ok(!/so actual will be lower/.test(html),
        'the vague "actual will be lower" caveat must be gone');
    // And the measurements it DOES show must all still be wired up.
    ok(/Expected attempts:/.test(html), 'expected attempts must still be shown');
    ok(/Estimated time: ~/.test(html), 'estimated time must still be shown');
    ok(/keys\/s/.test(html), 'the measured rate must still be shown');
});

check('progress: no duplicate id and no stale status under the panel', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    const ids = [...html.matchAll(/id="progress-text"/g)];
    eq(ids.length, 1,
        'id="progress-text" must appear exactly once; duplicates made the stale status line linger under the live logs');

    // The transient status must sit ABOVE the live panel. It used to render
    // below it, so "Starting..." remained on screen underneath the figures.
    const status = html.indexOf('id="progress-text"');
    const panel = html.indexOf('id="live-logs"');
    ok(status !== -1 && panel !== -1, 'both the status line and the panel must exist');
    ok(status < panel,
        'the transient status must be above the live panel, not lingering under it');

    // The live panel is what a screen reader should announce now that the
    // status line no longer updates during mining.
    ok(/id="live-logs"[^>]*aria-live="polite"/.test(html),
        'the live panel must be aria-live, or mining updates are silent');
});

check('progress: "Starting..." is retired once mining reports', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    // The bug: startMining() wrote 'Starting...' and nothing ever cleared it,
    // so it stayed on screen above the figures for the entire run.
    ok(html.includes("setStatusText('Starting...')"),
        'the startup message should be set through setStatusText');

    // The clear must sit INSIDE the progress branch. Asserted structurally by
    // slicing the branch body (rather than with a proximity regex, which broke
    // the moment a comment was added between the two lines) and requiring no
    // other handler to appear in between.
    const pStart = html.indexOf("e.data.type === 'progress'");
    ok(pStart !== -1, 'the progress branch must exist');
    const pEnd = html.indexOf("e.data.type === 'found'", pStart);
    const branch = html.slice(pStart, pEnd);
    ok(branch.includes('clearStatusText()'),
        'the first progress report must retire the startup status');
    ok(branch.indexOf('clearStatusText()') < branch.indexOf('pushRateGraphSample('),
        'the status must be cleared before the figures are updated');

    // A short search can match inside the FIRST batch (BATCH_SIZE 256) and so
    // deliver 'found' before any 'progress' message fires. Clearing only in the
    // progress branch left "Starting..." in the DOM for the next search's
    // startup. Every terminal branch must retire it too.
    for (const kind of ['found', 'error']) {
        const bStart = html.indexOf(`e.data.type === '${kind}'`);
        ok(bStart !== -1, `the ${kind} branch must exist`);
        const bEnd = html.indexOf('} else if (', bStart + 10);
        const body = html.slice(bStart, bEnd === -1 ? undefined : bEnd);
        ok(body.includes('clearStatusText()'),
            `the ${kind} branch must also retire the startup status`);
    }

    // Hiding the element (not just emptying it) is what removes the line box.
    // Emptying alone left a blank row that pushed the figures down.
    ok(/function setStatusText\(text\)[\s\S]{0,400}?\.hidden = !text/.test(html),
        'setStatusText must toggle the hidden property');
    ok(/\.status-text\[hidden\]\s*\{\s*display:\s*none/.test(html),
        'a hidden status line must not reserve a blank row');
});

check('status line: nothing writes it behind setStatusText()', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    // setStatusText() is what keeps `hidden` in sync with the text. A direct
    // textContent write sets the text but leaves `hidden` stale, so the line
    // cannot be retired properly and reappears over the next run. The export
    // path did exactly this ("Preparing export..."), and the libsodium-failure
    // path hid the panel without ever clearing the text.
    const direct = html.match(/getElementById\(['"]progress-text['"]\)[\s\S]{0,120}?\.textContent\s*=/g) || [];
    ok(direct.length === 1,
        `progress-text must only be written inside setStatusText, found `
        + `${direct.length} direct write(s)`);

    // Every path that hides the live panel must retire the status too, or the
    // text is still in the DOM when the panel next opens.
    //
    // Scope: the nearest `clearStatusText()` must sit within the same block as
    // the hide. Checking "does this function contain any clear" was tried and
    // is too weak - a SIBLING handler's clear vouched for a path that had none
    // (export onmessage cleared, so deleting the onerror one still passed).
    // Per-function counting was also tried and is too strict, since a defensive
    // clear (setFormDisabled-era code clears more often than it hides) breaks
    // the equality. Counting hides vs clears per function is the check that
    // survives both cases, and it is what runs below.
    const HIDE = "document.getElementById('progress').classList.add('hidden')";
    const fnStartAt = (at) => {
        const i = html.lastIndexOf('\n        function ', at);
        return i === -1 ? 0 : i;
    };
    const byFn = new Map();
    let h;
    while ((h = html.indexOf(HIDE, h === undefined ? 0 : h + 1)) !== -1) {
        const key = fnStartAt(h);
        byFn.set(key, (byFn.get(key) || 0) + 1);
    }
    ok(byFn.size >= 4,
        `expected the panel to be hidden across several functions, found ${byFn.size}`);

    const short = [];
    for (const [key, hides] of byFn) {
        const name = (html.slice(key).match(/function ([A-Za-z0-9_]+)/) || [])[1] || '?';
        const next = html.indexOf('\n        function ', key + 1);
        const body = html.slice(key, next === -1 ? undefined : next);
        // Count only STATEMENT calls, excluding ones inside comments - a
        // comment mentioning clearStatusText() must not count as satisfying it.
        const clears = (body.replace(/\/\/[^\n]*/g, '').match(/clearStatusText\(\)/g) || []).length;
        if (clears < hides) short.push(`${name}: ${hides} hide(s), ${clears} clear(s)`);
    }
    ok(short.length === 0,
        'every function that hides the live panel must call clearStatusText() '
        + `at least as often as it hides it - ${short.join('; ')}`);
});

// ---- Behavioural mining lifecycle -------------------------------------------
//
// These drive the REAL startMining/stopMining/resetForm handlers against the
// controllable worker pool, rather than asserting on source text. An executed
// test is what actually pins behaviour: it still fails if the logic changes in a
// way the static checks below would not notice. The static checks are kept as a
// cheap backstop.

function primeForm() {
    getElementById('prefix').value = 'ab';
    getElementById('suffix').value = '';
    workerPool.length = 0;
    exportPool.length = 0;
}

// Seed more than 100 keys so exportHistory takes the Worker path.
//
// This is hygiene, not convenience: addKeyToHistory() persists on every call,
// and persistHistory() is async, so seeding hundreds of keys without awaiting
// leaves writes in flight that land AFTER this test finishes and clobber the
// storage a later test set up. Flushing here, and restoring the obfuscation
// key cache and storage afterwards, keeps the export tests self-contained.
async function seedHistoryForExport() {
    api.clearHistory();
    api.__resetObfKeyCache();
    for (let i = 0; i < 101; i++) {
        api.addKeyToHistory({
            publicKey: 'ab' + String(i).padStart(62, '0'),
            privateKey: 'c'.repeat(64),
            attempts: i + 1,
            elapsed: 0.1,
            pattern: 'prefix ab',
        });
    }
    // Let every queued persist settle before the test moves on.
    await api.persistHistory();
    await new Promise((r) => setTimeout(r, 0));
    await api.persistHistory();
    await new Promise((r) => setTimeout(r, 0));
}

async function teardownExportTest() {
    api.clearHistory();
    api.__resetObfKeyCache();
    storage.delete(api.HISTORY_KEY);
    // Clear the derived secret so a later test starts from the same state it
    // would have had if this file had never seeded 100+ keys. Done against the
    // harness's own IndexedDB mock rather than through a production hook.
    for (const [, store] of idbData) store.clear();
    // The export path also creates a URL for the download itself, which
    // downloadFile() revokes on a 1s timer. Draining the mock's URL set keeps
    // that pending revocation from perturbing later tests that snapshot
    // urlStats.objectURLs.size.
    urlStats.objectURLs.clear();
    workerPool.length = 0;
    exportPool.length = 0;
    await new Promise((r) => setTimeout(r, 0));
}

// startMining() awaits awaitSodium(), which throws unless a libsodium global is
// present. The sandbox deliberately has none (a test above asserts that), so
// install one for the duration of a lifecycle check and remove it afterwards,
// leaving the rest of the suite's assumptions intact.
async function withSodium(fn) {
    const stub = {
        ready: Promise.resolve(),
        crypto_sign_seed_keypair(seed) {
            const pk = new Uint8Array(32);
            pk[0] = (seed[0] || 0) ^ 0xab;
            pk[31] = seed[31] & 0xff;
            return { publicKey: pk, privateKey: new Uint8Array(64) };
        },
    };
    sandbox.libsodium = stub;
    sandbox.sodium = stub;
    try {
        await fn();
    } finally {
        delete sandbox.libsodium;
        delete sandbox.sodium;
    }
}

await asyncCheck('startMining arms exactly one init watchdog per worker', async () => {
    await withSodium(async () => {
        primeForm();
        await api.startMining();
        ok(api.miningState(), 'mining should be active after startMining');
        const n = workerPool.length;
        ok(n >= 1, `expected at least one worker, created ${n}`);
        eq(api.initTimeoutCount(), n, 'one init watchdog per worker must be armed');
        eq(workerStats.live, n, 'every created worker must be live');
        await api.stopMining();
        eq(workerStats.live, 0, 'stopMining must terminate every worker');
        eq(api.initTimeoutCount(), 0, 'and clear every watchdog');
    });
});

await asyncCheck('stopMining retires the status and hides the panel', async () => {
    await withSodium(async () => {
        primeForm();
        await api.startMining();
        api.setStatusText('Starting...');
        await api.stopMining();
        eq(api.getStatusText(), '', 'the status text must be empty after stop');
        eq(api.getStatusHidden(), true, 'and the line must be hidden, not left blank');
        ok(getElementById('progress').classList.contains('hidden'),
            'the panel must be hidden after stop');
        eq(api.miningState(), false, 'mining must be inactive');
    });
});

await asyncCheck('a found event terminates every worker and clears the panel', async () => {
    await withSodium(async () => {
        primeForm();
        await api.startMining();
        const n = workerPool.length;
        api.setStatusText('Starting...');
        // Deliver 'found' from the first worker, as a short search would. This is
        // the path that fires before any 'progress' message, which is why the
        // status has to be retired here too.
        workerPool[0].deliver({
            type: 'found',
            publicKey: 'ab' + '0'.repeat(62),
            privateKey: 'c'.repeat(64),
            attempts: 3,
            elapsed: 0.01,
        });
        eq(api.miningState(), false, 'mining must stop on found');
        eq(workerStats.live, 0, `all ${n} workers must be terminated on found`);
        eq(api.initTimeoutCount(), 0, 'every watchdog must be cleared on found');
        eq(api.getStatusText(), '', 'no stale status after found');
        ok(getElementById('progress').classList.contains('hidden'),
            'the panel must be hidden after found');
        api.clearHistory();
    });
});

await asyncCheck('a stale worker cannot disarm the next search watchdog', async () => {
    await withSodium(async () => {
        // The regression. Worker handlers used to do
        // `clearTimeout(initTimeouts[i])`, indexing a shared array that
        // terminateAllWorkers() empties and the next search refills. A late event
        // from an already-terminated worker therefore cleared the NEW search's
        // watchdog at the same index, silently disarming the "failed to
        // initialize" alert so a genuinely hung worker never surfaces.
        primeForm();
    
        // --- search 1 ---
        timerLog.armed.length = 0;
        timerLog.cleared.length = 0;
        await api.startMining();
        const first = workerPool.slice();
        ok(first.length >= 1, 'search 1 must create workers');
        await api.stopMining();                  // workers terminated, timers cleared
        eq(api.initTimeoutCount(), 0, 'search 1 watchdogs cleared on stop');
    
        // --- search 2 ---
        const armedBefore = timerLog.armed.length;
        await api.startMining();
        const search2Handles = timerLog.armed.slice(armedBefore);
        ok(search2Handles.length >= 1, 'search 2 must arm its own watchdogs');
    
        // A worker from the FINISHED search fires late, after being terminated.
        // That is the real ordering: Worker.terminate() is not synchronous with
        // events already queued.
        for (const w of first) {
            ok(w.terminated, 'search 1 workers must already be terminated');
            if (w.hasHandler('onerror')) w.raiseError('late failure from a dead worker');
            if (w.hasHandler('onmessage')) {
                w.deliver({ type: 'progress', attempts: 1, rate: 1, expectedAttempts: 256 });
            }
        }
    
        // No handle belonging to search 2 may have been cleared.
        const crossCleared = search2Handles.filter((h) => timerLog.cleared.includes(h));
        eq(crossCleared.length, 0,
            'a terminated worker from a previous search must not clear the current '
            + `search's watchdogs (cleared ${crossCleared.length} of ${search2Handles.length})`);
        eq(api.initTimeoutCount(), search2Handles.length,
            'the current search must keep every watchdog armed');
        await api.stopMining();
    });
});

await asyncCheck('a stale worker cannot record a key into the next search', async () => {
    // The companion to the watchdog case, and the reason the onmessage handler
    // needs the same staleness guard as onerror.
    //
    // A worker from a finished search can still deliver 'found'. Unguarded,
    // that would write the old run's key into history, stop the CURRENT search
    // (mining = false, panel hidden, every live worker terminated) and report a
    // key belonging to a search the user already stopped.
    primeForm();
    timerLog.armed.length = 0;
    timerLog.cleared.length = 0;
    await withSodium(async () => {
        await api.startMining();
        const first = workerPool.slice();
        await api.stopMining();
        eq(api.miningState(), false, 'search 1 stopped');

        // --- search 2 begins ---
        await api.startMining();
        ok(api.miningState(), 'search 2 must be running');
        const liveBefore = workerStats.live;
        const historyBefore = api.getSavedKeys().length;

        // The dead worker reports a hit.
        for (const w of first) {
            w.deliver({
                type: 'found',
                publicKey: 'ab' + '1'.repeat(62),
                privateKey: 'd'.repeat(64),
                attempts: 7,
                elapsed: 0.02,
            });
        }

        eq(api.getSavedKeys().length, historyBefore,
            'a stale found must not add a key to history');
        eq(api.miningState(), true,
            'a stale found must not stop the current search');
        eq(workerStats.live, liveBefore,
            'a stale found must not terminate the current search\'s workers');
        await api.stopMining();
    });
});

await asyncCheck('resetForm retires the status and hides the panel', async () => {
    await withSodium(async () => {
        primeForm();
        api.setStatusText('Loading crypto library...');
        api.resetForm();
        eq(api.getStatusText(), '', 'resetForm must clear the status text');
        eq(api.getStatusHidden(), true, 'and hide the line');
        ok(getElementById('progress').classList.contains('hidden'),
            'resetForm must hide the panel');
    });
});

await asyncCheck('a ready event does not change the status', async () => {
    await withSodium(async () => {
        primeForm();
        await api.startMining();
        // 'ready' only tells the main thread to send the pattern; it must not
        // resurrect or alter the startup status.
        const before = api.getStatusText();
        workerPool[0].deliver({ type: 'ready' });
        eq(api.getStatusText(), before, 'a ready event must not change the status text');
        await api.stopMining();
    });
});

await asyncCheck('an in-flight export must not hide the live mining panel', async () => {
    // The live panel (#progress) is shared between mining and export - there is
    // one of it. The export path is asynchronous (a Worker, for >100 keys) and
    // the export button is not disabled while mining, so the two can overlap.
    //
    // Unguarded, the export's completion called clearStatusText() and hid the
    // panel, which made the live figures vanish mid-search: the same
    // stale-callback class of bug the mining workers are guarded against, in a
    // second worker the earlier fix did not reach.
    primeForm();
    await seedHistoryForExport();

    await withSodium(async () => {
        // Export starts first and shows its own status.
        api.exportHistory('csv');
        const exportWorker = exportPool[exportPool.length - 1];
        ok(exportWorker, 'the export must have spawned a worker');
        eq(api.getStatusText(), 'Preparing export...',
            'the export should own the status line while it runs');

        // Now the user starts a search before the export finishes.
        await api.startMining();
        ok(api.miningState(), 'mining must be running');
        api.setStatusText('Starting...');
        // The point of the separate pools: the export worker must NOT have been
        // swept into the mining pool, and mining must not have adopted it. Its
        // count is detectOptimalWorkers(), not 1.
        ok(workerPool.length > 0, 'mining must have created its own workers');
        eq(exportPool.length, 1,
            'the export worker must live in its own pool, not the mining one');
        ok(exportPool[0] !== workerPool[0],
            'the export worker and a mining worker must be distinct objects');

        // The export completes. It must deliver the file and clean up its own
        // worker, but must leave the mining panel exactly as it found it.
        exportWorker.deliver({
            type: 'done',
            filename: 'keys.csv',
            mime: 'text/csv',
            data: 'a,b',
        });

        ok(exportWorker.terminated, 'the export worker must still be terminated');
        ok(!getElementById('progress').classList.contains('hidden'),
            'the live mining panel must stay visible after an export completes');
        eq(api.miningState(), true,
            'a completing export must not stop the running search');

        await api.stopMining();
    });
    await teardownExportTest();
});

await asyncCheck('an export that finishes on its own clears the panel', async () => {
    // The other half: with no mining running, the export does own the panel and
    // must clean it up, exactly as before. Guards against "fixing" the overlap
    // by simply never touching the panel again.
    primeForm();
    await seedHistoryForExport();
    api.exportHistory('json');
    const w = exportPool[exportPool.length - 1];
    ok(w, 'the export must have spawned a worker');
    ok(!getElementById('progress').classList.contains('hidden'),
        'the panel should be visible while the export runs');
    w.deliver({ type: 'done', filename: 'k.json', mime: 'application/json', data: '[]' });
    ok(getElementById('progress').classList.contains('hidden'),
        'a standalone export must hide the panel when it finishes');
    eq(api.getStatusText(), '', 'and clear its status text');
    ok(w.terminated, 'and terminate its worker');
    await teardownExportTest();
});

await asyncCheck('an export must not hide the panel while a search is STARTING', async () => {
    // The window the `mining`-only guard missed.
    //
    // startMining() sets `starting = true`, shows #progress and writes its
    // status, then AWAITS libsodium. `mining` only flips to true after that
    // await and after the workers exist. So between the panel appearing and
    // `mining` becoming true there is a real interval - a cold libsodium load
    // makes it long - and an export completing inside it saw `mining === false`
    // and hid the panel the search had just opened. The live figures would then
    // render into a display:none element.
    primeForm();
    await seedHistoryForExport();
    api.exportHistory('csv');
    const exportWorker = exportPool[exportPool.length - 1];
    ok(exportWorker, 'the export must have spawned a worker');

    // Start a search but hold it before it finishes starting: panel is open,
    // `starting` is true, `mining` is still false.
    const realSodium = sandbox.libsodium;
    sandbox.libsodium = { ready: new Promise(() => {}) };   // never resolves
    sandbox.sodium = sandbox.libsodium;
    const inFlight = api.startMining();
    await new Promise((r) => setTimeout(r, 0));
    // Do NOT await `inFlight`: it is parked on the never-resolving libsodium
    // promise on purpose, so awaiting it deadlocks the suite. It is abandoned
    // below by restoring state directly.
    ok(inFlight && typeof inFlight.then === 'function',
        'startMining should return a promise while it waits for libsodium');
    try {
        eq(api.startingState(), true, 'the search must be in the starting phase');
        eq(api.miningState(), false, 'but not yet mining');
        ok(!getElementById('progress').classList.contains('hidden'),
            'the panel must be open during startup');

        // The export finishes inside that window.
        exportWorker.deliver({
            type: 'done', filename: 'k.csv', mime: 'text/csv', data: 'a,b',
        });

        ok(exportWorker.terminated, 'the export worker must still be terminated');
        ok(!getElementById('progress').classList.contains('hidden'),
            'an export must not hide the panel a starting search already opened');
        eq(api.getStatusText(), 'Loading crypto library...',
            'nor retire the starting search\'s status');
    } finally {
        sandbox.libsodium = realSodium;
        sandbox.sodium = realSodium;
        // stopMining() clears `starting` and the form, so the abandoned
        // startMining() cannot leave the harness in a starting state for the
        // tests that follow.
        api.stopMining();
    }
    await teardownExportTest();
});

await asyncCheck('cancelling during startup must not start the search', async () => {
    // The guard `if (mining) return;` that used to sit here could never fire -
    // `mining` is only set true once the workers exist, below the check - and it
    // was checking the wrong flag anyway: Stop and the new-search button both
    // clear `starting`, not `mining`. The check is now `if (!starting) return;`.
    primeForm();
    workerPool.length = 0;

    const realSodium = sandbox.libsodium;
    let release;
    // The stub must satisfy sodiumIsUsable(), which requires a real
    // crypto_sign_seed_keypair. Without it awaitSodium() THROWS before the guard
    // under test is ever reached, and the check passes for the wrong reason -
    // which is exactly what happened the first time this was written.
    const ready = new Promise((r) => { release = r; });
    const stub = {
        ready,
        crypto_sign_seed_keypair(seed) {
            const pk = new Uint8Array(32);
            pk[0] = (seed[0] || 0) ^ 0xab;
            pk[31] = seed[31] & 0xff;
            return { publicKey: pk, privateKey: new Uint8Array(64) };
        },
    };
    sandbox.libsodium = stub;
    sandbox.sodium = stub;
    const inFlight = api.startMining();
    await new Promise((r) => setTimeout(r, 0));
    try {
        eq(api.startingState(), true, 'the search should be waiting on libsodium');
        eq(workerPool.length, 0, 'and must not have created workers yet');

        // The user cancels: Stop (or New Search) clears `starting` while the
        // await is still pending.
        api.stopMining();
        eq(api.startingState(), false, 'cancelling must clear the starting flag');

        // Now libsodium finally resolves. The search must NOT proceed.
        release();
        await inFlight;
        await new Promise((r) => setTimeout(r, 0));

        eq(workerPool.length, 0,
            'a cancelled startup must not create workers after the await resolves');
        eq(api.miningState(), false, 'and must not end up mining');
        eq(api.liveWorkerCount(), 0, 'no worker may be registered');
    } finally {
        sandbox.libsodium = realSodium;
        sandbox.sodium = realSodium;
        api.stopMining();
    }
});

await asyncCheck('a superseded startup does not corrupt the running search', async () => {
    // CHARACTERISATION test, not a regression guard.
    //
    // Start -> New Search -> Start, all before libsodium resolves. New Search
    // (resetForm) clears `starting` AND re-enables the buttons, so a second
    // Start can begin while the first startMining() is still parked on
    // libsodium.ready. When libsodium resolves, the two resume in order: the
    // superseded call sees `starting === true`, proceeds and clears it; the
    // legitimate second call then bails on `!starting`.
    //
    // That looks alarming - the wrong call survives - but it is BENIGN, and this
    // test exists to pin why rather than to prevent it. Both bodies read the
    // pattern from the DOM AFTER the cancellation guard (verified: guard at
    // char ~33235, prefix read at ~33343), so whichever body proceeds mines
    // whatever the inputs currently hold. One surviving worker set, mining the
    // pattern on screen right now - which is what the user asked for.
    //
    // Asserted rather than assumed: an earlier attempt to "fix" this with a
    // start-token guard was written, measured, and REVERTED, because removing
    // the token changed nothing observable. So the invariant below is what the
    // current code actually guarantees.
    //
    // Scope of the claim: this pins today's behaviour. It was NOT verified to
    // catch a future refactor that captures the pattern before the guard - an
    // attempt to simulate that failed on a scoping error in the simulation
    // itself, so treat the "if that changes, this fails" reasoning as an
    // expectation rather than a demonstrated result.
    primeForm();
    workerPool.length = 0;

    const realSodium = sandbox.libsodium;
    let release;
    const ready = new Promise((r) => { release = r; });
    const stub = {
        ready,
        crypto_sign_seed_keypair(seed) {
            const pk = new Uint8Array(32);
            pk[0] = (seed[0] || 0) ^ 0xab;
            pk[31] = seed[31] & 0xff;
            return { publicKey: pk, privateKey: new Uint8Array(64) };
        },
    };
    sandbox.libsodium = stub;
    sandbox.sodium = stub;

    const first = api.startMining();          // parked on ready, pattern 'ab'
    await new Promise((r) => setTimeout(r, 0));
    api.resetForm();                          // New Search: cancels + re-enables
    // resetForm clears the inputs, and a real user then types a NEW pattern.
    // Without this the second Start fails validation and never reaches the
    // race, which would make the check pass for the wrong reason.
    getElementById('prefix').value = 'cd';
    getElementById('suffix').value = '';
    const second = api.startMining();         // a genuinely new search, pattern 'cd'
    await new Promise((r) => setTimeout(r, 0));
    try {
        eq(api.startingState(), true, 'the second search should be starting');
        release();                            // libsodium finally arrives
        await Promise.all([first, second]);
        await new Promise((r) => setTimeout(r, 0));

        // The surviving search must mine the pattern currently on screen, not
        // the one that was typed first. Workers receive the pattern on 'ready',
        // so drive that and check what was actually sent.
        ok(workerPool.length > 0, 'the surviving search should have created workers');
        for (const w of workerPool) w.deliver({ type: 'ready' });
        const sent = workerPool.flatMap((w) => w.posted.map((m) => m.prefix));
        ok(sent.length > 0, 'workers should have been sent the surviving pattern');
        ok(sent.every((p) => p === 'cd'),
            `only the pattern currently on screen may be mined, `
            + `got ${JSON.stringify(sent)}`);
    } finally {
        sandbox.libsodium = realSodium;
        sandbox.sodium = realSodium;
        api.stopMining();
    }
});

check('worker init timers are per-worker, not looked up by index', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    // Static backstop only. The behaviour that actually matters is pinned by
    // the executed tests above - notably 'a stale worker cannot disarm the next
    // search watchdog' and 'a stale worker cannot record a key into the next
    // search' - which drive the real handlers and failed for real when the
    // staleness guard was removed. This check stays because it costs nothing
    // and localises the regression to one sentence if it ever comes back.
    const indexed = html.match(/clearTimeout\(initTimeouts\[/g) || [];
    ok(indexed.length === 0,
        `no handler may clear its timer via initTimeouts[i]; found ${indexed.length} `
        + 'such call(s), which can disarm a later search\'s watchdog');

    // The handle must be captured per worker and cleared via the closure.
    ok(/let initTimeout = null;/.test(html),
        'each worker must capture its own init-timer handle');
    ok(/const clearOwnInitTimeout = \(\) => \{/.test(html),
        'the per-worker clear helper must exist');
    ok(/clearOwnInitTimeout\(\);/.test(html),
        'handlers must clear via the per-worker helper');

    // The helper must be idempotent: a late second call must not clear a
    // different timer, which it cannot if it nulls the handle first.
    const helper = html.slice(html.indexOf('const clearOwnInitTimeout'),
        html.indexOf('const clearOwnInitTimeout') + 400);
    ok(/initTimeout = null;/.test(helper),
        'the helper must null its handle, so a repeat call is a no-op');
    ok(/initTimeouts\.push\(initTimeout\)/.test(html),
        'the handle must still be registered for bulk teardown');

    // Both handlers must ignore events from workers that are no longer part of
    // the current search. terminateAllWorkers() is not synchronous with already
    // queued events, so without this a dead worker's error would tear down the
    // LIVE search. The executed tests above catch the behaviour; this pins the
    // mechanism so the intent is greppable.
    const staleGuards = html.match(/if \(!isCurrent\(\)\) return;/g) || [];
    ok(staleGuards.length === 2,
        `both onerror and onmessage must ignore a stale worker, found `
        + `${staleGuards.length} guard(s)`);
});

check('the rate graph cannot break the live figures', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    // pushRateGraphSample() sits in the middle of the progress handler, with
    // the progress percentage and the ETA BELOW it. An escaping throw would
    // pushRateGraphSample() sits in the middle of the progress handler, with
    // the progress percentage and the ETA BELOW it. An escaping throw would
    // skip both, freezing the live figures on stale values. The graph is
    // decoration; the figures are the product.
    const at = html.indexOf('pushRateGraphSample(rate)');
    ok(at !== -1, 'the progress handler must feed the graph');

    // Scope the check to the try/catch that wraps THIS call. A fixed-width
    // window was not enough: the next `try {` further down the file satisfied
    // it, so removing the guard entirely still passed. Bound the search to the
    // lines immediately surrounding the call instead.
    const before = html.slice(Math.max(0, at - 200), at);
    const after = html.slice(at, at + 200);
    ok(/\{\s*$/.test(before.trimEnd()) && after.includes('} catch'),
        'the graph call must be wrapped in a try/catch that closes after it');

    // clearStatusText() is the FIRST statement in that same handler, so it must
    // not be able to throw either. Scoped to the function body only, for the
    // same reason.
    const cStart = html.indexOf('function clearStatusText()');
    ok(cStart !== -1, 'clearStatusText must exist');
    const cEnd = html.indexOf('\n        }', cStart);
    const body = html.slice(cStart, cEnd === -1 ? cStart + 600 : cEnd);
    ok(body.includes('try {') && body.includes('catch'),
        'clearStatusText must swallow its own errors, since it runs first in '
        + 'the progress handler and a throw would skip every live figure');
});

check('rate graph: a keys/s trace sits behind the ETA digits', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    // A canvas, inside the ETA cell, and decorative.
    ok(/<canvas class="rate-graph" id="rate-graph"/.test(html),
        'the rate graph canvas must exist');
    const cell = html.indexOf('class="live-cell live-cell-eta"');
    const canvas = html.indexOf('id="rate-graph"');
    ok(cell !== -1 && canvas > cell && canvas < html.indexOf('</div>', html.indexOf('id="live-eta"')),
        'the graph must live inside the ETA cell');

    // Decorative: the numbers it shows are already announced by the live region.
    ok(/<canvas class="rate-graph" id="rate-graph"\s+aria-hidden="true"/.test(html)
        || /aria-hidden="true"[^>]*class="rate-graph"/.test(html)
        || /class="rate-graph"[^>]*aria-hidden="true"/.test(html),
        'the graph must be hidden from assistive tech');

    // Behind the digits: absolutely positioned, pointer-events off, and the
    // ETA row is its positioning context.
    ok(/\.rate-graph\s*\{[^}]*position:\s*absolute/.test(html),
        'the graph must be taken out of flow');
    ok(/\.rate-graph\s*\{[^}]*pointer-events:\s*none/.test(html),
        'the graph must not intercept clicks');
    ok(/\.live-cell-eta\s*\{[^}]*position:\s*relative/.test(html),
        'the ETA cell must anchor the absolutely-positioned graph');

    // It must be a bounded window, not an unbounded buffer that grows all run.
    ok(/RATE_GRAPH_POINTS\s*=\s*\d+/.test(html),
        'the sample buffer must be bounded');
    ok(/function pushRateGraphSample\(/.test(html),
        'the graph needs a sample-push entry point');
    ok(/function resetRateGraph\(/.test(html),
        'the graph must be resettable per search');
    // Feeding it the raw rate, not the EMA: smoothing is what would hide the
    // variation the graph exists to reveal.
    ok(/pushRateGraphSample\(rate\)/.test(html),
        'the graph should plot the raw per-batch rate');
});

check('visitor badge: proportions match the SVG so it is not stretched', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    const img = html.match(/<img\s+src="https:\/\/api\.visitorbadge\.io[\s\S]*?>/);
    ok(img, 'the badge img must exist');
    const w = Number((img[0].match(/width="(\d+)"/) || [])[1]);
    const h = Number((img[0].match(/height="(\d+)"/) || [])[1]);
    ok(w && h, 'the badge must declare width and height');
    // visitorbadge.io serves ~123.5x28 (4.4:1). It used to be declared 120x20
    // (6:1), which stretched it wide and squashed it short.
    const ratio = w / h;
    ok(ratio < 5 && ratio > 4,
        `the badge should keep its ~4.4:1 aspect ratio, got ${ratio.toFixed(2)}:1`);
    ok(w < 120, 'the badge should be narrower than the old 120px box');
    ok(/\.visitor-counter img\s*\{[^}]*height:\s*auto/.test(html),
        'the badge should follow its own ratio rather than a fixed height');
});

check('setStatusText: shows a status and hides it again', () => {
    // The "Starting..." bug was that it was written and never cleared. These
    // assert the set/clear pair that fixes it, including that clearing HIDES
    // the element rather than only emptying it (an emptied <p> still reserves
    // a line box, which is what left a blank row under the figures).
    api.setStatusText('Starting...');
    eq(api.getStatusText(), 'Starting...', 'the message is shown');
    eq(api.getStatusHidden(), false, 'and the line is visible');

    api.clearStatusText();
    eq(api.getStatusText(), '', 'the text is cleared');
    eq(api.getStatusHidden(), true, 'and the line is hidden, not left as a blank row');

    // Empty text must be treated as "no status", not as a visible empty line.
    api.setStatusText('');
    eq(api.getStatusHidden(), true, 'an empty status stays hidden');
});

check('rate graph: samples accumulate and stay bounded', () => {
    api.resetRateGraph();
    eq(api.rateGraphState().length, 0, 'a new search starts with no samples');

    api.pushRateGraphSample(100);
    eq(api.rateGraphState().length, 1, 'one sample stored');
    // Samples carry a timestamp alongside the value, so the on-screen window
    // is a fixed span of TIME rather than a fixed number of reports.
    eq(api.rateGraphState()[0].v, 100, 'the raw rate is stored');
    ok(Number.isFinite(api.rateGraphState()[0].t),
        'each sample must carry the time it was taken');

    // Nonsense must not reach the trace.
    api.pushRateGraphSample(NaN);
    api.pushRateGraphSample(-5);
    api.pushRateGraphSample(Infinity);
    api.pushRateGraphSample(undefined);
    eq(api.rateGraphState().length, 1, 'invalid samples are rejected');

    // The buffer must not grow without bound: a long search cannot leak
    // memory or flatten the early samples into nothing.
    const cap = api.RATE_GRAPH_POINTS;
    for (let i = 0; i < cap * 4; i++) api.pushRateGraphSample(200 + (i % 7));
    const n = api.rateGraphState().length;
    ok(n > 1 && n <= cap,
        `the buffer must stay within its window: ${n} samples, cap ${cap}`);

    // Halving on overflow must keep the newest value: the dot marking "now"
    // has to be the reading that was just pushed, not a stale neighbour.
    // Samples are smoothed on the way in, so with this repeating 7-value
    // pattern the trace converges to the pattern's mean and the newest sample
    // must be one of the pattern's values, not a blend of unrelated ones.
    const state = api.rateGraphState();
    const vs = state.map((s) => s.v);
    const newestV = vs[vs.length - 1];
    // Samples are smoothed on the way in, so the tail converges towards the
    // mean of the repeating 7-value pattern rather than equalling any one of
    // them. What matters is that the newest sample is still a real reading from
    // that pattern - not a blend of discarded history.
    ok(newestV >= 200 && newestV <= 206,
        `the newest sample must be a reading from the pattern, got ${newestV}`);

    api.resetRateGraph();
    eq(api.rateGraphState().length, 0, 'a new search clears the trace');
});

check('rate graph: the trace is smoothed so per-worker jitter is not drawn raw', () => {
    // Each sample is one worker's rate since it last reported, so consecutive
    // samples legitimately disagree. Drawn raw the line was unreadable spikes.
    api.resetRateGraph();
    const t0 = Date.now();
    const realNow = Date.now;
    try {
        let clock = 0;
        Date.now = () => t0 + clock * 1000;
        // Alternate hard between two very different rates.
        for (let i = 0; i < 10; i++) {
            api.pushRateGraphSample(i % 2 === 0 ? 1000 : 4000);
            clock++;
        }
        const vs = api.rateGraphState().map((s) => s.v);
        // The first sample is taken as-is so the trace starts at the true rate.
        eq(vs[0], 1000, 'the first sample is the true rate, not an ease-up');
        // Every later sample must be strictly inside the range of its
        // neighbours: smoothing means no sample equals either extreme input.
        ok(vs[1] > 1000 && vs[1] < 4000,
            `a smoothed sample must lie between its neighbours, got ${vs[1]}`);
        const swings = vs.slice(1).map((v, i) => Math.abs(v - vs[i]));
        ok(Math.max(...swings) < 3000,
            `smoothing must damp the 3000/s alternation, largest step ${Math.max(...swings)}`);
        // ...but it must still react: a sustained new rate must be reached quickly,
        // not approached asymptotically from far away.
        api.resetRateGraph();
        for (let i = 0; i < 10; i++) {
            api.pushRateGraphSample(4000);
            clock++;
        }
        const sustained = api.rateGraphState().map((s) => s.v);
        ok(sustained[9] > 3900,
            `a sustained rate must be reached within a few samples, got ${sustained[9]}`);
    } finally {
        Date.now = realNow;
        api.resetRateGraph();
    }
});

check('rate graph: the window is a fixed span of time, not the whole run', () => {
    // Regression: the trace used to keep halving the buffer without ever
    // dropping anything, so after a long enough run it spanned 100% of the
    // search. The first samples were then so far apart that recent rate
    // variation - the entire point of the graph - flattened into a straight
    // line. Timestamps let stale samples fall off the left edge instead.
    const t0 = Date.now();
    const realNow = Date.now;
    try {
        api.resetRateGraph();
        // 20 minutes of history at one sample a second, with a clear rate
        // swing in the LAST few minutes (simulated by the varying value).
        let clock = 0;
        Date.now = () => t0 + clock * 1000;
        for (let s = 0; s < 1200; s++) {
            // Constant 1000/s for the first 15 min, then noisy 1000-1400/s.
            const v = s < 900 ? 1000 : 1000 + (s % 5) * 100;
            api.pushRateGraphSample(v);
            clock++;
        }
        const state = api.rateGraphState();
        const newest = state[state.length - 1].t;
        const oldest = state[0].t;
        const spanSec = (newest - oldest) / 1000;

        // The window must be bounded by the configured time, not unbounded.
        ok(spanSec <= api.RATE_GRAPH_WINDOW_MS / 1000 + 5,
            `the window must not exceed RATE_GRAPH_WINDOW_MS, got ${spanSec}s`);
        // ...and once the run is long enough it must actually fill it, rather
        // than showing the whole search back to the beginning.
        ok(spanSec < 1200 * 0.5,
            `after 20 min the trace must not span the whole run, got ${spanSec}s`);

        // The recent variation must still be visible as variation: the
        // newest samples must not all be identical.
        const recent = state.slice(-5).map((s) => s.v);
        ok(new Set(recent).size > 1,
            `recent samples must still vary, got ${JSON.stringify(recent)}`);
    } finally {
        Date.now = realNow;
        api.resetRateGraph();
    }
});

check('rate graph: decimation keeps the newer of each pair, and terminates', () => {
    // The halving loop once kept index i (the OLDER of each adjacent pair)
    // while its comment claimed the newer, so every decimated reading was up
    // to one sample stale and the trace lagged real rate changes. Exercised
    // across every length from 1 to 400 so both parities and every shrink
    // step are covered, not just one convenient size.
    const cap = api.RATE_GRAPH_POINTS;
    const t0 = Date.now();
    const realNow = Date.now;
    let clock = 0;
    try {
        Date.now = () => t0 + clock * 1000;
        for (let n = 1; n <= 400; n++) {
            api.resetRateGraph();
            for (let i = 0; i < n; i++) {
                // Distinct, increasing, and identifiable by value.
                api.pushRateGraphSample(1000 + i);
                clock++;
            }
            const st = api.rateGraphState();
            ok(st.length >= 1, `n=${n}: the buffer must not be emptied`);
            ok(st.length <= cap, `n=${n}: must stay within the cap (${st.length} > ${cap})`);
            // The newest reading must always survive, since the dot marking
            // "now" is drawn from it. Samples are smoothed on the way in, so
            // identity is checked as "still the largest of a rising ramp"
            // rather than as equality with the raw reading.
            const vs = st.map((s) => s.v);
            eq(st[st.length - 1].v, Math.max(...vs),
                `n=${n}: the newest sample must survive decimation`);
            // Timestamps must stay strictly increasing: no reordering, and no
            // duplicated point from the re-append.
            let ordered = true;
            for (let i = 1; i < st.length; i++) {
                if (st[i].t <= st[i - 1].t) { ordered = false; break; }
            }
            ok(ordered, `n=${n}: timestamps must stay strictly increasing`);
        }
    } finally {
        Date.now = realNow;
        api.resetRateGraph();
    }

    // The specific defect: halving (0,1),(2,3),... and keeping the older of
    // each pair instead of the newer. Tested against decimateSamples() directly
    // rather than through pushRateGraphSample(): samples are smoothed on the
    // way in, so an alternating input becomes a converging average and index
    // parity - the only thing that distinguishes the two choices - disappears.
    const CAP = api.RATE_GRAPH_POINTS;
    const pairs = [];
    for (let i = 0; i < CAP; i++) pairs.push({ t: i, v: i % 2 === 0 ? 1000 : 2000 });
    pairs.push({ t: CAP, v: 1000 });   // overflows by one, forcing one halving
    const st = api.decimateSamples(pairs, CAP);
    eq(st[st.length - 1].v, 1000, 'the newest sample survives the halving');
    const body = st.slice(0, -1);
    ok(body.length > 0, 'expected retained samples to inspect');
    // Every survivor from a (low, high) pair must be the high one.
    const wrong = body.filter((s) => s.v !== 2000);
    ok(wrong.length === 0,
        `decimation must keep the newer (higher) of each pair, but retained `
        + `${wrong.length} stale reading(s) of 1000 in ${JSON.stringify(body.map((s) => s.v))}`);

    // Odd lengths at every size: halving can skip the final element, and the
    // re-append is what stops the newest sample being dropped.
    for (let n = 1; n <= 400; n++) {
        const list = [];
        for (let i = 0; i < n; i++) list.push({ t: i, v: i });
        const out = api.decimateSamples(list, 8);
        ok(out.length >= 1 && out.length <= 8,
            `n=${n}: decimation must settle at or below the cap, got ${out.length}`);
        eq(out[out.length - 1].v, n - 1, `n=${n}: the newest sample must survive`);
        // Timestamps strictly increasing, never duplicated.
        for (let i = 1; i < out.length; i++) {
            ok(out[i].t > out[i - 1].t, `n=${n}: timestamps must stay ordered`);
        }
    }
});
check('the estimate line cannot widen a narrow screen', () => {
    // Reported from an Android phone: the estimate ran off the side of the page
    // and the page scrolled sideways.
    //
    // Two independent causes, both needed:
    //
    // 1. Chrome on Android boosts the font size of text blocks it thinks are
    //    too small for the viewport. The viewport meta did not declare
    //    text-size-adjust, so the text was silently enlarged - and this line is
    //    a single unbroken run with nothing to wrap it.
    // 2. #estimate had no wrapping rule at all. `width: 100%` plus a block child
    //    that cannot break means the element is wider than its container.
    //
    // Both are load-bearing: with only (1) the line still overflows at the
    // authored size, and with only (2) the boost pushes it back out.
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    ok(/name="viewport"[^>]*text-size-adjust|viewport[^>]*initial-scale/.test(html)
        || /text-size-adjust:\s*100%/.test(html),
    'the page must disable Chrome\'s Android font boosting, or the estimate '
        + 'is silently enlarged on a phone');

    // The wrapping rule on the element itself.
    const m = html.match(/#estimate\s*\{([^}]*)\}/);
    ok(m, '#estimate must have a rule of its own');
    ok(/overflow-wrap:\s*anywhere/.test(m[1]),
        '#estimate must allow breaking, or one long run overflows the page');
    ok(/max-width:\s*100%/.test(m[1]),
        '#estimate must be capped at its container width');

    // And the facts must be separated by real break opportunities. The `|`
    // separators stranded at the start of wrapped lines and were the original
    // overflow trigger.
    ok(/white-space:\s*pre-line/.test(m[1]),
        '#estimate must honour the newlines between facts');
    ok(/\\nEstimated time: ~/.test(html),
        'the estimate facts must be newline-separated');
    ok(/\\n\(' \+ shownWorkers/.test(html),
        'the worker/rate clause must start on its own line too');

    // Narrow screens need the room: 40px of container padding on each side of a
    // 360px phone leaves 280px, which is not enough.
    ok(/@media \(max-width: 480px\)/.test(html),
        'a narrow-screen breakpoint must exist to reclaim the container padding');
    ok(/padding:\s*max\(16px, env\(safe-area-inset-top\)\)/.test(html),
        'the container must tighten its padding on a phone');

    // And if viewport-fit=cover is claimed, the safe-area padding has to be
    // real. A comment claiming padding that does not exist is worse than none.
    if (/viewport-fit=cover/.test(html)) {
        ok(/env\(safe-area-inset-(top|right|bottom|left)\)/.test(html),
            'viewport-fit=cover is declared, so the safe-area padding must be real');
    }
});

check('estimate omits the scaling provenance clause', () => {
    getElementById('prefix').value = 'ab';
    getElementById('suffix').value = '';
    api.updateEstimate();
    const txt = api.getEstimateText();
    ok(!/scale derived from/.test(txt),
        `the provenance clause must not be printed: ${txt}`);
    // Only actual measurements belong in the grey line: attempts, time, worker
    // count and the measured keys/s. The worker-scaling multiplier is a property
    // of the extrapolation model, not a measurement of this machine, so it is
    // no longer advertised. It still drives totalRate, and therefore the ETA.
    ok(!/improvement is only/.test(txt),
        `the scaling multiplier must not be advertised: ${txt}`);
    ok(!/\d+\.\d+x at \d+ threads/.test(txt),
        `no per-thread scaling baseline may appear: ${txt}`);
    ok(!/workers share cores/.test(txt),
        `the cores-sharing caveat is part of the removed clause: ${txt}`);
    // The measured figures must all still be there.
    ok(/keys\/s/.test(txt), 'the rate must still be stated');
    ok(/Expected attempts: [\d,]+/.test(txt),
        `expected attempts must still be stated: ${txt}`);
    ok(/Estimated time: ~\S+/.test(txt),
        `estimated time must still be stated: ${txt}`);
    ok(/\d+ workers?/.test(txt),
        `the worker count must still be stated: ${txt}`);
    getElementById('prefix').value = '';
    api.updateEstimate();
});

check('live logs: a titled 2x2 grid carries the four figures', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');

    ok(html.includes('Live Logs:'), 'the panel must be titled "Live Logs:"');

    // Four cells, each with a label and a value element.
    for (const id of ['live-attempts', 'live-rate', 'live-progress', 'live-eta']) {
        ok(html.includes(`id="${id}"`), `missing live-log value element #${id}`);
    }
    for (const label of ['Attempts', 'Rate', 'Progress', 'ETA']) {
        ok(new RegExp(`class="live-k">${label}<`).test(html), `missing label ${label}`);
    }

    // Laid out as a two-column grid.
    ok(/\.live-logs-grid\s*\{[^}]*grid-template-columns:\s*1fr 1fr/.test(html),
        'live logs must be a 2x2 grid');

    // Green styling, in two distinct brights: a readable green for the metric
    // names and a hotter one for the live values so the figures pop.
    ok(/\.live-k\s*\{[^}]*color:\s*#56d364/.test(html),
        'live labels should be green');
    ok(/\.live-v\s*\{[^}]*color:\s*#7ef7a0/.test(html),
        'live values should be a brighter green');

    // The title is styled as a header, right-aligned with the figures below it,
    // and scales with the viewport instead of using a fixed size.
    ok(/\.live-logs-title\s*\{[^}]*font-family:[^;]*monospace/.test(html)
        && /\.live-logs-title\s*\{[^}]*text-align:\s*right/.test(html),
    'live-logs title should be monospace and right-aligned with the metrics');
    ok(/\.live-logs-title\s*\{[^}]*font-size:\s*clamp\(/.test(html),
        'live-logs title font size should scale with the viewport');
    ok(/\.live-v\s*\{[^}]*font-size:\s*clamp\(/.test(html),
        'live value font size should scale with the viewport');

    // The redundant "Live estimate: ... at .../s" line is gone: it repeated
    // the rate and ETA the grid already shows. Asserted against rendered
    // output, not raw text, since comments legitimately name what was removed.
    ok(!/id="live-estimate"/.test(html), 'redundant live-estimate element must be removed');
    ok(!/>Live estimate/.test(html), 'no "Live estimate:" label should be rendered');
    ok(!/textContent = 'Live estimate/.test(html), 'nothing should write that label');
});

check('resetLiveLogs clears every cell for a new search', () => {
    api.resetLiveLogs();
    eq(getElementById('live-attempts').textContent, '0', 'attempts reset');
    eq(getElementById('live-rate').textContent, '0/s', 'rate reset');
    eq(getElementById('live-progress').textContent, '0.00%', 'progress reset');
    // The ETA resets through renderEta(0) rather than a single string, so it is
// rendered at its reserved slot widths from the first frame of a new search
// instead of snapping wider once a real duration arrives.
eq(api.getLiveEtaText('live-eta-h'), '0', 'eta hours reset');
eq(api.getLiveEtaText('live-eta-m'), '00', 'eta minutes reset');
eq(api.getLiveEtaText('live-eta-s'), '00', 'eta seconds reset');
    eq(getElementById('live-workers').textContent, '0 | -', 'workers | cores reset');
});

check('mining overhead is bounded: report cadence, worker yield, no per-draw reflow', () => {
    // process.argv[3] is the extracted worker script. Read it here rather than
    // via `workerJsPath`, which is only bound near the end of this file and
    // would be a temporal-dead-zone reference at this point.
    const workerSrc = fs.readFileSync(process.argv[3], 'utf8');
    // `source` is the extracted main-thread script, already read at startup.
    const mainSrc = source;

    // Each progress report costs a main-thread message, a forced layout and a
    // canvas repaint, on the same thread the mining workers compete with for
    // CPU. At 500ms that was 2 messages per worker per second.
    const reportMs = Number(/const REPORT_EVERY_MS\s*=\s*(\d+)/.exec(workerSrc)?.[1]);
    ok(Number.isFinite(reportMs), 'REPORT_EVERY_MS must be a literal number');
    ok(reportMs >= 2000,
        `reports must not be sub-second: ${reportMs}ms would put main-thread ` +
        'work back on the critical path');

    // The first report must not be suppressed: the throttle compares against
    // lastProgressReport, which starts at 0, so `now - last` is enormous and the
    // first call always reports. That is what keeps the self-calibration
    // converging in one interval; a forced extra call on top would post the
    // same batch twice. The behavioural guard is the worker first-batch test.
    ok(/let lastProgressReport = 0;/.test(workerSrc),
        'lastProgressReport must start at 0 so the first report is not throttled');
    ok(!/reportProgress\(true\)/.test(workerSrc),
        'the loop must not force a second report for the same batch');
    ok(!/firstReportSent/.test(workerSrc),
        'the redundant firstReportSent flag must not come back');

    // The yield parks the worker thread on a clamped timer. Yielding every 30ms
    // was ~33 times a second per worker - time not spent mining.
    const yieldMs = Number(/const YIELD_EVERY_MS\s*=\s*(\d+)/.exec(workerSrc)?.[1]);
    ok(Number.isFinite(yieldMs), 'YIELD_EVERY_MS must be a literal number');
    ok(yieldMs >= 200, `the worker must not park on a timer more than 5x a second, got ${yieldMs}ms`);

    // clientWidth/clientHeight force a synchronous layout. Reading them inside
    // the per-report draw path means one forced reflow per report.
    const drawBody = /function drawRateGraph\(\)\s*\{[\s\S]*?\n        \}/.exec(mainSrc)?.[0] || '';
    ok(drawBody.length > 0, 'drawRateGraph must be findable');
    ok(!/clientWidth|clientHeight/.test(drawBody),
        'drawRateGraph must not re-measure the canvas (forced layout per frame)');
    ok(/rateGraphBox/.test(drawBody),
        'drawRateGraph must use the cached box instead');

    // The ETA must keep a real day figure rather than only total hours.
    ok(/days:\s*Math\.floor\(total \/ 86400\)/.test(mainSrc),
        'etaParts must expose a day count');
});

check('live logs report the workers actually running', () => {
    // The pre-flight estimate is a per-worker extrapolation; showing the real
    // running count beside the core count is what makes a shortfall visible
    // instead of mysterious. They are shown together as "N | M" so the
    // comparison does not need to be made across two rows.
    api.resetLiveLogs(8, 8);
    eq(getElementById('live-workers').textContent, '8 | 8', 'workers | cores shown');

    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    ok(html.includes('id="live-workers"'), 'workers cell present');
    ok(/Workers \| Cores/.test(html), 'the label must read "Workers | Cores"');
    ok(!/>\s*Workers\s*<\/span>\s*<span class="live-k">Cores/.test(html),
        'workers and cores must not be two separate labelled rows again');

    api.reportActualWorkers(3);
    eq(getElementById('live-workers').textContent, '3 | 8',
        'actual running count must replace the plan, beside the core count');
    api.resetLiveLogs();
});

check('worker count uses every core', () => {
    // Reserving a core cost 25% throughput on a 4-core machine for no benefit,
    // because the hot loop already yields every 30ms.
    navigatorMock.hardwareConcurrency = 4;
    eq(api.detectOptimalWorkers(), 4, 'a 4-core machine should use all 4');
    navigatorMock.hardwareConcurrency = 1;
    eq(api.detectOptimalWorkers(), 1, 'never below 1');
    navigatorMock.hardwareConcurrency = 256;
    eq(api.detectOptimalWorkers(), 32, 'capped to bound oversubscription');
    navigatorMock.hardwareConcurrency = 0;
    eq(api.detectOptimalWorkers(), 4, '0 is falsy so the documented fallback of 4 applies');
    navigatorMock.hardwareConcurrency = 4;

    // Pin the README's worker-count prose to the code. It claimed
    // "hardwareConcurrency - 1, capped at 16" long after the reserve was
    // removed, which is the same doc-drift class as the stale scaling table.
    const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
    ok(/every logical core\*\*, capped at 32/.test(readme),
        'the README must describe the browser worker count as every logical core, '
        + 'capped at 32, matching detectOptimalWorkers()');
    ok(!/hardwareConcurrency - 1/.test(readme),
        "the README must not still claim a reserved core (hardwareConcurrency - 1); "
        + 'that reserve was removed as a 25% throughput loss with no UI benefit');
});

check('live log values are right-aligned, including on mobile', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    ok(/\.live-cell\s*\{[^}]*align-items:\s*flex-end/.test(html),
        'cells must right-align their content');
    ok(/\.live-v\s*\{[^}]*text-align:\s*right/.test(html),
        'values must be right-aligned');
    // Narrow screens collapse to one column and must keep the alignment.
    ok(/@media \(max-width: 420px\)/.test(html), 'there is a mobile breakpoint');
});

check('the pre-flight estimate presents the rate as a ceiling', () => {
    // Calibration is single-core; workers then share those cores, so rate x
    // workers is unreachable and the headline must not read as a promise.
    //
    // The rate keeps its "up to" hedge, which is what carries that caveat now.
    // The explanatory clause that used to spell out the cores-sharing ("workers
    // share cores, improvement is only ~2.3x at 8 threads") is gone from the
    // grey line, since it described the extrapolation model rather than a
    // measurement of the running machine.
    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    ok(/up to /.test(html), 'rate must be presented as a ceiling');
    // Guard the wording that replaced it: the rate stays explicitly hedged.
    const txt = (() => {
        navigatorMock.hardwareConcurrency = 8;
        getElementById('prefix').value = 'ab';
        getElementById('suffix').value = '';
        api.updateEstimate();
        const t = api.getEstimateText();
        navigatorMock.hardwareConcurrency = 4;
        return t;
    })();
    ok(/up to [\d,]+ keys\/s/.test(txt),
        `the live estimate must keep the "up to" ceiling: ${txt}`);
    ok(!/improvement is only/.test(txt),
        `and must not reintroduce the multiplier: ${txt}`);
});

check('formatElapsed: human units for long searches', () => {
    eq(api.formatElapsed(0), '0.00s');
    eq(api.formatElapsed(42.34), '42.3s');
    eq(api.formatElapsed(60), '1m 0s');
    eq(api.formatElapsed(130), '2m 10s');
    eq(api.formatElapsed(3729), '1h 2m 9s');
    eq(api.formatElapsed(-1), 'unknown');
});

// Defer: workerJsPath is only bound near the end of the file.
if (process.argv[3]) {
    check('worker: reports progress beyond 100% instead of clamping', () => {
        const w = fs.readFileSync(process.argv[3], 'utf8');
        ok(!/Math\.min\(\s*attempts\s*\/\s*expectedAttempts\s*\*\s*100\s*,\s*100\s*\)/.test(w),
            'progress must not be clamped to 100 in the worker');
        ok(/attempts\s*\/\s*expectedAttempts\s*\*\s*100/.test(w),
            'raw overshoot ratio should still be computed');
    });
}

// ---- history obfuscation key derivation ------------------------------------

// clearHistory() prompts before destroying anything; auto-accept so the
// deletion paths can be exercised.
sandbox.confirm = () => true;

// The key must be DERIVED from a machine/storage fingerprint, not read from
// localStorage. Storing it next to the ciphertext meant that anyone who
// lifted the stored history also lifted the key, so the "obfuscation" bought
// nothing against data-at-rest theft.

await asyncCheck('fingerprint includes the storage origin', async () => {
    const fp = api.machineFingerprint();
    ok(fp.includes('https://example.test'),
        `fingerprint must bind the origin: ${fp}`);
});

await asyncCheck('history round-trips through obfuscation', async () => {
    const plain = JSON.stringify([{ publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 }]);
    const encoded = await api.encryptHistoryData(plain);
    ok(encoded !== plain, 'history must actually be transformed');
    ok(!encoded.includes('publicKey'), 'plaintext field names must not survive');
    eq(await api.decryptHistoryData(encoded), plain, 'round-trip must be lossless');
});

await asyncCheck('history is portable across machines at the same origin', async () => {
    // Intended behaviour: the key is bound to the storage LOCATION, not to the
    // machine. Moving a profile, or opening the same origin on another device
    // with synced storage, must still decode. That is the whole point of
    // deriving from an install secret + origin rather than hardware.
    idbData.clear();
    storage.clear();
    api.__resetObfKeyCache();
    const plain = JSON.stringify([{ publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 }]);
    const encoded = await api.encryptHistoryData(plain);

    const origCores = navigatorMock.hardwareConcurrency;
    const origPlatform = navigatorMock.platform;
    navigatorMock.hardwareConcurrency = 64;
    navigatorMock.platform = 'Linux x86_64';
    api.__resetObfKeyCache();
    try {
        eq(await api.decryptHistoryData(encoded), plain,
            'history must follow the storage, not the hardware');
    } finally {
        navigatorMock.hardwareConcurrency = origCores;
        navigatorMock.platform = origPlatform;
        api.__resetObfKeyCache();
        storage.clear();
    }
});

await asyncCheck('history does not decode at a different origin', async () => {
    // The key is bound to location.origin, so a copy of the ciphertext
    // replayed on another site must not decode.
    idbData.clear();
    storage.clear();
    api.__resetObfKeyCache();
    const plain = JSON.stringify([{ publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 }]);
    const stolen = await api.encryptHistoryData(plain);

    const origOrigin = sandbox.location.origin;
    sandbox.location.origin = 'https://evil.example';
    api.__resetObfKeyCache();
    try {
        ok((await api.decryptHistoryData(stolen)) !== plain,
            'ciphertext must not decode under a different origin');
    } finally {
        sandbox.location.origin = origOrigin;
        api.__resetObfKeyCache();
        storage.clear();
    }
});

await asyncCheck('the secret lives in IndexedDB, never localStorage', async () => {
    // Clear both stores first so the scan below is unambiguous.
    idbData.clear();
    storage.clear();
    api.__resetObfKeyCache();
    const secret = await api.getOrCreateObfuscationSecret();
    ok(/^[0-9a-f]{64}$/.test(secret), `expected a 32-byte hex secret: ${secret}`);
    // The whole point: a localStorage-only dump must not contain the key.
    let leaked = null;
    for (const [k, v] of storage) {
        if (String(v).includes(secret)) leaked = `value at ${k}`;
        if (/secret|obf.*key/i.test(k)) leaked = `key name ${k}`;
    }
    ok(!leaked, `the secret must never appear in localStorage (${leaked})`);
    // And it must actually be persisted in IndexedDB.
    const stores = idbData.get(OBF_DB);
    ok(stores && stores.get(OBF_STORE).get('secret') === secret,
        'secret should be stored in IndexedDB');
});

await asyncCheck('the IndexedDB secret is stable across calls', async () => {
    const a = await api.getOrCreateObfuscationSecret();
    const b = await api.getOrCreateObfuscationSecret();
    eq(a, b, 'the secret must be minted once and reused');
    ok(!/^[0-9a-f]{64}$/.test(b) || b === a, 'existing secret must be reused');
});

await asyncCheck('fingerprint fallback excludes volatile values', async () => {
    // Only used when IndexedDB is unavailable, so anything that changes during
    // normal use must be absent: a UA update, timezone travel, a resize.
    const fp = api.machineFingerprint();
    ok(!/timezone|getTimezoneOffset/i.test(fp), `no timezone: ${fp}`);
    ok(!/useragent/i.test(fp), `no user agent: ${fp}`);
    ok(!/screen|colorDepth|width|height/i.test(fp), `no screen metrics: ${fp}`);
    ok(fp.includes('meshcore-vanity-obf-v2-fallback'),
        'fallback fingerprint must be versioned');
    ok(fp.includes('https://example.test'), 'must still bind the origin');
});

await asyncCheck('the fingerprint fallback still obfuscates, never plaintext', async () => {
    // When IndexedDB is simply absent (first run in private mode), the fallback
    // must produce a real XOR key - not a pass-through.
    idbData.clear();
    storage.clear();
    idbAvailable = false;
    api.__resetObfKeyCache();
    try {
        const plain = JSON.stringify([{ publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 }]);
        const encoded = await api.encryptHistoryData(plain);
        ok(encoded && encoded !== plain, 'fallback must still obfuscate');
        ok(!encoded.includes('publicKey'), 'fallback must not leak field names');
        eq(await api.decryptHistoryData(encoded), plain, 'fallback must round-trip');
    } finally {
        idbAvailable = true;
        api.__resetObfKeyCache();
        storage.clear();
    }
});

await asyncCheck('history survives a browser user-agent change', async () => {
    // The concrete failure v1 had: an ordinary browser update silently made
    // every saved key unreadable.
    idbData.clear();
    storage.clear();
    api.__resetObfKeyCache();
    const plain = JSON.stringify([{ publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 }]);
    const encoded = await api.encryptHistoryData(plain);

    const origUA = navigatorMock.userAgent;
    navigatorMock.userAgent = 'Mozilla/5.0 (Chrome 999)';
    api.__resetObfKeyCache();
    try {
        eq(await api.decryptHistoryData(encoded), plain,
            'history must survive a user-agent change');
    } finally {
        navigatorMock.userAgent = origUA;
        api.__resetObfKeyCache();
        storage.clear();
    }
});

await asyncCheck('history falls back gracefully when IndexedDB is blocked', async () => {
    // Private mode / disabled storage: history must still round-trip using the
    // fingerprint alone rather than throwing or silently losing data.
    const savedAvailable = idbAvailable;
    const savedData = new Map(idbData);
    idbData.clear();
    idbAvailable = false;
    api.__resetObfKeyCache();
    try {
        const plain = JSON.stringify([{ publicKey: 'c'.repeat(64), privateKey: 'd'.repeat(64), n: 1 }]);
        const encoded = await api.encryptHistoryData(plain);
        eq(await api.decryptHistoryData(encoded), plain,
            'must still round-trip without IndexedDB');
    } finally {
        idbAvailable = savedAvailable;
        idbData.clear();
        for (const [k, v] of savedData) idbData.set(k, v);
        api.__resetObfKeyCache();
        storage.clear();
    }
});

await asyncCheck('the legacy stored key is removed at load', async () => {
    // The previous scheme persisted the key beside the ciphertext. It must be
    // cleared, or someone who already ran that build keeps a copy forever.
    localStorageMock.setItem('meshcoreVanityObfKey', 'ab'.repeat(32));
    storage.set(api.HISTORY_KEY, JSON.stringify([
        { publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 },
    ]));
    await api.loadHistory();
    eq(localStorageMock.getItem('meshcoreVanityObfKey'), null,
        'legacy obfuscation key must be cleared at load');
    storage.delete(api.HISTORY_KEY);
});

await asyncCheck('undecodable history is never overwritten by a new key', async () => {
    // Regression: the stored blob may be the user's ONLY copy of older keys.
    // Mining a new key and persisting would silently destroy them, which would
    // make the "not deleted" reassurance a lie.
    storage.set(api.HISTORY_KEY, '7b3d6a7f8271615b');  // undecodable
    await api.loadHistory();

    api.addKeyToHistory({
        publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64),
        attempts: 1, elapsed: 1, pattern: "prefix 'a'", minedAt: 'now',
    });
    await api.persistHistory();

    eq(storage.get(api.HISTORY_KEY), '7b3d6a7f8271615b',
        'the unreadable stored history must survive a new key being added');
    // The key is still usable in-memory for this session.
    eq(api.getSavedKeys().length, 1, 'new key should be available in memory');
    const warn = getElementById('history-warn');
    ok(/session only|read-only/i.test(warn.textContent),
        `must explain session-only behaviour: ${warn.textContent}`);
    storage.delete(api.HISTORY_KEY);
});

await asyncCheck('clearHistory can discard unreadable history', async () => {
    // The warning tells the user to use "Clear All Keys" as the escape hatch,
    // so it must work even though savedKeys is empty in this state.
    storage.set(api.HISTORY_KEY, '7b3d6a7f8271615b');
    await api.loadHistory();
    api.clearHistory();
    await api.persistHistory();
    const after = storage.get(api.HISTORY_KEY);
    ok(after !== '7b3d6a7f8271615b', 'clear must overwrite the unreadable blob');
    // Writing must work again after an explicit clear.
    ok(after === 'W10=' || after !== null, `storage should hold empty history: ${after}`);
    storage.clear();
});

await asyncCheck('undecodable history warns instead of looking lost', async () => {
    // Ciphertext that this machine's key cannot read (fingerprint changed).
    storage.set(api.HISTORY_KEY, '7b3d6a7f8271615b');
    await api.loadHistory();
    const warn = getElementById('history-warn');
    ok(warn.style.display !== 'none', 'a decode failure must be surfaced');
    ok(/could not be decoded/.test(warn.textContent),
        `warning should explain, got: ${warn.textContent}`);
    ok(/still stored/.test(warn.textContent),
        'must reassure that the data is not deleted');
    // Critically: the ciphertext must be left in place.
    eq(storage.get(api.HISTORY_KEY), '7b3d6a7f8271615b',
        'unreadable history must not be deleted');
    storage.delete(api.HISTORY_KEY);
});

await asyncCheck('concurrent persists serialise, last write wins', async () => {
    // persistHistory is async; overlapping calls must not interleave writes.
    storage.clear();
    // Load a decodable history first: this also clears any read-only state left
    // by an earlier decode-failure test.
    storage.set(api.HISTORY_KEY, '[]');
    await api.loadHistory();
    eq(api.isHistoryUnreadable(), false, 'precondition: writes must be allowed');
    api.getSavedKeys().length = 0;
    const realDigest = globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle);
    let release;
    const gate = new Promise((r) => { release = r; });
    let first = true;
    globalThis.crypto.subtle.digest = async (...a) => {
        if (first) { first = false; await gate; }  // hold the first save open
        return realDigest(...a);
    };
    api.__resetObfKeyCache();
    api.getSavedKeys().push({ publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 });
    const p1 = api.persistHistory();
    api.getSavedKeys().push({ publicKey: 'c'.repeat(64), privateKey: 'd'.repeat(64), n: 2 });
    const p2 = api.persistHistory();
    release();
    await Promise.all([p1, p2]);
    globalThis.crypto.subtle.digest = realDigest;
    // Whatever landed last must be internally consistent (decodable), never a
    // half-written blend of the two states.
    const stored = storage.get(api.HISTORY_KEY);
    ok(stored, 'history must have been written');
    const decoded = await api.decryptHistoryData(stored);
    const parsed = JSON.parse(decoded);
    ok(Array.isArray(parsed), 'stored history must be valid JSON');
    ok(parsed.length === 1 || parsed.length === 2,
        `stored history must be one coherent state, got ${parsed.length} entries`);
    storage.clear();
});

await asyncCheck('history survives environment changes when the secret is present', async () => {
    // The realistic data-loss case, and the one this fixes: the key used to
    // depend on a fingerprint containing the user agent, screen metrics and the
    // timezone, so a browser update, a resize or travel silently changed it
    // and the saved keys became unreadable.
    idbData.clear();
    storage.clear();
    idbAvailable = true;
    api.__resetObfKeyCache();
    await api.getOrCreateObfuscationSecret();

    const plain = JSON.stringify([{ publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 }]);
    const written = await api.encryptHistoryData(plain);

    // Change everything the old fingerprint keyed on.
    const origUA = navigatorMock.userAgent;
    const origOffset = Date.prototype.getTimezoneOffset;
    navigatorMock.userAgent = 'Mozilla/5.0 (Chrome 999)';
    Date.prototype.getTimezoneOffset = () => -840;
    api.__resetObfKeyCache();
    try {
        eq(await api.decryptHistoryData(written), plain,
            'history must survive a UA update and a timezone change');
    } finally {
        navigatorMock.userAgent = origUA;
        Date.prototype.getTimezoneOffset = origOffset;
        api.__resetObfKeyCache();
        storage.clear();
    }
});

await asyncCheck('a lost secret preserves the ciphertext instead of destroying it', async () => {
    // Being precise: data encrypted with the secret CANNOT be recovered if the
    // secret is gone - no other candidate derives the same keystream. What we
    // can guarantee is that the bytes are never overwritten or replaced with
    // something unreadable, so the situation is recoverable if the secret comes
    // back (and is otherwise reported, not silently blanked).
    idbData.clear();
    storage.clear();
    idbAvailable = true;
    api.__resetObfKeyCache();
    await api.getOrCreateObfuscationSecret();

    const plain = JSON.stringify([{ publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 }]);
    const written = await api.encryptHistoryData(plain);

    idbData.clear();
    idbAvailable = false;
    api.__resetObfKeyCache();
    try {
        // A new key found later must not clobber the unreadable blob.
        storage.set(api.HISTORY_KEY, written);
        await api.loadHistory();
        api.addKeyToHistory({
            publicKey: 'e'.repeat(64), privateKey: 'f'.repeat(64),
            attempts: 1, elapsed: 1, pattern: "prefix 'e'", minedAt: 'now',
        });
        await api.persistHistory();
        eq(storage.get(api.HISTORY_KEY), written,
            'the original ciphertext must be left byte-for-byte intact');
    } finally {
        idbAvailable = true;
        api.__resetObfKeyCache();
        storage.clear();
    }
});

await asyncCheck('history written by the v1 scheme is still readable', async () => {
    // v1 mixed screen metrics and timezone into the key. Anyone who saved keys
    // on that release must not lose them, so v1 is kept as a candidate.
    await api.getOrCreateObfuscationSecret();

    // Reproduce v1 ciphertext exactly.
    const enc = new TextEncoder().encode(api.legacyFingerprintV1());
    const digest = await globalThis.crypto.subtle.digest('SHA-256', enc);
    const v1Key = Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, '0')).join('');

    const plain = JSON.stringify([{ publicKey: 'c'.repeat(64), privateKey: 'd'.repeat(64), n: 9 }]);
    const text = new TextEncoder().encode(plain);
    const kb = new Uint8Array(v1Key.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    const xored = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) xored[i] = text[i] ^ kb[i % kb.length];
    const combined = new Uint8Array(1 + xored.length);
    combined[0] = 0xef;
    combined.set(xored, 1);
    const v1Blob = btoa(String.fromCharCode.apply(null, combined));

    eq(await api.decryptHistoryData(v1Blob), plain, 'v1 history must still decode');
});

await asyncCheck('decrypt tries every candidate and rejects wrong keys', async () => {
    const keys = await api.deriveObfuscationKeys();
    ok(keys.length >= 2, `expected multiple candidates, got ${keys.length}`);
    ok(new Set(keys).size === keys.length, 'candidate keys must be distinct');
    ok(keys.every(k => /^[0-9a-f]{64}$/.test(k)), 'each key is 32 hex bytes');
    eq(await api.decryptHistoryData('7b3d6a7f8271615b'), '7b3d6a7f8271615b',
        'garbage must pass through unchanged, not as mojibake');
});

await asyncCheck('legacy plaintext history still loads', async () => {
    const legacy = JSON.stringify([{ publicKey: 'a'.repeat(64), privateKey: 'b'.repeat(64), n: 1 }]);
    eq(await api.decryptHistoryData(legacy), legacy,
        'pre-existing plaintext history must remain readable');
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

async function runWorker(workerJsPath, { resolveReadyImmediately = true, keygen = null, now = null } = {}) {
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
            // Default stub: the public key always starts with "abcd", so any
            // prefix test that wants more than one batch must pass `keygen`.
            const defaultKeygen = () => {
                const pk = new Uint8Array(32);
                pk[0] = 0xab; pk[1] = 0xcd;
                return { publicKey: pk, privateKey: new Uint8Array(64), keyType: 'ed25519' };
            };
            const make = keygen || defaultKeygen;
            if (resolveReadyImmediately) {
                g.sodium.crypto_sign_seed_keypair = make;
            } else {
                // Deferred: crypto API absent until ready resolves, exactly
                // like the real Emscripten build.
                g.libsodium.ready.then(() => {
                    g.sodium.crypto_sign_seed_keypair = make;
                });
            }
        },
    };
    workerGlobal.self = workerGlobal;
    workerGlobal.globalThis = workerGlobal;
    // The worker's report throttle and yield budget are both driven by
    // Date.now(), so a test that needs a specific number of reports has to
    // control the clock rather than sleep and hope. Subclassing Date keeps
    // `new Date()` working while making now() the injected one.
    if (now) {
        workerGlobal.Date = class extends Date {
            static now() { return now(); }
        };
    }

    vm.createContext(workerGlobal);
    vm.runInContext(src, workerGlobal, { filename: 'worker.js' });

    // Let the boot IIFE start and (if immediate) settle.
    await new Promise((r) => setTimeout(r, 0));
    return { workerGlobal, posted, resolveReady };
}

const workerJsPath = process.argv[3];
if (workerJsPath) {
    // 0. Progress reporting must not repeat a batch.
    //
    // The throttle compares against lastProgressReport, which starts at 0, so
    // the very first report is never suppressed - a forced "first report" on top
    // of it therefore posts the same batch twice. That is wasted main-thread work
    // (a message, a forced layout and a canvas repaint) in a loop whose whole
    // point was to reduce exactly that. Counted rather than eyeballed.
    await (async () => {
        try {
            // A keygen that matches only after MATCH_AFTER candidates, so the
            // worker runs several full batches before finishing. It must
            // terminate: the harness has no Worker.terminate(), so a keygen that
            // never matches leaves the mining loop spinning and node never exits.
            const MATCH_AFTER = 1024;
            // Fake clock advanced from inside the keygen: 256 candidates is one
            // batch and one second, and reports are throttled at
            // REPORT_EVERY_MS, so this produces exactly one report per batch,
            // deterministically and without sleeping.
            let clock = 1000000;
            let n = 0;
            const keygen = () => {
                const pk = new Uint8Array(32);
                const hit = n >= MATCH_AFTER;
                pk[0] = hit ? 0xab : 0x00;
                pk[1] = hit ? 0xcd : 0x00;
                n++;
                if (n % 256 === 0) clock += 1000;
                return { publicKey: pk, privateKey: new Uint8Array(64), keyType: 'ed25519' };
            };
            const { workerGlobal, posted } = await runWorker(workerJsPath, { keygen, now: () => clock });
            workerGlobal.onmessage({
                data: { prefix: 'ab', suffix: '', matchPrefix: true, matchSuffix: false },
            });
            for (let i = 0; i < 40 && !posted.some((m) => m.type === 'found'); i++) {
                await new Promise((r) => setTimeout(r, 0));
            }
            ok(posted.some((m) => m.type === 'found'),
                `the worker never finished, so the test would hang: ${posted.length} messages`);
            const progress = posted.filter((m) => m.type === 'progress');
            ok(progress.length >= 2,
                `expected the throttle to admit a second report, got ${progress.length}: `
                + JSON.stringify(progress.map((m) => m.attempts)));
            // The first report must not be throttled away: lastProgressReport
            // starts at 0, so the first call always reports.
            ok(progress[0].attempts <= 256,
                `the first report must cover the first batch, got ${progress[0].attempts}`);
            // The duplicate's signature is two reports describing the SAME work.
            // Later reports are legitimate, so the check is strict monotonicity
            // rather than a fixed count.
            for (let i = 1; i < progress.length; i++) {
                ok(progress[i].attempts > progress[i - 1].attempts,
                    `report ${i} must describe strictly more work than report ${i - 1}: `
                    + JSON.stringify(progress.map((m) => m.attempts)));
            }
            passed++;
        } catch (e) {
            failures.push(`worker first-batch reporting: ${e.message}`);
        }
    })();
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

// ---- worker lifecycle -------------------------------------------------------
// Regression for a CPU leak that shipped once: workers were returned to a reuse
// pool on stop instead of being terminated. Because a mining worker loops on
// `while (true)`, that meant "Stop" left every worker spinning at 100% CPU.
// Workers must be terminated, and their blob URLs revoked, on every exit path.

// Mirror what startMining() does: create the worker, then track it in the
// module-level `workers` array that terminateAllWorkers() drains.
function spawnTrackedWorker() {
    const w = api.createMiningWorker('self.onmessage=null;');
    api.__trackWorker(w);
    return w;
}

check('createMiningWorker registers its blob URL for cleanup', () => {
    const before = urlStats.objectURLs.size;
    spawnTrackedWorker();
    ok(api.liveWorkerCount() === 1, 'created worker must be tracked as live');
    eq(urlStats.objectURLs.size, before + 1, 'blob URL should be tracked:');
    api.terminateAllWorkers();
});

check('terminateAllWorkers terminates every live worker (no CPU leak)', () => {
    spawnTrackedWorker();
    spawnTrackedWorker();
    spawnTrackedWorker();
    eq(api.liveWorkerCount(), 3, 'three workers should be live:');
    ok(workerStats.live >= 3, `expected >=3 live workers, saw ${workerStats.live}`);

    api.terminateAllWorkers();

    eq(api.liveWorkerCount(), 0, 'worker list should be empty:');
    eq(workerStats.live, 0, `no worker may survive teardown (live=${workerStats.live}):`);
    eq(api.initTimeoutCount(), 0, 'init timeouts must be cleared:');
    eq(urlStats.objectURLs.size, 0,
        `every blob URL must be revoked (leaked ${urlStats.objectURLs.size}):`);
});

check('terminateAllWorkers is idempotent', () => {
    api.terminateAllWorkers();
    api.terminateAllWorkers();
    eq(workerStats.live, 0, 'repeat teardown must not resurrect workers:');
    eq(api.liveWorkerCount(), 0, 'worker list stays empty:');
});

// ---- report ----------------------------------------------------------------

if (failures.length) {
    console.error(`\nFAILED ${failures.length} of ${failures.length + passed} checks:\n`);
    for (const f of failures) console.error('  - ' + f);
    process.exit(1);
}
console.log(`page JS OK: ${passed} behaviour checks passed`);
