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
    `${source}\n;globalThis.__api = { formatElapsed, detectOptimalWorkers, updateEstimate, ratePerWorker, validateHex, checkReservedPrefix, validateForm, loadHistory, persistHistory, addKeyToHistory, renderHistory, currentPatternDesc, isQuotaError, sodiumIsUsable, awaitSodium, csvCell, HISTORY_KEY, MAX_SAVED_KEYS, resetForm, getSavedKeys: () => savedKeys, resetRateSmoothing, smoothRate, getSmoothedRate, invalidHexChars, escapeHtml, updatePatternNotice, createMiningWorker, terminateAllWorkers, stopMining, startMining, miningState: () => mining, startingState: () => starting, resetForm, liveWorkerCount: () => workers.length, initTimeoutCount: () => initTimeouts.length, __trackWorker: (w) => workers.push(w), clearHistory, isHistoryUnreadable: () => historyUnreadable, machineFingerprint, deriveObfuscationKeys, getOrCreateObfuscationSecret, legacyFingerprintV1, formatProgressLine, progressEtaClause, formatDayHint, formatEta, etaParts, renderEta, setEtaMessage, pad2, resetLiveLogs, reportActualWorkers, encryptHistoryData, decryptHistoryData, __resetObfKeyCache: () => { obfKeyPromise = null; }, workerScale, smoothEta, resetEtaSmoothing, ETA_MIN_SAMPLES, ETA_SMOOTHING_ALPHA, WORKER_SCALE_MEASURED, WORKER_SCALE_EXPONENT, setStatusText, clearStatusText, pushRateGraphSample, resetRateGraph, rateGraphState: () => rateGraph.map((s) => ({ t: s.t, v: s.v })), RATE_GRAPH_POINTS, RATE_GRAPH_WINDOW_MS, getStatusText: () => document.getElementById('progress-text').textContent, getStatusHidden: () => document.getElementById('progress-text').hidden, getLiveEtaText: (id) => { const el = document.getElementById(id); return el ? el.textContent : null; }, getEstimateText: () => document.getElementById('estimate').textContent, exportHistory, exportHistoryInWorker, downloadFile };`,
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
    // "workers share cores" explains the caveat; that is not the plural bug.
    ok(!/(?<!share cores, so )\bworkers\b(?! share cores)/.test(txt.replace(/workers share cores/g, '')),
        `must not use plural for the count: ${txt}`);
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
    eq(api.WORKER_SCALE_MEASURED[8], 2.3, 'the measurement is recorded');
    eq(Math.round(api.workerScale(8) * 100) / 100, 2.3,
        '8 workers must reproduce the measured 2.3x');
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

check('workerScale: the documented exponent matches the code', () => {
    // The page's comment block spells out the exponent and the interpolated
    // multipliers. Those went stale unnoticed for a long time (they claimed
    // ~0.457 / 1.37x / 1.87x while the code computes 0.4005 / 1.32x / 1.74x),
    // because every other test here checks SHAPE - concave, sublinear, anchored
    // - and shape is identical whichever exponent you fit. This pins the actual
    // values, and cross-checks them against the comment text, so a comment that
    // drifts from the code fails the build instead of misleading the next
    // person who re-measures.
    const expected = Math.log(api.WORKER_SCALE_MEASURED[8]) / Math.log(8);
    eq(api.WORKER_SCALE_EXPONENT.toFixed(4), expected.toFixed(4),
        'the exponent is exactly log(measured)/log(8)');

    // Recompute from first principles rather than trusting the constant.
    for (const n of [2, 4, 8, 16, 32]) {
        eq(api.workerScale(n).toFixed(3), Math.pow(n, expected).toFixed(3),
            `workerScale(${n}) must follow the documented power law`);
    }

    // The figures the page's comment quotes, asserted against the code. These
    // are the exact numbers stated in the MEASUREMENT BASIS comment block.
    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    const exp = api.WORKER_SCALE_EXPONENT.toFixed(4);
    // The comment writes the exponent with a leading '~' (it is an approximation).
    ok(html.includes(`exponent ~${exp}`) || html.includes(`exponent ${exp}`),
        `the comment must state the real exponent (~${exp})`);
    ok(!/exponent ~0\.457/.test(html),
        'the stale 0.457 exponent must not come back');
    ok(!/1\.37x at 2 threads/.test(html) && !/1\.87x at 4/.test(html),
        'the stale interpolated figures must not come back');

    // And the README quotes the same exponent; keep the two in agreement.
    const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
    ok(readme.includes(expected.toFixed(4)),
        `the README must state the same exponent (${expected.toFixed(4)})`);
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

    // Hours get the wide reserved slot; minutes and seconds exactly two.
    ok(/\.eta-num\s*\{[^}]*min-width:\s*2\d\s*ch/.test(html),
        'hours must reserve 20+ digits for multi-week runs');
    // Narrow screens cannot afford 20ch without overflowing, but must stay
    // fixed-width there too -- proportional space would reintroduce reflow.
    const narrow = html.slice(html.indexOf('@media (max-width: 420px)'));
    ok(/@media \(max-width: 420px\)[\s\S]*?\.eta-num\s*\{[^}]*min-width:\s*\d+\s*ch/.test(narrow),
        'narrow screens must keep a fixed hour slot, just a smaller one');
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

    // 116h 27m 22s -- the multi-week case this layout exists for.
    let p = api.etaParts(116 * 3600 + 27 * 60 + 22);
    eq(p.hours, 116);
    eq(p.minutes, 27);
    eq(p.seconds, 22);
    ok(/\(~5 days\)/.test(p.dayHint), 'the day estimate is still attached');

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
    eq(api.getLiveEtaText('live-eta-h'), '116');
    eq(api.getLiveEtaText('live-eta-m'), '07', 'minutes padded to two');
    eq(api.getLiveEtaText('live-eta-s'), '05', 'seconds padded to two');

    // A message state blanks the slots but must not leave stale digits behind.
    api.setEtaMessage('sampling...');
    eq(api.getLiveEtaText('live-eta-days'), 'sampling...');
    eq(api.getLiveEtaText('live-eta-h'), '');
    eq(api.getLiveEtaText('live-eta-m'), '');
    eq(api.getLiveEtaText('live-eta-s'), '');

    // ...and switching back to a real duration must restore them.
    api.renderEta(65);
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

check('estimate: states the measured scale instead of hedging', () => {
    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    // The scaling factor's provenance now lives only in WORKER_SCALE_MEASURED
    // and the README's "Worker scaling" section. It was also printed inline,
    // where it added a long clause that wrapped the whole line on a narrow
    // screen, so it is asserted ABSENT to keep it from creeping back.
    ok(!/scale derived from 2\.3x at 8 threads/.test(html),
        'the estimate must not print the scaling factor\'s provenance inline');
    ok(/improvement is only ~/.test(html),
        'the estimate must state the improvement multiplier');
    ok(!/so actual will be lower/.test(html),
        'the vague "actual will be lower" caveat must be gone');
    // The multiplier itself must survive the removal, otherwise the estimate
    // would go back to quietly implying linear scaling.
    ok(/improvement is only ~['"]?\s*\+?\s*scale\.toFixed/.test(html)
        || /improvement is only ~/.test(html),
        'the estimate must still disclose the actual multiplier');
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
    const state = api.rateGraphState();
    eq(state[state.length - 1].v, 200 + ((cap * 4 - 1) % 7),
        'the newest sample is the one just pushed');

    api.resetRateGraph();
    eq(api.rateGraphState().length, 0, 'a new search clears the trace');
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
            // "now" is drawn from it.
            eq(st[st.length - 1].v, 1000 + n - 1,
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
    // each pair instead of the newer. This is only observable on data where
    // the choice matters: on a uniform ramp both choices give a stride of 2,
    // so an arithmetic series cannot tell them apart. Here every sample is
    // either a low or a high value, and the survivors must be the HIGH one of
    // each pair, because those are the readings closer to the real rate at the
    // moment they were kept.
    const CAP = api.RATE_GRAPH_POINTS;
    api.resetRateGraph();
    let c = 0;
    Date.now = () => t0 + c * 1000;
    try {
        for (let i = 0; i < CAP; i++) {
            // Strictly increasing within a pair, and the second of each pair is
            // always the larger value, so index parity is observable.
            api.pushRateGraphSample(i % 2 === 0 ? 1000 : 2000);
            c++;
        }
        api.pushRateGraphSample(1000);   // overflows by one, forcing one halving
        c++;
        const st = api.rateGraphState();
        eq(st[st.length - 1].v, 1000, 'the newest sample survives the halving');
        const body = st.slice(0, -1);
        ok(body.length > 0, 'expected retained samples to inspect');
        // Every survivor from a (low, high) pair must be the high one.
        const wrong = body.filter((s) => s.v !== 2000);
        ok(wrong.length === 0,
            `decimation must keep the newer (higher) of each pair, but retained `
            + `${wrong.length} stale reading(s) of 1000 in ${JSON.stringify(body.map((s) => s.v))}`);
    } finally {
        Date.now = realNow;
        api.resetRateGraph();
    }
});

check('estimate omits the scaling provenance clause', () => {
    getElementById('prefix').value = 'ab';
    getElementById('suffix').value = '';
    api.updateEstimate();
    const txt = api.getEstimateText();
    ok(!/scale derived from/.test(txt),
        `the provenance clause must not be printed: ${txt}`);
    // The multiplier is the part that carries the meaning, so it must stay.
    ok(/improvement is only ~\d/.test(txt),
        `the multiplier must still be stated: ${txt}`);
    ok(/keys\/s/.test(txt), 'the rate must still be stated');
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
    eq(getElementById('live-workers').textContent, '0', 'workers reset');
    eq(getElementById('live-cores').textContent, '-', 'cores reset');
});

check('live logs report the workers actually running', () => {
    // The pre-flight estimate is a per-worker extrapolation; showing the real
    // running count and the core count is what makes a shortfall visible
    // instead of mysterious.
    api.resetLiveLogs(8, 8);
    eq(getElementById('live-workers').textContent, '8', 'planned workers shown');
    eq(getElementById('live-cores').textContent, '8', 'cores shown');

    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    ok(html.includes('id="live-workers"'), 'workers cell present');
    ok(html.includes('id="live-cores"'), 'cores cell present');

    api.reportActualWorkers(3);
    eq(getElementById('live-workers').textContent, '3',
        'actual running count must replace the plan');
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

check('the pre-flight estimate says it is an upper bound', () => {
    // Calibration is single-core; workers then share those cores, so rate x
    // workers is unreachable. The label must not read as a promise.
    const html = fs.readFileSync(pageHtmlPath, 'utf8');
    ok(/workers share cores/.test(html),
        'estimate must disclose that workers share cores');
    ok(/up to /.test(html), 'rate must be presented as a ceiling');
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
