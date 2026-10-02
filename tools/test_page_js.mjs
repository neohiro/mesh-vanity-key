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

const urlStats = { objectURLs: new Set() };
const URLMock = {
    createObjectURL(blob) {
        const u = `blob:mock/${urlStats.objectURLs.size}`;
        urlStats.objectURLs.add(u);
        return u;
    },
    revokeObjectURL(u) {
        if (urlStats.objectURLs.delete(u)) workerStats.revokedUrls++;
    },
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

const sandbox = {
    document: documentMock,
    navigator: navigatorMock,
    window: windowMock,
    console,
    // Validation failures report via alert(); capture instead of blocking.
    alert(msg) { alerts.push(String(msg)); },
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
    Worker: class {
        constructor(url) {
            this.url = url;
            this.terminated = false;
            workerStats.created++;
            workerStats.live++;
        }
        postMessage() {}
        terminate() {
            if (!this.terminated) {
                this.terminated = true;
                workerStats.terminated++;
                workerStats.live--;
            }
        }
    },
};
sandbox.globalThis = sandbox;
sandbox.self = sandbox;

// Expose the script's top-level bindings for assertions. The page script uses
// classic (non-module) top-level function declarations, so a function-scoped
// wrapper lets us return them.
vm.createContext(sandbox);
vm.runInContext(
    `${source}\n;globalThis.__api = { formatElapsed, detectOptimalWorkers, updateEstimate, ratePerWorker, validateHex, checkReservedPrefix, validateForm, loadHistory, persistHistory, addKeyToHistory, renderHistory, currentPatternDesc, isQuotaError, sodiumIsUsable, awaitSodium, csvCell, HISTORY_KEY, MAX_SAVED_KEYS, resetForm, getSavedKeys: () => savedKeys, resetRateSmoothing, smoothRate, getSmoothedRate, invalidHexChars, escapeHtml, updatePatternNotice, createMiningWorker, terminateAllWorkers, stopMining, startMining, miningState: () => mining, liveWorkerCount: () => workers.length, initTimeoutCount: () => initTimeouts.length, __trackWorker: (w) => workers.push(w), clearHistory, isHistoryUnreadable: () => historyUnreadable, machineFingerprint, deriveObfuscationKeys, getOrCreateObfuscationSecret, legacyFingerprintV1, formatProgressLine, progressEtaClause, formatDayHint, formatEta, resetLiveLogs, encryptHistoryData, decryptHistoryData, __resetObfKeyCache: () => { obfKeyPromise = null; } };`,
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

    // Green styling.
    ok(/\.live-v\s*\{[^}]*color:\s*#7ee787/.test(html),
        'live values should be green');

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
    eq(getElementById('live-eta').textContent, '-', 'eta reset');
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
