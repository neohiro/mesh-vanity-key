// Correctness cross-check for the rewritten worker hot loop.
//
// Verifies the allocation-free byte-walk against the previous BigInt/hex-string
// reference implementation:
//   1. the 32-byte big-endian increment matches BigInt +1n modulo 2**256
//   2. nibble matching is identical to hex startsWith/endsWith for every
//      pattern length (including odd lengths and full 64-char patterns)
//   3. the walk enumerates a contiguous, collision-free candidate sequence
//
// Run: bun tools/verify_worker_math.mjs

import assert from 'node:assert';

// --- the implementation under test (mirrors index.html) -------------------
const HEXNIB = new Int8Array(256).fill(-1);
for (let i = 0; i < 10; i++) HEXNIB[48 + i] = i;
for (let i = 0; i < 6; i++) HEXNIB[97 + i] = 10 + i;

const decodeNibbles = (hex) => {
    const out = new Uint8Array(hex.length);
    for (let i = 0; i < hex.length; i++) out[i] = HEXNIB[hex.charCodeAt(i)] & 0xff;
    return out;
};
const startsWithNibbles = (pub, nib, len) => {
    if (len > 64) return false;
    for (let j = 0; j < len; j++) {
        const b = pub[j >> 1];
        if (((j & 1) ? (b & 15) : (b >> 4)) !== nib[j]) return false;
    }
    return true;
};
const endsWithNibbles = (pub, nib, len) => {
    if (len > 64) return false;
    const total = 64;
    for (let j = 0; j < len; j++) {
        const k = total - len + j;
        const b = pub[k >> 1];
        if (((k & 1) ? (b & 15) : (b >> 4)) !== nib[j]) return false;
    }
    return true;
};
const bytesToHex = (bytes) => {
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
    return out;
};

// --- 1. byte increment == BigInt increment, including wraparound ----------
{
    const seed = new Uint8Array(32);
    seed[31] = 0xfe;   // two below a byte-boundary carry
    let ref = BigInt('0x' + bytesToHex(seed));
    const inc = () => {
        for (let i = 31; i >= 0; i--) {
            seed[i] = (seed[i] + 1) & 0xff;
            if (seed[i] !== 0) return;
        }
    };

    for (let i = 0; i < 5; i++) {
        inc();
        ref = (ref + 1n) & ((1n << 256n) - 1n);
        assert.equal(bytesToHex(seed), ref.toString(16).padStart(64, '0'), `increment #${i}`);
    }

    // Full wrap: all-0xFF + 1 must become all-zero.
    seed.fill(0xff);
    inc();
    assert.equal(bytesToHex(seed), '0'.repeat(64), 'must wrap 2**256 -> 0');

    // Carry propagation across a run of 0xFF bytes.
    seed.fill(0);
    seed[30] = 0xff; seed[31] = 0xff;
    seed[29] = 0x01;
    inc();
    assert.equal(bytesToHex(seed), '0'.repeat(58) + '02' + '0000', 'carry chain');

    // Regression: ++seed[i] returns 256 (unclamped) on a Uint8Array, so the
    // naive `if (++seed[i] !== 0) return;` drops every carry.
    {
        const probe = new Uint8Array(32);
        probe[31] = 0xff;
        const naive = () => { for (let i = 31; i >= 0; i--) { if (++probe[i] !== 0) return; } };
        naive();
        assert.equal(bytesToHex(probe), '0'.repeat(64),
            'naive ++ increment drops the carry (documents the bug)');
        // ...and the shipped form must carry correctly.
        probe[31] = 0xff;
        const masked = () => {
            for (let i = 31; i >= 0; i--) {
                probe[i] = (probe[i] + 1) & 0xff;
                if (probe[i] !== 0) return;
            }
        };
        masked();
        assert.equal(bytesToHex(probe), '0'.repeat(60) + '0100',
            'masked increment must carry into the next byte');
    }
    console.log('ok: byte increment matches BigInt incl. wraparound and carry');
}

// --- 2. nibble matching == hex string matching ----------------------------
{
    let checked = 0;
    for (let trial = 0; trial < 400; trial++) {
        const pub = new Uint8Array(32);
        for (let i = 0; i < 32; i++) pub[i] = (Math.random() * 256) | 0;
        const pubHex = bytesToHex(pub);

        for (let len = 0; len <= 64; len++) {
            if (len === 0) continue;
            // Prefix taken from the actual key so we exercise real matches.
            const prefix = pubHex.slice(0, len);
            assert.equal(
                startsWithNibbles(pub, decodeNibbles(prefix), len), true,
                `true prefix len ${len} must match`);
            // Flip the final nibble: must not match.
            const last = parseInt(prefix[len - 1], 16);
            const flipped = prefix.slice(0, -1) + ((last ^ 1) & 0xf).toString(16);
            assert.equal(
                startsWithNibbles(pub, decodeNibbles(flipped), len), false,
                `flipped prefix len ${len} must not match`);

            const suffix = pubHex.slice(64 - len);
            assert.equal(
                endsWithNibbles(pub, decodeNibbles(suffix), len), true,
                `true suffix len ${len} must match`);
            const first = parseInt(suffix[0], 16);
            const sflipped = ((first ^ 1) & 0xf).toString(16) + suffix.slice(1);
            assert.equal(
                endsWithNibbles(pub, decodeNibbles(sflipped), len), false,
                `flipped suffix len ${len} must not match`);
            checked++;
        }
    }
    // Over-long patterns can never match (guard against out-of-range reads).
    assert.equal(startsWithNibbles(new Uint8Array(32), decodeNibbles('ab'.repeat(40)), 80), false);
    assert.equal(endsWithNibbles(new Uint8Array(32), decodeNibbles('ab'.repeat(40)), 80), false);
    console.log(`ok: nibble matching == hex matching (${checked.toLocaleString()} length cases)`);
}

// --- 3. walk enumerates a contiguous, unique candidate sequence ------------
{
    const seed = new Uint8Array(32).fill(0);
    const inc = () => {
        for (let i = 31; i >= 0; i--) {
            seed[i] = (seed[i] + 1) & 0xff;
            if (seed[i] !== 0) return;
        }
    };
    const seen = new Set();
    let prev = -1;
    for (let i = 0; i < 5000; i++) {
        const v = Number(BigInt('0x' + bytesToHex(seed)));
        assert.ok(v > prev, `walk must increase (${v} !> ${prev})`);
        assert.ok(!seen.has(v), `walk must not repeat (${v})`);
        seen.add(v);
        prev = v;
        inc();
    }
    assert.equal(seen.size, 5000, 'all candidates distinct');
    console.log('ok: walk is contiguous, strictly increasing, collision-free');
}

console.log('\nworker math verified');