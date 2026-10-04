# meshcore-meshtastic-vanity-key

A fast, MeshCore-compatible Ed25519 vanity public-key generator.

**[Try it in your browser →](https://neohiro.github.io/meshcore-meshtastic-vanity-key/)**
No install, no build step, works offline once loaded.

Ships in two forms:

- **[Browser app](https://neohiro.github.io/meshcore-meshtastic-vanity-key/)** — a
  zero-install PWA that mines with Web Workers + libsodium WASM.
- **Python CLI** — bech32/base58/base64 output and parallel multiprocessing.

```bash
./run.sh abcd          # Linux/macOS  — installs PyNaCl on first run
run.bat abcd           # Windows
```

That is the whole install. Anything after the pattern goes straight through to
the CLI, so `./run.sh mc1q --encoding bech32 --workers 8` works too. See
[Running it](#running-it) for the flags.

Inspired by and credited to [MeshCore](https://meshcore.io/) — a decentralized
mesh networking project. This tool generates Ed25519 keypairs whose encoded
public keys match a user-defined pattern, suitable for use with MeshCore
devices and related tooling.

---

## What It Does

Generates Ed25519 cryptographic keypairs until the encoded public key matches a target pattern (prefix, suffix, or both). The search is optimized with a scalar-walk algorithm that avoids repeated hashing, making it significantly faster than naive approaches.

## Vanity & Functional Keypair Mining

<p align="center">
  <img alt="mining" src="https://img.shields.io/badge/mining-Ed25519%20prefix%20%2B%20suffix-7c4dff">
  <img alt="meshtastic" src="https://img.shields.io/badge/Meshtastic-PSK%20%2B%20node%20ID-00b0d9">
  <img alt="offline" src="https://img.shields.io/badge/mining-100%25%20in--browser-2ea043">
</p>

A node's identity is bytes out of a random number generator, and nothing about
them is designed. `a3f1…c902` is as arbitrary as a Wi-Fi MAC address, and it has
to be read off a QR code, dictated over a radio, or pasted into a phone by someone
who cannot see the screen. Mining is the one case where brute force is the right
answer: you pay for the search once, and every later contact with the node is
cheaper. **[meshcore-meshtastic-vanity-key](https://neohiro.github.io/meshcore-meshtastic-vanity-key/)**
is what this repository is, running entirely in the browser — Web Workers plus
libsodium WASM, no network round-trip, no telemetry, and it still works offline
once the page is loaded.

### Vanity and functional are two different goals

| | Vanity | Functional |
|---|---|---|
| **Why** | the identity reads well and is memorable | the identity is *checkable* by a human under bad conditions |
| **Typical target** | `mc1qneohiro…`, `!a1b2c3…` | a prefix **and** a suffix, so a half-transcribed key fails loudly |
| **Cost** | `16ⁿ` attempts for `n` hex characters — 4 is instant, 6 is minutes | that, squared: each constrained end multiplies rather than adds |
| **Classic mistake** | asking for 9+ characters. That is a lottery ticket, not a mnemonic | mining a *reserved* prefix and then wondering why the client refuses the key |

Same code path, same flags. The distinction only matters when deciding what to ask
for — and in both cases the pattern is matched against the **encoded public key**,
never the private one, which never leaves your machine.

### Meshtastic prefix and suffix mining

Meshtastic has two unrelated things people both call "the key", and they are mined
by two unrelated means. Conflating them is the usual first mistake.

**Channel PSK — symmetric, minable directly.** A channel is a name plus a
pre-shared key written `base64:…`. `AQ==` is the single byte `0x01` and is the
well-known default on every device — not a secret. `Ag==`–`Cg==` are the
`simple1`–`simple9` shorthands. A private channel is 16 bytes (AES-128) or 32 bytes
(AES-256). A PSK is raw key material rather than a signing key, so there is no
keypair to derive — the bytes *are* the key, which makes a vanity PSK a genuinely
**functional** target rather than a decoration. `--encoding base64` mines exactly
this form:

```bash
./run.sh NHI --encoding base64              # channel key starting "NHI…"
./run.sh NHI --encoding base64 --suffix 0   # …and ending "…0"
./run.sh --encoding base64 --suffix qw      # suffix only
```

Memorable here means **transcribable**. A group reads a PSK out over an FM handheld
before anybody has a phone paired, and a key with recognisable ends survives that
round trip when a bare 24-character base64 blob does not. Note that base64's last
character is constrained (see
[Suffixes and base64 padding](#suffixes-and-base64-padding)), so a suffix must end
in one of `048AEIMQUYcgkosw`.

**Node key and `!` user ID — a different curve, and one more derivation.** A
Meshtastic node's key is **Curve25519**, not Ed25519, and the `!` + hex ID the
firmware advertises is a *further* derivation from that node key — since firmware
2.5, from the public-key identity rather than from a hardware MAC address, which is
what lets a node keep its identity across a factory reset. Two separate things
therefore have to line up:

```
   seed ─▶ Curve25519 node key ─▶ firmware derivation ─▶ !a1b2c3d4
            ▲ the keypair                              ▲ what you read out of the UI
              that matters
```

The trap worth naming is the curve. `--encoding hex` chooses how a key is
*printed*; it does not choose which key it is. On the default Ed25519 derivation
you get a valid MeshCore device key and **not** a Meshtastic node key, and the
node will simply refuse the import — which reads like a firmware bug and is not
one. Meshtastic node-key mining is a different algorithm, not a different
encoding.

Which leaves the `!` ID itself, and three things worth knowing before spending an
afternoon on it:

- It is fixed width, so there is no short form to ask for. `!a1b2c3d4` is four
  bytes of derivation and nothing truncates it away.
- An ID pattern is **not** a key pattern. Constraining `!a1b2c3d4` constrains a
  derivation *of* the key, not the key, so the search is no cheaper than mining
  the key and usually dearer.
- Node keys are TOFU-bound: the first public key a node hears for a given node
  number is the one it keeps. Change a key after it has been seen and peers treat
  you as a stranger who replaced somebody.

### One caveat, stated plainly

Every device in this family generates its own key on first boot, and **nothing
here changes the identity a shipped firmware hands you**. Mining is for a node you
are deliberately provisioning: a fresh key imported over USB, a companion client,
or a factory-reset device whose identity you are re-establishing anyway. If a node
already has an identity, mine a *new* one and swap it in deliberately. Never
overwrite a key that peers already hold.

## Browser Version

**Live: [neohiro.github.io/meshcore-meshtastic-vanity-key](https://neohiro.github.io/meshcore-meshtastic-vanity-key/)**

The app is a single self-contained PWA (`index.html`) — no build step, and no
dependencies beyond the checked-in `libsodium.js`. To run your own copy it must
be **served over HTTP(S)**, not opened as a `file://` URL, because browsers
refuse to create blob Web Workers from `file://`.

```bash
python -m http.server 8000
# then open http://localhost:8000/
```

Deploy it to any static host (GitHub Pages, Netlify, Cloudflare Pages). The
service worker precaches the app shell and serves stale-while-revalidate, so
the app works offline and picks up new deploys on the next load.

Mobile-friendly: the estimate line breaks between facts rather than mid-number,
Chrome's Android font boosting is disabled, and the container respects the notch
inset.

Browser-specific behaviour, for comparison with the CLI below:

| | Browser app | Python CLI |
|---|---|---|
| Pattern matching | hex only | hex, base64, base64url, base58, bech32 |
| Parallelism | auto-detected Web Workers (every logical core, capped at 32) | `--workers N` processes (CPU count for long searches, capped at 64) |
| Key history | kept in `localStorage`, exportable as JSON/CSV | none |
| Installable | yes (PWA with maskable icons) | n/a |
| Private key | shown per result, stored in history | printed to stderr by default; `--no-output-private` suppresses |
| History display | newest first, scroll stays at the top | n/a |

> **Security:** the browser app obfuscates saved keys in `localStorage` with an
> XOR keystream. The key is `SHA-256(secret || origin)`, where `secret` is 32
> random bytes minted once and kept in **IndexedDB** — a different storage
> backend from the ciphertext. So lifting `localStorage` on its own (backup,
> sync, shared profile, a stray export) does not yield the key, while
> `origin` binds the key to this site so a copy of both stores only decodes
> here.
>
> Because the key does not depend on anything the browser can change under the
> user, saved history survives browser updates that alter the user-agent
> string, timezone changes while travelling, and window resizes. (An earlier
> version derived the key purely from a hardware fingerprint and every one of
> those permanently orphaned the history.)
>
> This is **obfuscation, not encryption**, and it has a deliberate scope. It
> stops data-at-rest theft from a copied storage blob. It does **not** protect
> against script running on the origin (XSS, a malicious extension), because
> such code can read IndexedDB. Treat the history as a secret store, and clear
> it when done.
>
> If IndexedDB is unavailable (private mode, storage disabled) the key falls back
> to `SHA-256(fingerprint)`, so history still round-trips rather than being lost.
> The chosen mode is recorded on first run and never re-decided, because
> switching modes would change the key and orphan every stored key.
>
> If no key can be derived at all, the page **refuses to save** rather than
> writing plaintext. A silently-degraded path would put saved private keys in
> `localStorage` in the clear, which is the exact exposure this scheme exists to
> prevent; instead the session keeps keys in memory and says so.

Reserved hex prefixes `00` and `ff` are **mined with a warning** rather than
rejected, in both the browser app and the CLI — some users deliberately want
one. Set `MESHCORE_VANITY_STRICT_RESERVED=1` to make the CLI reject them again.

### Maintaining the PWA assets

- `tools/make_icons.py` regenerates `icon-192.png`, `icon-512.png` and
  `icon-maskable-512.png` from code. Run it after changing the icon design:
  `python tools/make_icons.py`
- When you add or remove a file from `sw.js`'s `urlsToCache`, bump `CACHE_VERSION`
  in the same commit so returning visitors get the new app shell.
- `node tools/test_page_js.mjs <main.js> <worker.js>` executes the page and worker
  JS against a mock DOM; CI runs it after `tools/check_inline_js.py` extracts them.

### The live panel

Six figures are shown while mining: attempts, rate, progress, workers actually
running beside the core count, and ETA. A keys/s trace is drawn behind the ETA row.

**Workers and cores are shown as one `WORKERS | CORES` figure** (`8 | 8`), not as
two separate rows. The point of showing cores at all is the comparison between
them, and across two rows the reader has to join them mentally — which is exactly
the comparison they exist to support. Workers is the count *actually* running, so
a shortfall against the core count is visible rather than mysterious.

**The ETA carries a real day figure** (`4d 19h 05m 30s`), not unbounded total
hours. It previously rendered hours as a running total, so a five-day estimate read
`116h 25m`, and the ` (~4.5 days)` hint beside it was withheld entirely past ~10
days — so the longest searches, the ones where "how many days is this?" matters
most, were the only ones with no day unit anywhere on screen.

**The rate graph answers a different question from the rate figure.** The rate
cell says how fast the search is *now*; the trace says whether that has been
*steady*. A tab throttled in the background, a thermal dip or a GC pause all
show as a visible droop, which a single headline number cannot reveal.

It is deliberately drawn as a **backdrop on the ETA row** rather than as a
separate chart block, so it costs no vertical space and cannot push the figures
around:

- absolutely positioned with `pointer-events: none`, so it never intercepts a
  click aimed at the digits sitting above it, and never enters layout;
- the digits carry a matching dark `text-shadow` so the line crossing a glyph
  cannot make the figure harder to read;
- the x-axis is **real elapsed time over a 2-minute window**, not sample index.
  Reports are throttled per worker and the worker count varies, so a fixed
  sample *count* would not be a fixed span - and the window has to be fixed in
  time or the recent detail (the part anyone looks at) flattens into a straight
  line;
- it plots the **raw** per-batch rate, not the EMA. Smoothing is what the
  headline figure is for; smoothing the trace would hide the variation it exists
  to reveal;
- the y-scale is padded and deliberately **not** zero-based, because a zero
  baseline flattens exactly the variation the graph is for;
- `aria-hidden`, since the numbers it shows are already announced by the live
  region, and it no-ops without a 2d context so it can never throw into the
  progress handler and stall the figures behind it.

It is deliberately **not** suppressed under `prefers-reduced-motion`, unlike the
starfield: that is decoration, this is a data readout. It only changes when the
miner reports a measurement, never animates on a timer, and hiding it would
remove information rather than remove motion.

**The ETA is split into fixed digit slots.** Rendered as one string it reflowed
every time a field changed digit count — `9h 5m 3s` becoming `9h 5m 13s` moved
everything after it, so the row visibly hopped. Instead the duration is written
into separate elements, each reserving its width:

| Slot | Reserved | Why |
|---|---|---|
| days | `5ch` | carries the magnitude, so it is the field that grows |
| hours | `2ch` | the hours *within* the day, so 0–23 and never wider |
| minutes | `2ch` | always two digits, zero-padded |
| seconds | `2ch` | as above |

Hours used to be an unbounded total, reserved at `20ch`, which meant a five-day
estimate rendered as `116h 25m` and the slot carried a wide dead gap beside every
figure. Days now carry the magnitude (`4d 19h 05m 30s`), so hours never exceeds
two digits and the reservation shrank to match.

The panel also sets `font-variant-numeric: tabular-nums`, which is what actually
stops a digit changing width — the reserved `min-width`s then hold the columns.
All three slots stay fixed on screens under 420px, since proportional space would
reintroduce reflow. Minutes and seconds are always padded to two digits, so
`05m` is exactly as wide as `15m`.

**The ETA is also smoothed over time.** It is the most eye-catching number on the
page and the least stable, being an instantaneous rate divided by a large
remaining count. Shown raw it hopped several times a second, which reads as
instability and trains people to ignore the one figure they came for. It is now
withheld until four samples exist — the opening batches are always slower while
WASM warms up, so a figure derived from them would be misleading — and then eased
in with an EMA at `alpha = 0.12`. A 10x spike in the underlying rate moves the
displayed ETA by well under half, instead of tracking it linearly.

### Mining-loop performance

The browser miner spends almost all of its time inside libsodium, so the wrapper
around each candidate must be close to free. Two things dominate it if done
naively, and both were real defects that capped throughput at a few thousand
keys/second **regardless of how fast the crypto was**:

- **Yielding per batch.** Browsers clamp nested `setTimeout(0)` to ≥4 ms. Yielding
  after every batch of candidates therefore throttled each worker to ~4,000
  candidates/s. The worker now yields on a wall-clock budget instead — 250 ms,
  which is 4 times a second per worker rather than 33.
- **Rebuilding hex strings per candidate.** Converting the candidate and public
  key to hex and running `startsWith`/`endsWith` costs more than the keygen. The
  walk state is now a 32-byte array incremented in place, and the pattern is
  pre-decoded to nibbles compared directly against the raw public-key bytes — no
  allocation and no string building in the hot loop.

#### Main-thread overhead

The workers and the UI share the same cores, so UI work is subtracted directly
from mining throughput. Everything the main thread was doing per report has been
cut, because at 500 ms per report and one report per worker it was paying a full
layout plus a canvas repaint several times a second:

| Was | Now | Why |
|---|---|---|
| Report every 500 ms per worker | every 3 s | 16 main-thread wake-ups a second at 8 workers, for figures that are an aggregate rate over seconds. The first report is already immediate — the throttle compares against a counter starting at 0 — so no special case is needed. |
| `canvas.clientWidth`/`clientHeight` read inside every draw | measured once, cached, refreshed by a `ResizeObserver` | Reading them forces a synchronous layout, so each report paid for a full reflow of the panel. |
| Graph trace drawn from raw per-worker samples | exponential average (`α = 0.5`) in `pushRateGraphSample` | Consecutive samples come from different workers over different windows, so raw values differ by a lot and the line read as spikes rather than a trend. The headline rate figure is unchanged — this is display smoothing only. |
| 48 calibration samples at load | 256, yielding every 32 rather than every 8 | 48 was short enough to be dominated by noise, and yielding every 8 spent most of the loop asleep on clamped timers. |

A regression guard asserts the report interval and yield budget stay coarse, that
`drawRateGraph` never re-measures the canvas, and that the ETA keeps a real day
figure.

The CLI benefits from the same lesson in the one place it applied: its progress
`--progress-interval` counts *attempts* (100,000 by default, roughly a second at
typical rates) rather than wall-clock, so a slow machine reports less often
instead of more.

Regression guards:

| Command | Checks |
|---|---|
| `node tools/verify_worker_math.mjs` | the byte-walk is arithmetically identical to the previous BigInt/hex implementation, including 2²⁵⁶ carry and wraparound |
| `node tools/bench_worker.mjs <worker.js>` | wrapper overhead with a stubbed (free) keygen; must stay far above the keygen cost. Runs three trials and reports the best, so JIT warm-up or a descheduled shared vCPU cannot fail an otherwise healthy run — a real regression drops every trial and still fails hard |
| `node tools/bench_worker_scaling.mjs` | aggregate throughput vs worker count, using a synthetic ALU+table workload. Reports higher scaling than is real - its workload is ILP-friendly - so prefer the keygen probe below |
| `node tools/bench_keygen_scaling.mjs` | aggregate keys/s vs thread count using the **real** `crypto_sign_seed_keypair` from the shipped wasm. The trustworthy of the two scaling probes — see "Worker scaling" |
| `node tools/check_keygen_baseline.mjs <report>` | compares a keygen-scaling run against `tools/keygen_baseline.json`; fails only on a large **drop**. Runs nightly via the `keygen-scaling` workflow |

#### Where a candidate's time actually goes (CLI)

Measured on the development host, best-of-N, so the split is not noise:

| Component | Per candidate | Share |
|---|---|---|
| `crypto_sign_seed_keypair` (whole primitive) | ~36.7 µs | — |
| — of which Ed25519 scalar multiplication | ~32.4 µs | ~88% |
| — of which SHA-512 over the seed | ~0.9 µs | ~2.5% |
| Hex encode + pattern compare | ~0.2 µs | ~1% |
| Scalar-walk bookkeeping | ~0.3 µs | ~1% |

The scalar multiplication is irreducible without changing the algorithm, and the
algorithm is already the right one — see "Scalar-Walk Optimization". Two
consequences worth stating plainly:

- **Switching to `crypto_scalarmult_base` to skip SHA-512 would buy ~2.5%**, and
  needs a re-clamp per candidate since incrementing a clamped scalar breaks the
  clamping. Not worth the correctness risk.
- **The remaining wrapper is ~1–2%.** Micro-optimising the encode/compare path
  cannot move keys/s meaningfully; the browser needs its nibble comparison
  because JS overhead is a far larger share there, but Python does not.

The one genuinely contended resource is the shared progress counter, which every
worker locks once per 16 candidates. Measured at 8 workers it costs ~0.6 µs per
batch against ~620 µs of keygen — **~0.1%** — so `--workers` is the only real
throughput lever, and it is already there.

> **Careful:** never write `if (++bytes[i] !== 0)`. Incrementing a `Uint8Array`
> element returns the *unclamped* value (`256`, not `0`), so the carry test never
> fires and the counter silently stops at a byte boundary. Mask explicitly:
> `bytes[i] = (bytes[i] + 1) & 0xff;` then test `bytes[i] !== 0`.

### Why libsodium.js, and what else was considered

The hot loop is one operation repeated tens of millions of times: derive an
Ed25519 keypair, then match the target pattern against the public key's bytes.
Everything else in the wrapper is cheap in comparison, so the choice of crypto
implementation *is* the throughput ceiling. Candidates evaluated:

| Option | Verdict | Reason |
|---|---|---|
| **libsodium.js (WASM)** | **chosen** | The reference C implementation compiled to WebAssembly. Measured at **~13.5k keys/s/core** in this app's worker. WASM avoids the per-operation type checks and boxing that dominate pure-JS scalar arithmetic. |
| WebCrypto `Ed25519` | unusable | The API only returns a public key as a `CryptoKey`. A non-extractable key exposes no bytes at all, so there is nothing to pattern-match; making it extractable to read the bytes would leak exactly the value being mined for. A structural blocker, not a speed trade-off. |
| tweetnacl.js | rejected | Pure JS. Correct and small, but its scalar loop loses to the WASM path at this call rate. |
| noble-ed25519 | rejected | Pure JS and well maintained, but again slower than WASM on raw scalar-multiply throughput — the only metric that matters when it is called millions of times. |
| Hand-rolled JS bigint | rejected | This was the original approach and the baseline that WASM beats. Far slower, and a large correctness risk in hand-rolled curve arithmetic. |

Two caveats, stated plainly rather than buried:

- **The ~13.5k keys/s/core figure measures the chosen path only**, not a
  controlled head-to-head benchmark against every row above. The tweetnacl and
  noble-ed25519 rejections rest on them being pure-JS scalar loops against a
  WASM one, plus spot checks — not on a rigorous sweep on identical hardware.
- **There is no faster primitive to reach for.** WASM SIMD would not help: Ed25519
  scalar multiplication is inherently serial field arithmetic, and libsodium
  exposes no batched or vectorised `scalarmult` entry point to call. No such
  primitive was found in the available builds, so the loop stays where it is.

### Worker scaling: 2 → 8 threads

Calibration measures **one** worker on **one** core, but the search then runs
`navigator.hardwareConcurrency` workers concurrently. Multiplying the
single-worker rate by the worker count overstates the result, because the
workers do not each get a core to themselves. This was measured rather than
assumed:

- Reference host: **8 logical CPUs on 4 physical cores**.
- Pure-CPU keygen was run at 1–8 concurrent workers, measuring aggregate
  throughput.
- Aggregate throughput **saturated at ≈2.3x the single-worker rate at 8 threads**,
  not the 8x that linear scaling predicts.

Two effects explain the shortfall: SMT siblings sharing one physical core do not
get independent execution units (so 4→8 threads buys far less than 2x), and the
workers contend for memory bandwidth.

> **Worth re-measuring before trusting the 2.3x.** Two probes disagree with it,
> and the one that uses the real primitive is the one to believe.
>
> `node tools/bench_keygen_scaling.mjs` runs the shipped `libsodium.wasm`'s
> actual `crypto_sign_seed_keypair` across N OS threads. On the reference-class
> host (verified: i3-10105, 4 physical / 8 logical — the same topology as the
> recorded reference host):
>
> | Threads | Aggregate keys/s | vs 1 thread |
> |---|---|---|
> | 1 | 23,934 | 1.00x |
> | 2 | 47,157 | 1.97x |
> | 4 | 81,885 | 3.42x |
> | 8 | 97,555 | **4.08x** |
>
> So real keygen scales to roughly **4x**, not 2.3x. SMT siblings still add ~19%
> over four threads, which is why saturating every *logical* core is correct and
> there is no throughput left to win on the worker-count axis.
>
> (`tools/bench_worker_scaling.mjs`, which uses a synthetic ALU+table workload,
> reports ~6.4x. That probe is misleading on its own — its workload is
> ILP-friendly with a small working set, so it does not contend the way real
> keygen does.)
>
> **The constant has deliberately not been changed.** A Node thread pool has no
> event loop, no UI thread and no `postMessage` per progress report, so raising
> it on this evidence would make every ETA optimistic on the strength of a proxy.
> Re-measure with `tools/bench_real_browser.mjs` in a real browser, then update the
> constant, the page's `MEASUREMENT BASIS` comment and the table below together.
>
> One thing to check when doing that: the power-law fit is anchored only at 8
> threads, and the measured real-crypto curve is much flatter at the low end
> than a single-anchor fit predicts — against these numbers it would say ~1.6x
> at 2 threads (measured 1.97x) and ~2.5x at 4 (measured 3.42x). Recording the
> intermediate points may matter more than the 8-thread anchor.
>
> The number is user-visible on every estimate: raising it shortens every ETA,
> lowering it lengthens them.

These are the values `workerScale()` returns today:

| Workers | Speedup | Basis |
|---|---|---|
| 1 | 1.00x | baseline |
| 2 | 1.97x | **measured** |
| 3 | 2.72x | interpolated |
| 4 | 3.42x | **measured** |
| 6 | 3.79x | interpolated |
| **8** | **4.08x** | **measured** |
| 16, 32 | 4.08x | clamped to the ceiling |

Measured with `tools/bench_keygen_scaling.mjs`, which runs the shipped
`libsodium.wasm`'s real `crypto_sign_seed_keypair` across N OS threads:

    1 thread     23,934 keys/s   1.00x
    2 threads    47,157 keys/s   1.97x
    4 threads    81,885 keys/s   3.42x
    8 threads    97,555 keys/s   4.08x   (19% better than 4)

**This is a table, not a power law, and that matters.** The model used to be
`n ** (log(2.3) / log(8))` — one anchor, everything else a fit. Measuring the
real primitive showed scaling is near-linear to 2 threads and then flattens
sharply, which a single-anchor law cannot represent: it predicted 1.32x at 2
threads against 1.97x measured, and **1.74x at 4 against 3.42x measured**, so
every 4-core laptop was told it would run at half its real speed. The measured
points are now recorded directly and interpolated log-linearly between them,
which reproduces the curve's shape.

Above 8 threads the curve **clamps** rather than extrapolating: extra threads
cannot beat what was observed on 4 physical cores, and `detectOptimalWorkers`
caps at 32, so a 32-thread machine would otherwise be told it is 7x faster than
anything ever measured.

**Honest caveat:** these are Node OS threads, not browser Web Workers — no event
loop, no UI thread, no `postMessage` per report. The browser may well be slower;
an earlier browser-only measurement put 8 threads at 2.3x, below every number
here. That is why the browser measures its own curve instead of trusting the
table — see below.

### The grey estimate is a static pre-flight projection

The grey line above the panel is computed **once**, before any work starts, and
does not change for the duration of a search. It shows the expected attempts,
the estimated time, the worker count and the projected keys/s, and it is labelled
`estimated` or `calibrated` so it is clear which kind of number it is.

It used to be rewritten on every progress report so it could flip from
`estimated` to `measured` once the workers had reported twice. That put a moving
number in grey directly above the green live-logs panel, which already showed
the live rate, progress and a live ETA computed from each worker's own reported
rate — two figures changing under the user at once, with the projection
masquerading as part of the live read-out. The live panel is for live figures;
the grey line is what you should be deciding on before you press Start.

What makes a fixed pre-flight figure defensible is that it is no longer imported
from other hardware: `ratePerWorker()` is measured on this CPU at load, and
`workerScale()` comes from the per-machine calibration described above. So the
grey line is a projection from two local measurements, not a table someone else
produced.

The provenance of the factor (which host it was measured on, and the fit) is
documented here and in `WORKER_SCALE_MEASURED` in `index.html` rather than
printed on every page load — the inline clause was long enough to wrap the
estimate line on a narrow screen.

**To re-measure on different hardware**, replace `WORKER_SCALE_POINTS` in the
browser app with fresh `tools/bench_keygen_scaling.mjs` output, update this
table, and nothing else needs to change — the interpolation and clamping read
straight from the table.

> The multiplier is **hardware-specific** — 2.3x encodes *this* host's 2:1 SMT
> ratio. A machine with 8 physical cores would scale very differently and must be
> re-measured rather than reusing 2.3x.

## Privacy and third-party requests

The miner runs entirely in the browser. Keys are generated, compared and stored
locally; nothing about a search is transmitted.

The page makes **no script requests to third parties**. The one external request
is a visitor-counter badge — a plain `<img>` from `visitorbadge.io`, served as a
static SVG, with `referrerpolicy="no-referrer"` so the referring URL is not sent.
It is the same counter used on the author's other sites. No cookies, no
fingerprinting, no analytics, and it cannot execute. If it fails to load the page
is otherwise unaffected, which is why the browser smoke test asserts the badge's
presence and URL but deliberately does **not** assert that the image loads: a
flaky assertion about a third party's uptime should not be able to fail the build.

The service worker caches only same-origin files. The counter is never cached.

## Quick Start

### One command, straight from the browser

Nothing to download, clone or install first. This fetches the tool, runs it, and
throws the environment away afterwards:

```bash
uv run --from git+https://github.com/neohiro/meshcore-meshtastic-vanity-key \
  meshcore-vanity abcd --encoding hex
```

`uv` is a single self-contained binary ([install](https://docs.astral.sh/uv/)).
Substitute `pipx run --spec git+https://github.com/neohiro/meshcore-meshtastic-vanity-key
meshcore-vanity` if you prefer pipx; the arguments after the entry point are
identical.

```bash
# A different prefix AND a different suffix, in one search
uv run --from git+https://github.com/neohiro/meshcore-meshtastic-vanity-key \
  meshcore-vanity ab --suffix Yc

# A MeshCore bech32 address
uv run --from git+https://github.com/neohiro/meshcore-meshtastic-vanity-key \
  meshcore-vanity mc1q --encoding bech32
```

### Locally, from a clone

If you have the repository, `./run.sh` creates a local `.venv` on first use,
installs PyNaCl into it, and passes everything after the pattern straight
through:

```bash
./run.sh abcd          # Linux / macOS
run.bat abcd           # Windows
```

| | |
|---|---|
| Need to install anything? | No. PyNaCl is fetched into `.venv` on first run. |
| Uninstall | `rm -rf .venv` |
| Already have PyNaCl? | It is still used from the venv; set `MESH_VANITY_NO_VENV=1` to use the ambient interpreter instead. |
| See every flag | `./run.sh abcd --help` |

> If `run.sh` is not executable, call it through the interpreter:
> `python3 run.py abcd`.

### Calling the CLI directly

If you already have the dependencies:

```bash
pip install -r requirements.txt
python meshcore_vanity.py <prefix> [options]
```

> **Check you are running the right copy.** If a copy of `meshcore_vanity.py`
> is left in a *parent* directory, `python meshcore_vanity.py` will silently run
> that older copy — it produces valid-looking output but uses an older code
> path (for example a single worker instead of all cores), which looks like the
> tool "getting slower". Confirm what you are executing with:
>
> ```bash
> python meshcore_vanity.py --version
> ```
>
> This prints the version and the absolute path of the file that was actually
> loaded.

The encoded public key is printed to **stdout**, so you can pipe the result
directly:

```bash
./run.sh ab --encoding hex > mykey.txt
```

> **The private key is printed to stderr by default**, on three lines
> (`PRIVATE_KEY_BASE64`, `MESHCORE_PRIV_HEX`, `set prv.key`). Re-running a
> search to recover it costs minutes to days of CPU, which is why it is not
> behind a flag any more. If you are piping output somewhere a secret should
> not land — a CI log, a shared terminal, a dashboard — add
> `--no-output-private`.

### Budget estimator

Before every search, the tool prints the expected attempt count, a locally
measured keygen rate, and an ETA — and asks for confirmation on interactive
terminals:

```
Estimate: 65,536 expected attempts (~35,062 keys/s (single-worker measurement x 1.7 for 4 workers)) | ETA ~2s
Continue? [y/N]:
```

Piped/non-interactive runs skip the prompt automatically. Use `-f` / `--force`
to skip it explicitly in scripts:

```bash
python meshcore_vanity.py abcdef --encoding hex --workers 4 -f
```

## Usage Examples

### Basic prefix search (hex encoding)

```bash
python meshcore_vanity.py ab --encoding hex
```

Finds a key whose hex-encoded public key starts with `ab`.

### Bech32 encoding (MeshCore style)

```bash
python meshcore_vanity.py mc1neoh --encoding bech32
```

Finds a bech32-encoded key starting with `mc1neoh`.

### Separate prefix and suffix

```bash
python meshcore_vanity.py ab --suffix Yc                     # base64
python meshcore_vanity.py mc1q --encoding bech32 --suffix qs   # bech32
```

Finds a key that starts with `ab` **and** ends with `Yc`, checked in the same
search — as the browser does with its two input boxes.

### Suffix instead of prefix

```bash
python meshcore_vanity.py abc --encoding hex --suffix
```

Finds a key whose hex encoding ends with `abc`.

### Both ends, one pattern

```bash
python meshcore_vanity.py 0101 --encoding hex --both
```

Finds a key that both starts and ends with `0101`.

### Deterministic search with a seed

```bash
python meshcore_vanity.py ab --encoding hex --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Using the same seed always produces the same result. Omit `--seed` for random keys.

### Parallel workers

```bash
python meshcore_vanity.py ab --encoding hex --workers 4
```

Uses 4 parallel processes to speed up the search.

### The private key is printed by default

Every successful search prints the private key to **stderr**, in three
copy-pasteable forms:

- Base64-encoded raw private key (`PRIVATE_KEY_BASE64=`)
- MeshCore expanded private key, hex uppercase (`MESHCORE_PRIV_HEX=`)
- A ready-to-use `set prv.key` command

This is the default because the alternative is bad: if the key is not printed,
the only way to recover it is to run the search again, which costs anywhere
from seconds to days of CPU. The key is on stderr rather than stdout so that
piping stdout somewhere does not silently write your private key into that
destination — only the public key goes to stdout.

To suppress it, pass `--no-output-private`:

```bash
python meshcore_vanity.py ab --encoding hex --no-output-private
```

Worth using when stderr goes somewhere a secret should not end up — CI logs, a
shared terminal, or a piped dashboard. Note that a shell history, a CI log, or
a scrollback buffer will all capture the default output, so treat any terminal
you search in as one that now holds a private key.

## Command-Line Options

| Option | Default | Description |
|---|---|---|
| `pattern` (positional) | — | The text to match. Matched against the **start** of the encoded key by default; `--suffix` and `--both` change where it is matched. |
| `--encoding` | `base64` | Key encoding: `hex`, `base64`, `base64url`, `base58`, `bech32` |
| `--hrp` | `mc` | Human-readable part for bech32 encoding |
| `--case-sensitive` | off | Force case-sensitive matching. Implied for `base64`/`base64url`/`base58`, whose alphabets are case-sensitive. |
| `--suffix [PATTERN]` | off | **With no value:** match the positional pattern against the **end** of the key instead of the start. **With a value:** require that value at the end *in addition to* the positional prefix — two independent patterns in one search. |
| `--both` | off | Require the positional pattern at **both** ends, using that same pattern for each. |
| `--max-attempts` | unlimited | Stop after N attempts. An exact bound: the budget is split across workers by largest remainder, so the attempts actually performed sum to exactly N — including when N is smaller than the worker count |
| `--progress-interval` | 100000 | Progress report frequency, in attempts |
| `--no-output-private` | off | Suppress the private key, which is printed to stderr by default |
| `--seed` | random | 64 hex chars (32 bytes) for deterministic search |
| `--workers` | all CPU cores (max 256) | Number of parallel processes (forced to 1 for searches expected to finish in under a second) |
| `-f`, `--force` | off | Skip the pre-search estimate confirmation |
| `--version` | | Print version and the loaded file path, then exit |

### Matching one end, or both

The pattern always comes from the positional argument. To constrain **both** ends
with *different* text, give the suffix to `--suffix`:

| Goal | Command | Matches |
|---|---|---|
| Start only (default) | `run.sh abcd` | keys **starting with** `abcd` |
| End only | `run.sh 7c --suffix` | keys **ending with** `7c` |
| Both ends, different text | `run.sh ab --suffix Yc` | keys **starting with** `ab` **and ending with** `Yc` |
| Both ends, same text | `run.sh abcd --both` | keys **starting and ending with** `abcd` |
| End only, no prefix | `run.sh --suffix Yc` | keys **ending with** `Yc` |

Those examples use the default `base64` encoding, whose final character is
constrained — see [Suffixes and base64 padding](#suffixes-and-base64-padding).
Suffix patterns there must end in one of `048AEIMQUYcgkosw`, so `cd` and `7f`
are rejected. With `--encoding hex` every digit is reachable and any suffix
works.

This mirrors the browser, which has always taken an independent prefix and
suffix box and checked both in the same pass.

Each constrained end multiplies the search space rather than adding to it, so
`--both abcd` (and `--suffix`-with-`ab`) costs roughly 65k² attempts. Keep the
patterns short unless you have hours. `--both` cannot be combined with a separate
suffix pattern or with a bare `--suffix`, since they contradict each other.

If the two patterns are long enough to overlap in the key, the search can never
succeed, so it is rejected up front rather than left spinning.

## Supported Encodings

| Encoding | Example Output | Notes |
|---|---|---|
| `hex` | `a1b2c3...` (64 chars) | Standard for MeshCore device import |
| `base64` | `q83v...` (44 chars) | Standard base64 with padding |
| `base64url` | `q83v...` (43 chars) | URL-safe base64, no padding |
| `base58` | `2gV...` (44 chars) | Bitcoin alphabet |
| `bech32` | `mc1q...` (61 chars) | BIP-0173, MeshCore default |

## How It Works

### Scalar-Walk Optimization

Candidates come from a 256-bit counter taken from the seed once and incremented
in place, rather than from a fresh random draw per attempt:

1. Derive an initial 256-bit counter from the seed via SHA-256 (once)
2. For each attempt, increment it and pass it as the seed to libsodium
3. A given `--seed` therefore reproduces a search exactly

**This is not a hashing optimisation, and the distinction matters.** libsodium
derives each candidate with SHA-512 over that counter inside
`crypto_sign_seed_keypair`, so the hash is paid per attempt either way —
measured at ~0.9 µs of a ~36.7 µs candidate. What the walk avoids is a CSPRNG
draw (a syscall) and, more importantly, it makes a run reproducible. Its real
contribution to throughput is small; the practical way to go faster is
`--workers`.

Walking the counter is also mathematically sound for mining. Consecutive scalars
give public keys related by a fixed curve point, which is public knowledge and
reveals nothing about the discrete log; every candidate still requires a full
scalar multiplication, and there is no exploitable structure in the sequence.

### Parallel Search

With `--workers N`, the tool spawns N processes, each searching a disjoint subset of the scalar space. The first match wins.

### Reserved Prefixes

Hex prefixes `00` and `ff` are reserved for MeshCore framework devices. They are
**mined with a warning, not rejected** — the browser and the CLI behave the same
way, because some people deliberately want one:

```
UserWarning: prefix '00' starts with a prefix reserved for MeshCore framework
devices (00 and FF are not available for consumer nodes). It will still be
mined, but the key may not work with standard MeshCore clients.
```

Set `MESHCORE_VANITY_STRICT_RESERVED=1` to turn the warning back into a hard
rejection if you would rather fail than hand someone a key their client refuses.

### Case sensitivity

`hex` and `bech32` are matched case-insensitively. `base64`, `base64url` and
`base58` are **case-sensitive alphabets and are always matched exactly** — a key
beginning `AB` is a different key from one beginning `ab`, and returning the
wrong case would mean the tool hands you a key that does not match the pattern
you asked for.

### Suffixes and base64 padding

A 32-byte key is 44 base64 characters, the last of which is the `=` pad. Suffix
matching compares against the end of the **key data**, not the padding, so
`--suffix Yc` matches keys whose last two *data* characters are `Yc`.

There is a second base64 quirk worth knowing, because it makes a suffix
*impossible* rather than merely rare. 256 bits do not divide evenly into 6-bit
base64 characters: the 43rd data character carries only 4 significant bits, so
its low two bits are always zero and only 16 of the 64 symbols can appear there.
A suffix whose last character is one of the other 48 can never match, so it is
rejected immediately instead of searching forever:

```console
$ meshcore-vanity ab --suffix b
Error: this suffix pattern can never match a base64 key: a 32-byte key's
base64 form is 43 data characters, and the last one carries only 4 significant
bits, so it can only be one of 048AEIMQUYcgkosw. 'b' is not among them
(the full pattern was 'b')
```

Only the final character is constrained — earlier characters of the pattern sit
at positions where all 64 symbols are reachable.

### Suffixes and the bech32 checksum

`bech32` has the same kind of constraint, in a different place. A 32-byte key is
61 characters: `hrp` + `1` + 52 data characters + a 6-character checksum. The 52
five-bit groups hold 260 bits for 256 bits of key, so 4 padding bits land in the
**last data character**, leaving it one significant bit — only `q` or `s` can
occur there.

That character sits 7 from the end, so a bech32 suffix only faces the constraint
at length 7 or more; shorter suffixes land in the checksum, which is uniform.

```console
$ meshcore-vanity mc1q --encoding bech32 --suffix ccccccc
Error: this suffix pattern can never match a bech32 key: a 32-byte key encodes to
52 data characters carrying 256 bits, so the last one holds only 4 significant
bits and can only be qs - but this pattern needs 'c' there (position 0 of 7,
7 characters from the end).
```

It also makes such a search **16x cheaper** than the character count suggests,
which the pre-flight estimate accounts for: a 7-character bech32 suffix costs
`2 × 32⁶`, not `32⁷`.

### Encodings that are deliberately not validated

`hex` and `base58` have no impossible-pattern rule, and none is invented for
them. base58's encoder prepends `1` for each leading zero byte, and its
leading-digit distribution does make some two- and three-character prefixes
**rare** — but an exhaustive check over all of them, by interval arithmetic
against the reachable value range, showed every one is still reachable. Only the
highest-probability ones were merely absent from a 300,000-key sample. Refusing
them would reject valid targets, which is the worse failure; a pattern that is
merely rare still gets found, and one that is genuinely impossible now ends in a
visible `exceeded max_attempts` rather than running forever.

## Limitations

- **Search time grows exponentially with prefix length.** A 2-char hex prefix takes ~1 second; a 6-char prefix may take hours. Use `--workers` to parallelize.
- **No GPU acceleration, and that is not an oversight.** This is CPU-only in both
  the CLI and the browser, and there is no GPU implementation of Ed25519
  keygen to integrate. The reason is the shape of the work, not maturity:

  - **It is serial.** One candidate is `SHA-512(seed)` → a clamped 255-bit
    scalar → one scalar multiplication `[a]B`. That multiplication is a chain
    of ~150 *dependent* field multiplications; each needs the previous one's
    result, so there is no instruction-level parallelism to fill.
  - **It is latency-bound, not throughput-bound.** Each step is a 128-bit
    product followed by a reduction mod 2²⁵⁵−19 (a long carry chain of shifts
    and adds), and the point additions consume a 32-entry precomputed table —
    so memory latency sits directly on the critical path.
  - **A GPU wins on work that is wide, independent and dense.** This is the
    opposite on all three counts.

  Batching many independent candidates *would* suit a GPU in principle, but at
  ~25k keys/s per CPU core it would take thousands of in-flight candidates,
  each with its own table, before utilisation approached full — more memory than
  a CPU keeps in L1, at which point you are bandwidth-bound. That is why no
  CUDA, WebGPU or WebGL implementation exists to port.

  **What actually helps** is more cores (`--workers`), more machines, and the
  browser app, which uses every logical core automatically.
- **Bech32 prefix must be compatible with HRP.** Every bech32 key starts with `<hrp>1`. A prefix like `ne` with `--hrp mc` will be rejected because keys always start with `mc1`.
- **The private key is printed to stderr by default.** Use
  `--no-output-private` to suppress it where output is captured somewhere a
  secret should not land (CI logs, a shared terminal, a piped dashboard).
- **Not a MeshCore node.** This tool only generates keys. You still need MeshCore firmware or software to use them.
- **Deterministic mode requires a seed.** Without `--seed`, each run produces different results.
- **Browser app is hex-only.** It has no bech32/base58/base64 output; use the CLI for those encodings.
- **Browser app must be served over HTTP(S).** Blob Web Workers are blocked on `file://` URLs.
- **Browser worker count is a heuristic.** It uses `navigator.hardwareConcurrency` with no reserve (capped at 32), which can over- or under-estimate on constrained or shared hardware. The UI stays responsive anyway because the hot loop yields to the event loop every 250 ms.
- **Browser key history is obfuscated, not encrypted.** The XOR key is derived from an IndexedDB secret plus the origin, so a copied `localStorage` blob cannot be decoded elsewhere. Script on the origin can read IndexedDB, so this is not XSS protection. Clearing site data deletes the secret and orphans the history. History is never written in plaintext: if no key can be derived, saving is refused instead.
- **Progress is not capped at 100%.** Expected attempts are the mean of a geometric distribution, so ~37% of searches legitimately run past it. The CLI and browser show the overshoot as `+105.00%` plus how far past the mean the search has run. Once past the mean there is no meaningful "time remaining", so the ETA is replaced by the overshoot instead of being dropped or shown negative.
- **The hot loop is already at the maths limit.** The cost of a candidate is the Ed25519 scalar multiplication, not our code. Measured per core: **Python/native libsodium ~25,000–32,000 keys/s**, **browser libsodium.wasm ~13,500 keys/s** (`python tools/bench_mining.py`, `bun tools/bench_real_browser.mjs`). Our wrapper adds per-candidate overhead measured at ~10M keys/s equivalent — roughly three orders of magnitude cheaper than the derivation it wraps — so optimising it further cannot help. OpenSSL (via `cryptography`) was measured as a separate backend and is ~20% *slower* than libsodium, so switching implementations is not a win either. The only throughput lever is core count.
- **Browser workers use every logical core**, capped at 32. This previously reserved one core for the UI, which cost 25% throughput on a 4-core machine for no benefit: the hot loop already yields to the event loop every 250 ms, far more often than the browser needs to repaint, so the UI stays responsive anyway. Measured with the real keygen primitive, SMT siblings still add ~19% over four threads (see "Worker scaling"), so saturating every logical core is the right call and there is no throughput left on that axis.

  **This is now measured rather than assumed.** `navigator.hardwareConcurrency`
  counts *logical* threads, and there is no browser API for physical cores — so a
  4-core/8-thread machine is indistinguishable from a real 8-core one without
  measuring. That matters here, because SMT siblings contend rather than
  complement: Ed25519 keygen is a chain of dependent 128-bit multiplications with
  long carry reductions, so the second thread on a physical core fights the first
  for the same ALU and carry resources. On such a machine one worker per logical
  thread is simply the wrong count, and it also starves the main thread.

  So the first search on a machine measures its own curve — a handful of
  candidates per worker per round, over a hard 1.5 s budget — and caches it
  against the machine fingerprint. Later sessions use the measurement for both
  the worker count and the estimate, instead of the imported table. A step that
  adds less than 10% is not worth taking: those threads cost main-thread time
  (every worker report is a message, a forced layout and a canvas repaint) and
  buy almost nothing.

  Every failure path falls back to the imported table, which is exactly what
  runs today, so this can never stop a search from starting; a failed attempt is
  remembered and not retried. A corrupt or stale cache is rejected rather than
  trusted. To discard a measurement, clear this site's storage.

  The imported `WORKER_SCALE_POINTS` table remains the fallback and is still
  used on any machine whose calibration has not completed.
- **The CLI raises its worker count to the CPU count for long searches**, capped at 64, and refuses more than 256. It stays at 1 when the search is expected to finish in under a second (`_PARALLEL_MIN_SECONDS = 1.0`), because creating a `spawn` pool costs ~0.3s and made short prefixes dramatically slower. Pass `--workers N` to override either way.
- **Browser prefix + suffix are limited to 64 hex digits combined.** A key is exactly 64 hex digits, so longer patterns would overlap and could never match; the app refuses to start such a search.

## Output

### stdout

The encoded public key (the match). Pipe this to a file or another tool.

### stderr

Progress messages, statistics, and the private key in multiple formats (stderr; suppress with `--no-output-private`).

Example:

```
Searching for hex public key starting with 'ab' (case-insensitive)...
  attempts=100,000 rate=45,000/s elapsed=2.2s progress=38.15% eta=4s
Found in 123,456 attempts (2.75s, 44,893 keys/s)
```

## Security Notes

- **Never share your private key.** The CLI prints it to **stderr by default**,
  and so does the browser app. If you are capturing stderr — a CI log, a shared
  terminal, a piped dashboard — pass `--no-output-private` to keep it out, or
  redirect stderr to a file you control:
  `./run.sh abcd 2> secret.log`.
- **Use a strong seed for deterministic mode.** A predictable seed means predictable keys.
- **Verify the generated key** before using it in production.
- **Clear the browser history when done.** `Clear All Keys` in the
  [browser app](https://neohiro.github.io/meshcore-meshtastic-vanity-key/) wipes
  `localStorage`, but exported JSON/CSV files still contain private keys.

## License

MIT

## Credits

- [MeshCore](https://meshcore.io/) — decentralized mesh networking
- [Ed25519](https://ed25519.cr.yp.to/) — fast, secure elliptic curve signatures
- [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) — bech32 address format
- [PyNaCl](https://pynacl.readthedocs.io/) — Python libsodium bindings (Ed25519)
