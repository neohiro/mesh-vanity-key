# meshcore-vanity-key

A fast, MeshCore-compatible Ed25519 vanity public-key generator. Ships in two forms:

- **`meshcore_vanity.py`** — a Python CLI with bech32/base58/base64 support and parallel multiprocessing.
- **`index.html`** — a zero-install browser app (PWA) that mines with Web Workers + libsodium WASM.

Inspired by and credited to [MeshCore](https://meshcore.io/) — a decentralized mesh networking project. This tool generates Ed25519 keypairs whose encoded public keys match a user-defined pattern, suitable for use with MeshCore devices and related tooling.

---

## What It Does

Generates Ed25519 cryptographic keypairs until the encoded public key matches a target pattern (prefix, suffix, or both). The search is optimized with a scalar-walk algorithm that avoids repeated hashing, making it significantly faster than naive approaches.

## Browser Version

`index.html` is a self-contained PWA — no build step, no dependencies beyond the
checked-in `libsodium.js`. It needs to be **served over HTTP(S)**, not opened as a
`file://` URL, because browsers refuse to create blob Web Workers from `file://`.

```bash
python -m http.server 8000
# then open http://localhost:8000/
```

Deploy it to any static host (GitHub Pages, Netlify, Cloudflare Pages). The service
worker precaches the app shell and serves stale-while-revalidate, so the app works
offline and picks up new deploys on the next load.

Browser-specific behaviour, for comparison with the CLI below:

| | Browser app | Python CLI |
|---|---|---|
| Pattern matching | hex only | hex, base64, base64url, base58, bech32 |
| Parallelism | auto-detected Web Workers (`hardwareConcurrency - 1`, capped at 16) | `--workers N` processes |
| Key history | kept in `localStorage`, exportable as JSON/CSV | none |
| Installable | yes (PWA with maskable icons) | n/a |
| Private key | shown per result, stored in history | only with `--output-private` |
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
running, cores, and ETA. A keys/s trace is drawn behind the ETA row.

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
| days | `8ch` | the `(~5 days)` estimate leads, so the hours never shift under it |
| hours | `20ch` | a multi-week run reaches 4-5 figures; reserve the widest case so the layout is identical from the first minute to the last |
| minutes | `2ch` | always two digits, zero-padded |
| seconds | `2ch` | as above |

The panel also sets `font-variant-numeric: tabular-nums`, which is what actually
stops a digit changing width — the reserved `min-width`s then hold the columns.
On screens under 420px the hour slot drops to `10ch`: still far more than a
three-week ETA needs (~500h), and still fixed rather than proportional, which is
the part that matters. Minutes and seconds are always padded to two digits, so
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
  candidates/s. The worker now yields on a 30 ms wall-clock budget instead.
- **Rebuilding hex strings per candidate.** Converting the candidate and public
  key to hex and running `startsWith`/`endsWith` costs more than the keygen. The
  walk state is now a 32-byte array incremented in place, and the pattern is
  pre-decoded to nibbles compared directly against the raw public-key bytes — no
  allocation and no string building in the hot loop.

Regression guards:

| Command | Checks |
|---|---|
| `node tools/verify_worker_math.mjs` | the byte-walk is arithmetically identical to the previous BigInt/hex implementation, including 2²⁵⁶ carry and wraparound |
| `node tools/bench_worker.mjs <worker.js>` | wrapper overhead with a stubbed (free) keygen; must stay far above the keygen cost. Runs three trials and reports the best, so JIT warm-up or a descheduled shared vCPU cannot fail an otherwise healthy run — a real regression drops every trial and still fails hard |
| `node tools/bench_worker_scaling.mjs` | aggregate throughput vs worker count, using a synthetic ALU+table workload. Reports higher scaling than is real - its workload is ILP-friendly - so prefer the keygen probe below |
| `node tools/bench_keygen_scaling.mjs` | aggregate keys/s vs thread count using the **real** `crypto_sign_seed_keypair` from the shipped wasm. The trustworthy of the two scaling probes — see "Worker scaling" |

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

| Workers | Aggregate speedup | Basis |
|---|---|---|
| 1 | 1.00x | baseline |
| 2 | 1.32x | fitted |
| 3 | 1.55x | fitted |
| 4 | 1.74x | fitted |
| 6 | 2.05x | fitted |
| **8** | **2.30x** | **measured** |

Only the 8-thread end point was measured directly; the intermediate points come
from a power-law fit anchored to that measurement:

    scale(n) = n ** (log(2.3) / log(8))     # exponent ~= 0.4005

The curve is concave and capped at the measured ceiling, so it cannot predict
more speedup than was actually observed. The browser estimate folds this factor
in and prints the multiplier inline instead of hedging:

    workers share cores, improvement is only ~2.3x at 8 threads

The provenance of the factor (which host it was measured on, and the fit) is
documented here and in `WORKER_SCALE_MEASURED` in `index.html` rather than
printed on every page load — the inline clause was long enough to wrap the
estimate line on a narrow screen.

**To re-measure on different hardware**, update `WORKER_SCALE_MEASURED` and
`WORKER_SCALE_EXPONENT` in `index.html` together; nothing else needs to change.
`tools/bench_real_browser.mjs` measures real-browser keygen throughput.

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

### Prerequisites

- Python 3.10+
- `PyNaCl` package

```bash
pip install -r requirements.txt
```

### Single-Command Usage

Run these **from the repository root** (the directory containing
`meshcore_vanity.py`):

```bash
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

The encoded public key is printed to **stdout**. Progress and statistics go to **stderr**, so you can pipe the result directly:

```bash
python meshcore_vanity.py ab --encoding hex > mykey.txt
```

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

### Suffix matching

```bash
python meshcore_vanity.py abc --encoding hex --suffix
```

Finds a key whose hex encoding ends with `abc`.

### Both prefix and suffix

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

### Output private key (use with caution)

```bash
python meshcore_vanity.py ab --encoding hex --output-private
```

Prints the private key in multiple formats to stderr:
- Base64-encoded raw private key
- MeshCore expanded private key (hex, uppercase)
- Ready-to-use `set prv.key` command

## Command-Line Options

| Option | Default | Description |
|---|---|---|
| `prefix` (positional) | — | Target pattern to match |
| `--encoding` | `base64` | Key encoding: `hex`, `base64`, `base64url`, `base58`, `bech32` |
| `--hrp` | `mc` | Human-readable part for bech32 encoding |
| `--case-sensitive` | off | Match prefix case-sensitively |
| `--suffix` | off | Match suffix instead of prefix |
| `--both` | off | Match both prefix and suffix |
| `--max-attempts` | unlimited | Stop after N attempts |
| `--progress-interval` | 100000 | Progress report frequency |
| `--output-private` | off | Also output private key to stderr |
| `--seed` | random | 64 hex chars (32 bytes) for deterministic search |
| `--workers` | all CPU cores (max 256) | Number of parallel processes (forced to 1 for searches expected to finish in under a second) |
| `-f`, `--force` | off | Skip the pre-search estimate confirmation |
| `--version` | | Print version and the loaded file path, then exit |

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

Instead of hashing a seed + counter for every attempt (expensive), the tool:

1. Derives an initial 256-bit scalar from the seed via SHA-256 (once)
2. For each attempt, increments the scalar by 1 and uses it directly as the Ed25519 private key seed
3. This avoids the SHA-256 per attempt, yielding significant speedup

### Parallel Search

With `--workers N`, the tool spawns N processes, each searching a disjoint subset of the scalar space. The first match wins.

### Reserved Prefixes

Hex prefixes `00` and `ff` are reserved for MeshCore framework devices and are rejected by default.

## Limitations

- **Search time grows exponentially with prefix length.** A 2-char hex prefix takes ~1 second; a 6-char prefix may take hours. Use `--workers` to parallelize.
- **No GPU acceleration.** This is CPU-only. For very long prefixes, consider a GPU-based tool.
- **Bech32 prefix must be compatible with HRP.** Every bech32 key starts with `<hrp>1`. A prefix like `ne` with `--hrp mc` will be rejected because keys always start with `mc1`.
- **Private key is only shown with `--output-private`.** Without this flag, only the public key is printed. This is a safety measure.
- **Not a MeshCore node.** This tool only generates keys. You still need MeshCore firmware or software to use them.
- **Deterministic mode requires a seed.** Without `--seed`, each run produces different results.
- **Browser app is hex-only.** It has no bech32/base58/base64 output; use the CLI for those encodings.
- **Browser app must be served over HTTP(S).** Blob Web Workers are blocked on `file://` URLs.
- **Browser worker count is a heuristic.** It uses `navigator.hardwareConcurrency - 1` (capped at 16), which can over- or under-estimate on constrained or shared hardware.
- **Browser key history is obfuscated, not encrypted.** The XOR key is derived from an IndexedDB secret plus the origin, so a copied `localStorage` blob cannot be decoded elsewhere. Script on the origin can read IndexedDB, so this is not XSS protection. Clearing site data deletes the secret and orphans the history. History is never written in plaintext: if no key can be derived, saving is refused instead.
- **Progress is not capped at 100%.** Expected attempts are the mean of a geometric distribution, so ~37% of searches legitimately run past it. The CLI and browser show the overshoot as `+105.00%` plus how far past the mean the search has run. Once past the mean there is no meaningful "time remaining", so the ETA is replaced by the overshoot instead of being dropped or shown negative.
- **The hot loop is already at the maths limit.** The cost of a candidate is the Ed25519 scalar multiplication, not our code. Measured per core: **Python/native libsodium ~25,000–32,000 keys/s**, **browser libsodium.wasm ~13,500 keys/s** (`python tools/bench_mining.py`, `bun tools/bench_real_browser.mjs`). Our wrapper adds per-candidate overhead measured at ~10M keys/s equivalent — roughly three orders of magnitude cheaper than the derivation it wraps — so optimising it further cannot help. OpenSSL (via `cryptography`) was measured as a separate backend and is ~20% *slower* than libsodium, so switching implementations is not a win either. The only throughput lever is core count.
- **Browser workers default to `hardwareConcurrency - 1`** (capped at 16), leaving one core for the UI. The hot loop yields every 30 ms, so this may be more conservative than necessary, but it has never been measured in a real browser.
- **The CLI uses every core by default.** `--workers` defaults to all CPUs, but stays serial when the search is expected to finish in under a second, because creating a `spawn` pool costs a few tenths of a second and made short prefixes dramatically slower. Pass `--workers N` to override.
- **Browser prefix + suffix are limited to 64 hex digits combined.** A key is exactly 64 hex digits, so longer patterns would overlap and could never match; the app refuses to start such a search.

## Output

### stdout

The encoded public key (the match). Pipe this to a file or another tool.

### stderr

Progress messages, statistics, and (with `--output-private`) the private key in multiple formats.

Example:

```
Searching for hex public key starting with 'ab' (case-insensitive)...
  attempts=100,000 rate=45,000/s elapsed=2.2s progress=38.15% eta=4s
Found in 123,456 attempts (2.75s, 44,893 keys/s)
```

## Security Notes

- **Never share your private key.** The `--output-private` flag prints it to stderr. Redirect stderr separately if you need to capture only the public key.
- **Use a strong seed for deterministic mode.** A predictable seed means predictable keys.
- **Verify the generated key** before using it in production.
- **Clear the browser history when done.** `Clear All Keys` in the browser app wipes `localStorage`, but exported JSON/CSV files still contain private keys.

## License

MIT

## Credits

- [MeshCore](https://meshcore.io/) — decentralized mesh networking
- [Ed25519](https://ed25519.cr.yp.to/) — fast, secure elliptic curve signatures
- [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) — bech32 address format
- [PyNaCl](https://pynacl.readthedocs.io/) — Python libsodium bindings (Ed25519)
