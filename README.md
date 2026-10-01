# meshcore-vanity-key

A fast, MeshCore-compatible Ed25519 vanity public-key generator. Ships in two forms:

- **`meshcore_vanity.py`** — a Python CLI with bech32/base58/base64 support and parallel multiprocessing.
- **`index.html`** — a zero-install browser app (PWA) that mines with Web Workers + libsodium WASM.

Inspired by and credited to [MeshCore](https://meshcore.co.uk/) — a decentralized mesh networking project. This tool generates Ed25519 keypairs whose encoded public keys match a user-defined pattern, suitable for use with MeshCore devices and related tooling.

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

> **Security:** the browser app stores found keys in `localStorage` in plaintext.
> That is fine for a throwaway vanity key, but treat the history as a secret store
> — it persists until you clear it.

Reserved hex prefixes `00` and `ff` are rejected in both implementations.

### Maintaining the PWA assets

- `tools/make_icons.py` regenerates `icon-192.png`, `icon-512.png` and
  `icon-maskable-512.png` from code. Run it after changing the icon design:
  `python tools/make_icons.py`
- When you add or remove a file from `sw.js`'s `urlsToCache`, bump `CACHE_VERSION`
  in the same commit so returning visitors get the new app shell.
- `node tools/test_page_js.mjs <main.js> <worker.js>` executes the page and worker
  JS against a mock DOM; CI runs it after `tools/check_inline_js.py` extracts them.

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
| `node tools/bench_worker.mjs <worker.js>` | wrapper overhead with a stubbed (free) keygen; must stay far above the keygen cost |

> **Careful:** never write `if (++bytes[i] !== 0)`. Incrementing a `Uint8Array`
> element returns the *unclamped* value (`256`, not `0`), so the carry test never
> fires and the counter silently stops at a byte boundary. Mask explicitly:
> `bytes[i] = (bytes[i] + 1) & 0xff;` then test `bytes[i] !== 0`.

## Quick Start

### Prerequisites

- Python 3.10+
- `PyNaCl` package

```bash
pip install -r requirements.txt
```

### Single-Command Usage

```bash
python meshcore_vanity.py <prefix> [options]
```

The encoded public key is printed to **stdout**. Progress and statistics go to **stderr**, so you can pipe the result directly:

```bash
python meshcore_vanity.py ab --encoding hex > mykey.txt
```

### Budget estimator

Before every search, the tool prints the expected attempt count, a locally
measured keygen rate, and an ETA — and asks for confirmation on interactive
terminals:

```
Estimate: 65,536 expected attempts (~38,400 keys/s (single-worker measurement x 2)) | ETA ~2s
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
| `--workers` | 1 | Number of parallel processes |
| `-f`, `--force` | off | Skip the pre-search estimate confirmation |

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
- **Browser key history is plaintext.** `localStorage` is readable by any script on the origin and is not encrypted.

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

- [MeshCore](https://meshcore.co.uk/) — decentralized mesh networking
- [Ed25519](https://ed25519.cr.yp.to/) — fast, secure elliptic curve signatures
- [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) — bech32 address format
- [PyNaCl](https://pynacl.readthedocs.io/) — Python libsodium bindings (Ed25519)
