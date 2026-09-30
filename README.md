# meshcore-vanity-key

A fast, MeshCore-compatible Ed25519 vanity public-key generator written in Python.

Inspired by and credited to [MeshCore](https://meshcore.co.uk/) — a decentralized mesh networking project. This tool generates Ed25519 keypairs whose encoded public keys match a user-defined pattern, suitable for use with MeshCore devices and related tooling.

---

## What It Does

Generates Ed25519 cryptographic keypairs until the encoded public key matches a target pattern (prefix, suffix, or both). The search is optimized with a scalar-walk algorithm that avoids repeated hashing, making it significantly faster than naive approaches.

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

Hex prefixes `00` and `FF` are reserved for MeshCore framework devices and are rejected by default.

## Limitations

- **Search time grows exponentially with prefix length.** A 2-char hex prefix takes ~1 second; a 6-char prefix may take hours. Use `--workers` to parallelize.
- **No GPU acceleration.** This is CPU-only. For very long prefixes, consider a GPU-based tool.
- **Bech32 prefix must be compatible with HRP.** Every bech32 key starts with `<hrp>1`. A prefix like `ne` with `--hrp mc` will be rejected because keys always start with `mc1`.
- **Private key is only shown with `--output-private`.** Without this flag, only the public key is printed. This is a safety measure.
- **Not a MeshCore node.** This tool only generates keys. You still need MeshCore firmware or software to use them.
- **Deterministic mode requires a seed.** Without `--seed`, each run produces different results.

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

## License

MIT

## Credits

- [MeshCore](https://meshcore.co.uk/) — decentralized mesh networking
- [Ed25519](https://ed25519.cr.yp.to/) — fast, secure elliptic curve signatures
- [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) — bech32 address format
- [PyNaCl](https://pynacl.readthedocs.io/) — Python libsodium bindings (Ed25519)
