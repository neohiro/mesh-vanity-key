# meshcore-vanity-key

MeshCore-compatible Ed25519 vanity public-key generator.

Generates keys until the encoded public key starts with a target prefix.

## Usage

```bash
python meshcore_vanity.py <prefix> [--encoding hex|base64|base64url|base58|bech32] [--hrp mc] [--max-attempts N] [--workers N] [--output-private] [--seed HEX]
```

## Examples

```bash
# Find a hex key starting with "ab"
python meshcore_vanity.py ab --encoding hex

# Find a bech32 key starting with "mc1neoh"
python meshcore_vanity.py mc1neoh --encoding bech32

# Deterministic search with a seed
python meshcore_vanity.py ab --encoding hex --seed 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

## Optimizations

- Scalar-walk: increment private scalar directly instead of hashing per attempt
- Parallel workers with multiprocessing
- Early-exit for reserved prefixes (00, FF)
- Batch verification with early rejection

## Testing

```bash
python -m pytest test_meshcore_vanity.py -v
```
