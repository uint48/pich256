# pich256 🔩

A symmetric-key **stream cipher in pure Rust** — zero dependencies, self-contained
crypto primitives, and a hand-rolled big-integer layer. Derive a key from a
passphrase, and encrypt or decrypt a byte stream by XORing it with a
keystream produced by an evolving 128-bit state.

> 🚧 **Hardware acceleration is under active research and development.** The
> intrinsics-backed fast paths (with a portable software fallback) are not
> shipped yet — see the [Roadmap](#roadmap--todo).

> ⚠️ **Educational / experimental.** pich256 is a learning project, not a
> vetted cryptographic library. It has had no third-party review, provides no
> authentication (MAC), and no per-message nonce. **Do not use it to protect
> real secrets.** For production use reach for an audited AEAD such as
> `chacha20poly1305` or `aes-gcm`.

## Features

- **Pure Rust, zero dependencies** — SHA-256, HMAC-SHA-256, the key schedule,
  and the 128/192/256-bit integer arithmetic are all implemented in-tree.
- **Passphrase-based keying** — any string is stretched to a 256-bit key via an
  HKDF-style (HMAC-SHA-256 extract-then-expand) derivation.
- **SPN-flavored round function** — rotate → Rijndael (AES) S-box substitution →
  round-key XOR, over a 16-entry Fibonacci subkey ring.
- **Data-dependent keystream tap** — each output byte is read from a position
  chosen by the state itself.
- **Symmetric API** — `encrypt` and `decrypt` are the same XOR operation.

## How it works (at a glance)

1. **Key derivation** — `PRK = HMAC-SHA256(0³², passphrase)`, then
   `OKM = HMAC-SHA256(PRK, 0x01)` gives a 256-bit key.
2. **Split** — the high 128 bits seed the initial state `W₀`; the low 128 bits
   seed the 16-key Fibonacci subkey schedule.
3. **Warm-up** — the state is advanced 62 rounds so the output is decorrelated
   from the raw key material.
4. **Keystream** — each byte costs 2 rounds; the byte is then read at index
   `w[0] & 0x0F`.
5. **Cipher** — `ciphertext = plaintext ⊕ keystream`.

For the full specification, math, and diagrams, see
[PICH256_DESIGN_DOCUMENT.md](PICH256_DESIGN_DOCUMENT.md).

## API

| Method | Signature | Description |
| :--- | :--- | :--- |
| `Pich256::new` | `fn new(base_key: &str) -> Pich256` | Derive the key, build the subkey ring, and run 62 warm-up rounds. |
| `Pich256::encrypt` | `fn encrypt(&mut self, msg: &[u8]) -> Vec<u8>` | XOR each plaintext byte with the next keystream byte. |
| `Pich256::decrypt` | `fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8>` | Identical operation; recovers plaintext under the same key. |

## Examples

The repo ships runnable examples in [`examples/`](examples):

```bash
cargo run --example basic_usage
```

```bash
cargo run --example cli_encrypt -- "my passphrase" "attack at dawn"
```

```bash
cargo run --example key_sensitivity
```

`key_sensitivity` demonstrates the avalanche effect: two keys differing by a
single character produce ciphertexts that differ in nearly every bit.

## Testing

The crate has an extensive in-tree test suite covering the SHA-256/HMAC
primitives (FIPS 180-4 / RFC 4231 vectors), the big-integer arithmetic, the
S-box properties, the key schedule, and encrypt/decrypt round trips:

```bash
cargo test
```

## Project layout

```
src/
├── lib.rs           crate root / module wiring
├── pich256.rs       Pich256 + internal State (round function, keystream)
├── kdf.rs           HKDF-style 256-bit key derivation
├── key_gen.rs       Fibonacci subkey schedule (generator g)
├── round_key.rs     Roundkey struct
├── rc.rs            round constants + expansion
├── sbox.rs          Rijndael S-box and the xbox/sboxes/cbox pipeline
├── sha256.rs        SHA-256 + HMAC-SHA-256
└── bigint/          I128 / I192 / I256 arithmetic types
```

## Roadmap / TODO

- [ ] **Hardware acceleration with software fallback** — detect CPU features at
  build/runtime and dispatch to intrinsics-backed implementations (e.g. AES-NI
  for the S-box, SHA extensions for the KDF, SIMD for the state), falling back
  to the portable pure-Rust path on targets/CPUs that lack them.
- [ ] **Cryptanalysis & security testing** — statistical randomness suites
  (Dieharder / NIST STS / PractRand) on the keystream, avalanche and bit-bias
  measurements, and analysis of linear/differential resistance.
- [ ] **Improve the S-box and internal structure**
- [ ] **Benchmarks** — add Criterion benchmarks for throughput and key setup,
  and track performance across the portable vs. accelerated paths.
- [ ] **Publish to [crates.io](https://crates.io)** — add crate metadata
  (description, keywords, categories, repository, docs), documentation, and cut
  a release.

## License

Licensed under the [MIT License](LICENSE).
