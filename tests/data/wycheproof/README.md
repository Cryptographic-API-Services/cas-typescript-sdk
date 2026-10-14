# Wycheproof test vectors

The JSON files in this directory are vendored, unmodified, from the
[C2SP/wycheproof](https://github.com/C2SP/wycheproof) project
(`testvectors_v1/`), pinned at commit
[`d0db6205a1570feb1e5918a735f7e57f6ad7b3f6`](https://github.com/C2SP/wycheproof/tree/d0db6205a1570feb1e5918a735f7e57f6ad7b3f6/testvectors_v1).

Wycheproof is licensed under the Apache License 2.0; see
<https://github.com/C2SP/wycheproof/blob/main/LICENSE>.

| File | Exercised by |
| --- | --- |
| `aes_gcm_test.json` | `tests/wycheproof-aes-gcm.spec.ts` |
| `ed25519_test.json` | `tests/wycheproof-ed25519.spec.ts` |
| `x25519_test.json` | `tests/wycheproof-x25519.spec.ts` |
| `hmac_sha256_test.json` | `tests/wycheproof-hmac.spec.ts` |
| `hmac_sha512_test.json` | `tests/wycheproof-hmac.spec.ts` |
| `chacha20_poly1305_test.json` | `tests/wycheproof-chacha20-poly1305.spec.ts` |
| `aes_gcm_siv_test.json` | `tests/wycheproof-aes-gcm-siv.spec.ts` |
| `mlkem_1024_semi_expanded_decaps_test.json` | `tests/wycheproof-ml-kem.spec.ts` |
| `mldsa_65_sign_seed_test.json` | `tests/wycheproof-ml-dsa.spec.ts` |
| `mldsa_65_verify_test.json` | `tests/wycheproof-ml-dsa.spec.ts` |

Not covered, and why:

- **Ascon** — `cas-lib` implements NIST SP 800-232 Ascon-AEAD128 (`ascon-aead`
  0.5.x); Wycheproof currently only ships vectors for the pre-standard
  Ascon v1.2 family (`ascon128`, `ascon128a`, `ascon80pq`).
- **RSA signatures** — `cas-lib` signs with unprefixed PKCS#1 v1.5 over raw
  caller data (no DigestInfo), so the `rsa_signature_*` vectors cannot match.
- **AES-GCM / AES-GCM-SIV / ChaCha20-Poly1305 vectors with AAD, non-96-bit
  IVs, or AES-192 keys** — the SDK's API surface does not accept AAD, only
  takes 96-bit nonces, and does not expose AES-192.
- **ML-KEM seed-form vectors** (`mlkem_1024_test.json`, encaps/keygen files) —
  the SDK's decapsulation takes the expanded 3168-byte key, so only the
  semi-expanded decaps file applies; encapsulation is randomized and cannot be
  vector-tested.
- **PBKDF2** — the SDK's PBKDF2 uses HMAC-SHA3-256; Wycheproof only ships
  vectors for HMAC-SHA1/224/256/384/512.
- **ML-DSA vectors with a context string, hedged `rnd`, or precomputed μ**
  (and `mldsa_65_sign_noseed_test.json`, ML-DSA-44/87) — the SDK exposes only
  ML-DSA-65, signs deterministically with an empty context, and takes the
  32-byte seed as the signing key, so those cases are skipped (the skip counts
  are pinned in the spec).
- **SLH-DSA** — no Wycheproof vectors exist for it yet.
- **SHA-2 / SHA-3 / BLAKE2 hashing** — Wycheproof ships no plain digest
  vectors. SHA2-256/512 are covered by the NIST CAVS `.rsp` vectors in
  `tests/data/hashers/` (`tests/hasher.spec.ts`), and exercised through
  Wycheproof indirectly via `hmac_sha256_test.json` / `hmac_sha512_test.json`.
- **HPKE, password hashers, zstd** — no applicable Wycheproof vector sets.
