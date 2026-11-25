# Migrating from 1.x to 2.0

cas-typescript-sdk 2.0 moves the underlying [cas-lib](https://github.com/Cryptographic-API-Services/cas-lib) from 0.2.92 to [0.7.0](https://github.com/Cryptographic-API-Services/cas-lib/releases/tag/v0.7.0) and fixes the findings of the November 2026 security review. Most of the breaking changes turn an insecure input that 1.x accepted silently into an error. A few change outputs: RSA signatures and X25519-derived keys made by 1.x are not compatible with 2.0.

The full list of changes is in the [Changelog](../CHANGELOG.md). Usage for every method is in the [Examples](./EXAMPLES.md).

The snippets below use the same helpers as the examples:

```typescript
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const toBytes = (text: string): Array<number> => Array.from(encoder.encode(text));
const toText = (bytes: Array<number>): string => decoder.decode(new Uint8Array(bytes));
```

## Checklist

| Area | What changes | What you need to do |
| --- | --- | --- |
| [RSA signatures](#rsa-signatures) | `sign` / `verify` are standard RS256 over the message. Key sizes are 2048, 3072 or 4096. | Re-sign anything signed by 1.x and replace 1024-bit keys. Prefer `signPss` / `verifyPss` for new designs. |
| [X25519 key derivation](#x25519-key-derivation) | The AES key helpers take both public keys and return different keys. Low-order public keys throw. | Pass both public keys and upgrade both peers together. |
| [PBKDF2](#pbkdf2) | At least 600,000 iterations and a 16-byte salt. | Re-derive stored keys on the user's next login. |
| [Password hashers](#password-hashers) | bcrypt rejects passwords over 72 bytes. Argon2, scrypt and bcrypt costs are bounded. | Keep custom parameters in range. Existing hashes still verify. |
| [Argon2 AES keys](#argon2-aes-key-derivation) | `deriveAes128Key` / `deriveAes256Key` are deprecated. | Use `generateSalt` with `deriveAes*KeyWithSalt`. |
| [zstd](#zstd-decompression) | `decompress` stops at 64 MiB by default. Legacy frames are rejected. | Pass `maxOutputSize` for larger trusted input. |
| [Ed25519](#ed25519) | `verifyWithKeyPairBytes` is strict, like `verifyBytes`. | Nothing, unless you relied on accepting malleable signatures. |
| [ML-KEM](#ml-kem) | `decapsulate` rejects a decapsulation key that fails the FIPS 203 hash check. | Nothing for keys from `generateKeyPair`. |
| [HPKE](#hpke) | Optional `aad`. `info` is limited to 65,530 bytes. | Use a fixed, application-specific `info`. |
| [Errors](#errors) | Native errors carry a stable `code`. | Branch on `CasErrorCode` with `isCasError` instead of message text. |
| [Native bindings](#raw-native-bindings) | Some generated `index.js` functions changed signature. | Only relevant if you load the generated binding directly. |

## RSA signatures

`RSAWrapper.sign` / `verify` now sign the **message** with RSASSA-PKCS1-v1_5 and SHA-256, which is standard `RS256` (JWS, OpenSSL, WebCrypto, Node's `crypto.sign("sha256", ...)`). 1.x signed the bytes you passed as they were, without the DigestInfo prefix, so:

- signatures made by 1.x don't verify in 2.0 (`verify` returns `false`), and 2.0 signatures don't verify in 1.x;
- pass the message itself, of any length, not a digest of it;
- `getKeyPair` accepts 2048, 3072 and 4096 (1.x accepted 1024, 2048 and 4096). 1024-bit keys throw, including keys you generated with 1.x;
- `verify` accepts public keys up to 8192 bits, and private keys whose two primes differ greatly in size are rejected.

For new designs, prefer [RSA-PSS](#rsa-pss) (`signPss` / `verifyPss`). Keep `sign` / `verify` for systems that require `RS256`.

1.x:

```typescript
const rsa = new RSAWrapper();
const keys = rsa.getKeyPair(1024); // 1024, 2048 or 4096
const message = toBytes("This is my message to sign");
const signature = rsa.sign(keys.privateKey, message); // signed the raw bytes, no DigestInfo
const isValid = rsa.verify(keys.publicKey, message, signature);
```

2.0:

```typescript
const rsa = new RSAWrapper();
const keys = rsa.getKeyPair(3072); // 2048, 3072 or 4096
const message = toBytes("This is my message to sign");
const signature = rsa.sign(keys.privateKey, message); // RS256 over the message
const isValid: boolean = rsa.verify(keys.publicKey, message, signature);

// Recommended for new designs: RSA-PSS (PS256)
const pssSignature = rsa.signPss(keys.privateKey, message);
const pssIsValid: boolean = rsa.verifyPss(keys.publicKey, message, pssSignature);
```

Re-sign stored documents and tokens with 2.0. If you have to accept 1.x signatures while you do that, Node's `crypto` can check them: a 1.x signature is PKCS#1 v1.5 padding around exactly the bytes that were passed to `sign`.

```typescript
import { constants, publicDecrypt, timingSafeEqual } from "crypto";

// Only for the transition: accepts signatures made by RSAWrapper.sign in 1.x
function verify1xSignature(publicKey: string, signedBytes: Array<number>, signature: Array<number>): boolean {
  try {
    const recovered = publicDecrypt({ key: publicKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(signature));
    const expected = Buffer.from(signedBytes);
    return recovered.length === expected.length && timingSafeEqual(recovered, expected);
  } catch {
    return false;
  }
}
```

## X25519 key derivation

The helpers that turn an X25519 shared secret into an AES key now take **both public keys** as well as the shared secret, and bind the key to the cipher and to both public keys:

- `AESWrapper.aes128KeyNonceX25519DiffieHellman` / `aes256KeyNonceX25519DiffieHellman`
- `AESGCMSIVWrapper.aes128KeyFromX25519SharedSecret` / `aes256KeyFromX25519SharedSecret`

The public keys can be passed in either order, so both peers get the same key. The derived keys are **different from 1.x**, so both peers must upgrade together: a 1.x peer and a 2.0 peer derive different keys from the same handshake, and decryption fails.

`X25519Wrapper.generateSharedSecret` now throws if the peer's public key is a low-order point, which would force an all-zero shared secret that an attacker knows. It throws a `CasError` with `CasErrorCode.InvalidKey`; treat that as a failed handshake.

1.x:

```typescript
const aliceShared = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);
const aliceKey = aes.aes256KeyNonceX25519DiffieHellman(aliceShared);
const sivKey = siv.aes256KeyFromX25519SharedSecret(aliceShared);
```

2.0:

```typescript
const x25519 = new X25519Wrapper();
const aes = new AESWrapper();
const siv = new AESGCMSIVWrapper();
const alice = x25519.generateSecretAndPublicKey();
const bob = x25519.generateSecretAndPublicKey();

// Throws if bob.publicKey is a low-order point
const aliceShared = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);
const bobShared = x25519.generateSharedSecret(bob.secretKey, alice.publicKey);

// Pass both public keys, in either order
const aliceKey = aes.aes256KeyNonceX25519DiffieHellman(aliceShared, alice.publicKey, bob.publicKey);
const bobKey = aes.aes256KeyNonceX25519DiffieHellman(bobShared, bob.publicKey, alice.publicKey); // same as aliceKey
const sivKey = siv.aes256KeyFromX25519SharedSecret(aliceShared, alice.publicKey, bob.publicKey);
```

## PBKDF2

`Pbkdf2Wrapper.derive` and `deriveWithSalt` throw unless the iteration count is an integer of at least **600,000**, and `deriveWithSalt` throws for a salt shorter than **16 bytes**. The algorithm is unchanged (PBKDF2-HMAC-SHA3-256 with a 32-byte output), so keys derived by 1.x with at least 600,000 iterations and a 16-byte salt re-derive identically.

1.x:

```typescript
const pbkdf2 = new Pbkdf2Wrapper();
const { derivedKey, salt } = pbkdf2.derive(password, 10_000);
const sameKey = pbkdf2.deriveWithSalt(password, 10_000, salt);
```

2.0:

```typescript
const pbkdf2 = new Pbkdf2Wrapper();
const password = toBytes("ThisOneBadPassword!@");
const { derivedKey, salt } = pbkdf2.derive(password, 600_000); // 32 byte key + random 16 byte salt
const sameKey = pbkdf2.deriveWithSalt(password, 600_000, salt);
```

### Migrating stored keys

A key derived with weaker parameters can't be re-derived with 2.0. Re-derive it on the user's next successful login, when you have the password: check it with the old parameters, then derive a new key with 2.0 and replace the stored salt, iteration count and key. If the key encrypts data rather than verifying the password, decrypt with the old key and re-encrypt with the new one in the same step.

Node's `crypto.pbkdf2Sync` with `"sha3-256"` reproduces the 1.x derivation, so you don't need 1.x installed alongside 2.0:

```typescript
import { pbkdf2Sync, timingSafeEqual } from "crypto";

interface StoredKey {
  salt: Array<number>;
  iterations: number;
  derivedKey: Array<number>;
}

const MIN_ITERATIONS = 600_000;
const pbkdf2 = new Pbkdf2Wrapper();

// Returns the record to store from now on, or null if the password is wrong
function verifyAndUpgrade(password: Array<number>, stored: StoredKey): StoredKey | null {
  const current = stored.iterations >= MIN_ITERATIONS && stored.salt.length >= 16;
  const candidate = current
    ? Buffer.from(pbkdf2.deriveWithSalt(password, stored.iterations, stored.salt))
    : pbkdf2Sync(Buffer.from(password), Buffer.from(stored.salt), stored.iterations, 32, "sha3-256");
  if (!timingSafeEqual(candidate, Buffer.from(stored.derivedKey))) {
    return null;
  }
  if (current) {
    return stored;
  }
  const { derivedKey, salt } = pbkdf2.derive(password, MIN_ITERATIONS);
  return { salt, iterations: MIN_ITERATIONS, derivedKey };
}
```

## Password hashers

### bcrypt: 72-byte passwords

`BCryptWrapper.hashPassword`, `hashPasswordWithParameters` and `verify` throw for a password longer than **72 bytes of UTF-8** (bytes, not characters: `"€"` is 3 bytes). 1.x silently ignored everything after the 72nd byte. Limit passwords to 72 bytes at sign-up, or use Argon2, which has no such limit. A 1.x hash of a longer password only covers its first 72 bytes and can't be checked with 2.0, because `verify` throws for the full password; send those accounts through a password reset.

### Cost bounds

`hashPasswordWithParameters` throws for a value outside these ranges, before calling into native code:

| Hasher | 1.x | 2.0 |
| --- | --- | --- |
| Argon2 | no bounds | memory 19–4096 **MiB**, iterations 1–10, parallelism 1–16 |
| scrypt | no bounds | log₂ N 10–20, `r` 1–32, `p` 1–16, and log₂ N < 16 · `r` (log₂ N 16 and above need `r` ≥ 2) |
| bcrypt | no bounds | cost 10–16 |

The Argon2 memory cost is in **mebibytes**: `64` means 64 MiB. 1.x treated it the same way, but cas-lib documented it as KiB and multiplied by 1024 without an overflow check, so a KiB value such as `65536` asked for 64 GiB, and larger values could wrap around to a much weaker hash. In 2.0 those values throw.

**Existing hashes still verify**, including hashes below today's minimums (for example bcrypt cost 4 or scrypt log₂ N 8). `verify` throws only for a stored hash whose costs are above the upper bounds, such as `$2b$31$...`, so a hostile hash can't tie up memory or CPU. If you made hashes above the bounds with 1.x, rehash them with in-range parameters on the next login while you are still on 1.x, or reset those passwords.

1.x:

```typescript
argon2.hashPasswordWithParameters(password, 65536, 50, 32); // accepted
scrypt.hashPasswordWithParameters(password, 22, 8, 1); // accepted
bcrypt.hashPasswordWithParameters(password, 4); // accepted
bcrypt.hashPassword("a".repeat(100)); // truncated to 72 bytes
```

2.0:

```typescript
const argon2 = new Argon2Wrapper();
const scrypt = new ScryptWrapper();
const bcrypt = new BCryptWrapper();
const argon2Hash = argon2.hashPasswordWithParameters("ThisOneBadPassword!@", 64, 3, 1); // 64 MiB, 3 iterations, parallelism 1
const scryptHash = scrypt.hashPasswordWithParameters("ScryptRocks", 17, 8, 1); // log2 N 17, r 8, p 1
const bcryptHash = bcrypt.hashPasswordWithParameters("ThisOneBadPassword!@", 12); // cost 10-16
const isMatch: boolean = bcrypt.verify(bcryptHash, "ThisOneBadPassword!@");
```

## Argon2 AES key derivation

`Argon2Wrapper.deriveAes128Key` / `deriveAes256Key` are deprecated. They draw a random salt and throw it away, so a key they return can never be derived again from the password. They still work, but use `generateSalt` and `deriveAes128KeyWithSalt` / `deriveAes256KeyWithSalt` instead: store the salt (it is not secret) next to what the key protects, and pass it back with the password to get the same key. They use Argon2id with fixed parameters (19 MiB, 2 iterations, parallelism 1), so a stored salt keeps working across updates. A salt shorter than 16 bytes throws a `CasError` with `CasErrorCode.InvalidParameters`.

Keys from the deprecated methods can't be re-derived by any version, so there is nothing to migrate: data encrypted under them is only readable while you still hold the key itself.

1.x:

```typescript
const key = argon2.deriveAes256Key(toBytes(password)); // one-time key, salt discarded
```

2.0:

```typescript
const argon2 = new Argon2Wrapper();
const salt = argon2.generateSalt(); // 16 random bytes; store it
const key = argon2.deriveAes256KeyWithSalt(toBytes("ThisOneBadPassword!@"), salt);
const sameKey = argon2.deriveAes256KeyWithSalt(toBytes("ThisOneBadPassword!@"), salt); // equal to key
const key128 = argon2.deriveAes128KeyWithSalt(toBytes("ThisOneBadPassword!@"), salt);
```

## zstd decompression

`ZTSDWrapper.decompress` stops at **64 MiB** of output by default and throws a `CasError` with `CasErrorCode.DecompressionLimitExceeded`, so a small crafted input (a decompression bomb) can't exhaust memory. 1.x had no limit. Pass `maxOutputSize` (bytes) to change the limit, and only raise it for trusted input.

zstd frames in the legacy format (zstd before v0.8) are rejected, and so are frames that declare a back-reference window over 128 MiB (for example from `zstd --long=31`). Decompress such data with a zstd build that still reads it, such as the `zstd` command-line tool or 1.x of this SDK, and compress it again with 2.0.

1.x:

```typescript
const data = zstd.decompress(compressed); // no output limit
```

2.0:

```typescript
const zstd = new ZTSDWrapper();
const compressed = zstd.compress(toBytes("This is my data to compress"), 3);
const data = zstd.decompress(compressed); // at most 64 MiB
const large = zstd.decompress(compressed, 256 * 1024 * 1024); // trusted input up to 256 MiB

try {
  zstd.decompress(compressed, 16);
} catch (err) {
  if (isCasError(err, CasErrorCode.DecompressionLimitExceeded)) {
    // the output would exceed maxOutputSize
  }
}
```

## Ed25519

`Ed25519Wrapper.verifyWithKeyPairBytes` now verifies strictly, like `verifyBytes` already did, so both reject malleable signatures (for example a non-canonical `S`) that `verifyWithKeyPairBytes` used to accept. Signatures made by `signBytes` are not affected, and no code change is needed.

## ML-KEM

`MlKem1024Wrapper.decapsulate` throws for a decapsulation key whose embedded hash doesn't match (the FIPS 203 §7.3 check) instead of decapsulating anyway. Keys from `generateKeyPair` always pass. If a stored key starts throwing, it was corrupted or tampered with.

## HPKE

- `HpkeWrapper.encrypt` and `decrypt` take an optional trailing `aad`. It is authenticated but not encrypted or returned, and `decrypt` throws unless it gets the same bytes. Existing calls without it keep working.
- `info` longer than **65,530 bytes** throws a `CasError` with `CasErrorCode.InvalidInput`.
- A random `info`, such as the `infoStr` from `generateKeyPair` or `generateInfoString()`, is not domain separation, and it has to be sent or stored alongside every message. Use a fixed, application-specific value that both sides already know. To decrypt messages you already have, keep passing the `info` they were encrypted with; a fixed `info` only applies to new messages.

1.x:

```typescript
const recipient = hpke.generateKeyPair();
const encrypted = hpke.encrypt(plaintext, recipient.publicKey, recipient.infoStr);
const decrypted = hpke.decrypt(encrypted.ciphertext, recipient.secretKey, encrypted.encapsulatedKey, encrypted.tag, recipient.infoStr);
```

2.0:

```typescript
const hpke = new HpkeWrapper();
const recipient = hpke.generateKeyPair();
const info = toBytes("my-app/v1/file-encryption"); // fixed, application-specific
const aad = toBytes("message-id: 42"); // optional
const encrypted = hpke.encrypt(toBytes("This is my message to encrypt"), recipient.publicKey, info, aad);
const decrypted = hpke.decrypt(encrypted.ciphertext, recipient.secretKey, encrypted.encapsulatedKey, encrypted.tag, info, aad);
```

## Errors

Every error raised by cas-lib now reaches JavaScript as an `Error` with a stable `code` from the exported `CasErrorCode` enum, such as `"CAS_DECRYPTION_FAILED"` or `"CAS_DECOMPRESSION_LIMIT_EXCEEDED"`. In 1.x these errors only had a message to go on. The messages are unchanged, so existing message checks keep working, but branch on the code instead: the text may be reworded.

`isCasError(err, code?)` checks for a cas-lib error, optionally with a specific code. Argument checks that the wrapper classes do themselves (empty data, an out-of-range cost, a bad RSA key size) still throw a plain `Error` with no `code`, and `isCasError` returns `false` for them.

1.x:

```typescript
try {
  aes.aes256Decrypt(key, nonce, ciphertext);
} catch (err) {
  if (String(err).includes("decrypt")) {
    // matching on message text
  }
}
```

2.0:

```typescript
import { CasErrorCode, isCasError } from "cas-typescript-sdk";

try {
  aes.aes256Decrypt(key, nonce, ciphertext);
} catch (err) {
  if (isCasError(err, CasErrorCode.DecryptionFailed)) {
    // wrong key, nonce or AAD, or tampered data
  } else if (isCasError(err)) {
    console.error(err.code, err.message); // any other cas-lib error
  } else {
    throw err; // wrapper argument check or a bug
  }
}
```

## Raw native bindings

The package's `exports` map only exposes the wrapper classes, so this section only matters if you load the generated napi binding (`index.js` at the package root) directly. These functions changed:

| Function | 1.x | 2.0 |
| --- | --- | --- |
| `signRsa` / `verifyRsa` | `(privateKey, hash)` / `(publicKey, hash, signature)`, unprefixed PKCS#1 v1.5 | `(privateKey, message)` / `(publicKey, message, signature)`, RS256 |
| `hpkeEncrypt` / `hpkeDecrypt` | no AAD | required trailing `aad` (pass `[]` for none) |
| `pbkdf2Derive` / `pbkdf2DeriveWithSalt` | any iteration count and salt | throw below 600,000 iterations or a 16-byte salt |
| `aes128KeyFromX25519SharedSecret`, `aes256KeyFromX25519SharedSecret`, `aes128GcmSivKeyFromX25519SharedSecret`, `aes256GcmSivKeyFromX25519SharedSecret` | `(sharedSecret)` | `(sharedSecret, publicKeyA, publicKeyB)`, different keys |
| `x25519DiffieHellman` | any public key | throws for low-order public keys |
| `ztsdDecompress` | no output limit | 64 MiB limit; `ztsdDecompressWithLimit(data, maxOutputSize)` for another limit |
| `argon2HashParams`, `scryptHashParams`, `bcryptHashParams` and the `*Verify` functions | no cost bounds | the [cost bounds](#cost-bounds) above |

Every function also throws errors with a `code`, as described under [Errors](#errors).

## Recommended APIs

2.0 adds safer APIs. They aren't required to upgrade, but use them for new code.

### seal / open

Every AEAD has `seal` / `open` methods. `seal` draws a fresh random nonce for each call and returns `nonce || ciphertext || tag`, so there is no nonce to store or reuse by mistake. AAD is optional, and `open` needs the same bytes.

| Wrapper | seal / open |
| --- | --- |
| `AESWrapper` (AES-GCM) | `aes128Seal` / `aes128Open`, `aes256Seal` / `aes256Open` |
| `AESGCMSIVWrapper` | `aes128Seal` / `aes128Open`, `aes256Seal` / `aes256Open` |
| `ChaCha20Poly1305Wrapper` | `seal` / `open` |
| `AsconWrapper` | `ascon128Seal` / `ascon128Open` |

A random 96-bit nonce is only safe for about 2³² messages per key, so rotate keys well before that.

```typescript
const aes = new AESWrapper();
const key = aes.aes256Key();
const aad = toBytes("message-id: 42");
const sealed = aes.aes256Seal(key, toBytes("This is my message to encrypt"), aad);
const opened = toText(aes.aes256Open(key, sealed, aad));

const chacha = new ChaCha20Poly1305Wrapper();
const chachaKey = chacha.generateKey();
const chachaSealed = chacha.seal(chachaKey, toBytes("hello"));
const chachaOpened = chacha.open(chachaKey, chachaSealed);
```

### AAD with a caller-supplied nonce

If you manage nonces yourself, the `*WithAad` methods bind additional authenticated data: `AESWrapper` and `AESGCMSIVWrapper` have `aes128EncryptWithAad` / `aes128DecryptWithAad` and `aes256EncryptWithAad` / `aes256DecryptWithAad`, `ChaCha20Poly1305Wrapper` has `encryptWithAad` / `decryptWithAad`, and `AsconWrapper` has `ascon128EncryptWithAad` / `ascon128DecryptWithAad`. Never reuse a nonce with the same key; if you can't guarantee that, use AES-GCM-SIV or `seal`.

```typescript
const siv = new AESGCMSIVWrapper();
const sivKey = siv.aes256Key();
const nonce = siv.generateNonce();
const header = toBytes("record-id: 7");
const ciphertext = siv.aes256EncryptWithAad(sivKey, nonce, toBytes("This is my message to encrypt"), header);
const plaintext = siv.aes256DecryptWithAad(sivKey, nonce, ciphertext, header);
```

### RSA-PSS

`RSAWrapper.signPss` / `verifyPss` use RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt (`PS256`). See [RSA signatures](#rsa-signatures) for an example.

### AES key wrap

`AesKeyWrapWrapper` wraps key material under a key-encryption key (KEK) with AES-KW (RFC 3394, for keys that are a multiple of 8 bytes and at least 16 bytes) or AES-KWP (RFC 5649, any non-zero length). Use it to store data keys encrypted under a master key; use an AEAD for general data.

```typescript
const keyWrap = new AesKeyWrapWrapper();
const kek = keyWrap.aes256GenerateKek();
const dataKey = new AESWrapper().aes256Key();
const wrapped = keyWrap.aes256WrapKey(kek, dataKey); // 8 bytes longer than dataKey
const unwrapped = keyWrap.aes256UnwrapKey(kek, wrapped); // throws CasErrorCode.DecryptionFailed if tampered

const padded = keyWrap.aes256WrapKeyWithPadding(kek, toBytes("any length secret"));
const unpadded = keyWrap.aes256UnwrapKeyWithPadding(kek, padded);
```
