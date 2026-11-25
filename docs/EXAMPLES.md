# Usage Examples

Every wrapper is exported from the package root:

```typescript
import {
  AESWrapper,
  AESGCMSIVWrapper,
  AesKeyWrapWrapper,
  ChaCha20Poly1305Wrapper,
  RSAWrapper,
  CASRSAKeyPairResult,
  Ed25519Wrapper,
  SHAWrapper,
  SHA2Wrapper,
  Blake2Wrapper,
  HasherFactory,
  HasherType,
  Argon2Wrapper,
  BCryptWrapper,
  ScryptWrapper,
  Pbkdf2Wrapper,
  PasswordHasherFactory,
  PasswordHasherType,
  X25519Wrapper,
  HmacWrapper,
  AsconWrapper,
  HpkeWrapper,
  ZTSDWrapper,
  MlKem1024Wrapper,
  MlDsa65Wrapper,
  SlhDsaWrapper,
  CasErrorCode,
  isCasError,
} from "cas-typescript-sdk";
```

Binary data crosses the API as `Array<number>` (a byte array). The examples below use these helpers to convert text:

```typescript
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const toBytes = (text: string): Array<number> => Array.from(encoder.encode(text));
const toText = (bytes: Array<number>): string => decoder.decode(new Uint8Array(bytes));
```

## Symmetric

Every AEAD has `seal` / `open` methods, the recommended API. `seal` draws a fresh random nonce for every call and returns `nonce || ciphertext || tag` (a 16 byte tag; a 12 byte nonce, or 16 bytes for Ascon), so there is no nonce to store or reuse by mistake. Optional AAD (additional authenticated data) is bound to the tag but not encrypted or stored: `open` needs the same bytes. `open` throws `CasErrorCode.DecryptionFailed` for a wrong key, AAD or tampered data, and `CasErrorCode.InvalidInput` for a blob shorter than nonce + tag.

A random 96 bit nonce (AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305) is only safe for about 2³² messages per key, so rotate keys well before that. If you have to manage nonces yourself, use AES-GCM-SIV: reusing a nonce there only reveals whether two messages were identical, while with AES-GCM or ChaCha20-Poly1305 it breaks confidentiality and authenticity.

### AES-GCM (128 / 256)
```typescript
const aes = new AESWrapper();
const key = aes.aes256Key(); // or aes.aes128Key()

// Recommended: seal / open manage the nonce for you
const sealed = aes.aes256Seal(key, toBytes("This is my message to encrypt"));
const opened = toText(aes.aes256Open(key, sealed));

// With AAD, which open must receive unchanged
const aad = toBytes("message-id: 42");
const sealedWithAad = aes.aes256Seal(key, toBytes("This is my message to encrypt"), aad);
const openedWithAad = aes.aes256Open(key, sealedWithAad, aad);

// AES-128 uses the matching methods
const key128 = aes.aes128Key();
const sealed128 = aes.aes128Seal(key128, toBytes("hello"));
const opened128 = aes.aes128Open(key128, sealed128);

// A sealed blob is nonce (12 bytes) || ciphertext || tag, so decrypt can read it too
const sameMessage = aes.aes256Decrypt(key, sealed.slice(0, 12), sealed.slice(12));

// Caller-supplied nonce: never use a nonce twice with the same key
const nonce = aes.generateAESNonce();
const ciphertext = aes.aes256Encrypt(key, nonce, toBytes("This is my message to encrypt"));
const plaintext = toText(aes.aes256Decrypt(key, nonce, ciphertext));
const nonce128 = aes.generateAESNonce();
const ciphertext128 = aes.aes128Encrypt(key128, nonce128, toBytes("hello"));
const plaintext128 = aes.aes128Decrypt(key128, nonce128, ciphertext128);

// Caller-supplied nonce with AAD (same nonce rule); decrypt throws CasErrorCode.DecryptionFailed for other AAD
const header = toBytes("record-id: 7");
const aadNonce = aes.generateAESNonce();
const aadCiphertext = aes.aes256EncryptWithAad(key, aadNonce, toBytes("This is my message to encrypt"), header);
const aadPlaintext = toText(aes.aes256DecryptWithAad(key, aadNonce, aadCiphertext, header));
const aadNonce128 = aes.generateAESNonce();
const aadCiphertext128 = aes.aes128EncryptWithAad(key128, aadNonce128, toBytes("hello"), header);
const aadPlaintext128 = aes.aes128DecryptWithAad(key128, aadNonce128, aadCiphertext128, header);

// Bring your own key (throws if the length is wrong: 16 bytes for 128, 32 bytes for 256)
const ownKey = aes.aes256KeyFromBytes(existing32ByteKey);
const ownKey128 = aes.aes128KeyFromBytes(existing32ByteKey.slice(0, 16));
```

### AES-GCM-SIV (nonce-misuse resistant)
```typescript
const siv = new AESGCMSIVWrapper();
const key = siv.aes256Key(); // or siv.aes128Key()

// Recommended: seal / open manage the nonce for you (AAD is optional)
const aad = toBytes("message-id: 42");
const sealed = siv.aes256Seal(key, toBytes("This is my message to encrypt"), aad);
const opened = siv.aes256Open(key, sealed, aad);

// AES-128-GCM-SIV
const key128 = siv.aes128Key();
const sealed128 = siv.aes128Seal(key128, toBytes("hello"));
const opened128 = siv.aes128Open(key128, sealed128);

// Caller-supplied nonce, for when you have to manage nonces yourself
const nonce = siv.generateNonce();
const ciphertext = siv.aes256Encrypt(key, nonce, toBytes("This is my message to encrypt"));
const plaintext = siv.aes256Decrypt(key, nonce, ciphertext);
const ciphertext128 = siv.aes128Encrypt(key128, nonce, toBytes("hello"));
const plaintext128 = siv.aes128Decrypt(key128, nonce, ciphertext128);

// Caller-supplied nonce with AAD; decrypt throws CasErrorCode.DecryptionFailed for other AAD
const header = toBytes("record-id: 7");
const aadNonce = siv.generateNonce();
const aadCiphertext = siv.aes256EncryptWithAad(key, aadNonce, toBytes("This is my message to encrypt"), header);
const aadPlaintext = siv.aes256DecryptWithAad(key, aadNonce, aadCiphertext, header);
const aadCiphertext128 = siv.aes128EncryptWithAad(key128, aadNonce, toBytes("hello"), header);
const aadPlaintext128 = siv.aes128DecryptWithAad(key128, aadNonce, aadCiphertext128, header);

// Bring your own key (16 bytes for 128, 32 bytes for 256)
const ownKey = siv.aes256KeyFromBytes(existing32ByteKey);
const ownKey128 = siv.aes128KeyFromBytes(existing32ByteKey.slice(0, 16));
```

### ChaCha20-Poly1305
```typescript
const chacha = new ChaCha20Poly1305Wrapper();
const key = chacha.generateKey();

// Recommended: seal / open manage the nonce for you (AAD is optional)
const aad = toBytes("message-id: 42");
const sealed = chacha.seal(key, toBytes("This is my message to encrypt"), aad);
const opened = chacha.open(key, sealed, aad);

// Caller-supplied nonce: never use a nonce twice with the same key
const nonce = chacha.generateNonce();
const ciphertext = chacha.encrypt(key, nonce, toBytes("This is my message to encrypt"));
const plaintext = chacha.decrypt(key, nonce, ciphertext);

// Caller-supplied nonce with AAD (same nonce rule); decrypt throws CasErrorCode.DecryptionFailed for other AAD
const header = toBytes("record-id: 7");
const aadNonce = chacha.generateNonce();
const aadCiphertext = chacha.encryptWithAad(key, aadNonce, toBytes("This is my message to encrypt"), header);
const aadPlaintext = chacha.decryptWithAad(key, aadNonce, aadCiphertext, header);
```

### AES key wrapping (AES-KW, RFC 3394 / AES-KWP, RFC 5649)
```typescript
const keyWrap = new AesKeyWrapWrapper();
const kek = keyWrap.aes256GenerateKek(); // 32 byte key-encryption key
const dataKey = new AESWrapper().aes256Key();

// AES-KW: key data must be a multiple of 8 bytes and at least 16 bytes; output is 8 bytes longer
const wrapped = keyWrap.aes256WrapKey(kek, dataKey);
const unwrapped = keyWrap.aes256UnwrapKey(kek, wrapped); // throws CAS_DECRYPTION_FAILED if tampered

// AES-KWP: key data of any non-zero length
const wrappedPadded = keyWrap.aes256WrapKeyWithPadding(kek, toBytes("20 byte secret value"));
const unwrappedPadded = keyWrap.aes256UnwrapKeyWithPadding(kek, wrappedPadded);

// AES-128 KEKs use the matching methods
const kek128 = keyWrap.aes128GenerateKek(); // 16 bytes
const wrapped128 = keyWrap.aes128WrapKey(kek128, dataKey);
const unwrapped128 = keyWrap.aes128UnwrapKey(kek128, wrapped128);
const wrappedPadded128 = keyWrap.aes128WrapKeyWithPadding(kek128, toBytes("short"));
const unwrappedPadded128 = keyWrap.aes128UnwrapKeyWithPadding(kek128, wrappedPadded128);
```

## Asymmetric

### RSA signatures

`sign` / `verify` take the message itself (any length), not a digest of it, and use RSASSA-PKCS1-v1_5 with SHA-256: standard `RS256`, as in JWS, OpenSSL and WebCrypto. Signatures made by 1.x of this SDK don't verify. Keys are PEM strings: PKCS#8 for the private key, PKCS#1 for the public key. `verify` accepts public keys from 2048 up to 8192 bits.

```typescript
const rsa = new RSAWrapper();
const keys: CASRSAKeyPairResult = rsa.getKeyPair(4096); // 2048, 3072 or 4096; smaller keys throw
const message = toBytes("This is my message to sign");
const signature = rsa.sign(keys.privateKey, message);
const isValid: boolean = rsa.verify(keys.publicKey, message, signature);

// Interoperates with Node's crypto module (and any other RS256 implementation)
import { sign, verify } from "crypto";
const nodeSignature = sign("sha256", Buffer.from(message), keys.privateKey);
const nodeSignatureIsValid: boolean = rsa.verify(keys.publicKey, message, Array.from(nodeSignature));
const verifiedByNode: boolean = verify("sha256", Buffer.from(message), keys.publicKey, Buffer.from(signature));
```

### RSA PSS signatures

`signPss` / `verifyPss` use RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt (`PS256`), and are recommended for new designs; keep `sign` / `verify` for systems that need `RS256`. PSS signatures are randomized, so signing the same message twice gives different signatures that both verify. Keys and message handling are the same as for `sign` / `verify`.

```typescript
const rsaPss = new RSAWrapper();
const pssKeys = rsaPss.getKeyPair(2048);
const pssMessage = toBytes("This is my message to sign");
const pssSignature = rsaPss.signPss(pssKeys.privateKey, pssMessage);
const pssIsValid: boolean = rsaPss.verifyPss(pssKeys.publicKey, pssMessage, pssSignature);

// Interoperates with Node's crypto module using PSS padding and a 32-byte salt
import { constants, sign as nodeSign, verify as nodeVerify } from "crypto";
const pssOptions = { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };
const nodePssSignature = nodeSign("sha256", Buffer.from(pssMessage), { key: pssKeys.privateKey, ...pssOptions });
const nodePssSignatureIsValid: boolean = rsaPss.verifyPss(pssKeys.publicKey, pssMessage, Array.from(nodePssSignature));
const pssVerifiedByNode: boolean = nodeVerify("sha256", Buffer.from(pssMessage), { key: pssKeys.publicKey, ...pssOptions }, Buffer.from(pssSignature));
```

## Digital Signatures

### Ed25519
```typescript
const ed25519 = new Ed25519Wrapper();
const keyPair = ed25519.getKeyPair();
const message = toBytes("This is my message to sign");
const signature = ed25519.signBytes(keyPair.privateKey, message);
const isValid: boolean = ed25519.verifyBytes(keyPair.publicKey, message, signature);

// Verify with the 32 byte private key instead of the public key (strict, like verifyBytes)
const isValidWithKeyPair: boolean = ed25519.verifyWithKeyPairBytes(keyPair.privateKey, message, signature);
```

## Hashers

`SHAWrapper` (SHA3-512 / SHA3-256), `SHA2Wrapper` (SHA-512 / SHA-256) and `Blake2Wrapper` (BLAKE2b-512 / BLAKE2s-256) share the same interface. `verify512` / `verify256` take the existing hash first, then the data to check.

Empty input is valid: `[]`, `null` and `undefined` all hash as the empty message, which has a well-defined digest.

```typescript
const emptyDigest = new SHA2Wrapper().hash256(null); // e3b0c442...b855, same as hash256([])
const emptyMatches: boolean = new SHA2Wrapper().verify256(emptyDigest, []);
```

### SHA3
```typescript
const sha3 = new SHAWrapper();
const data = toBytes("This is my array to hash");
const hash512 = sha3.hash512(data);
const hash256 = sha3.hash256(data);
const matches512: boolean = sha3.verify512(hash512, data);
const matches256: boolean = sha3.verify256(hash256, data);
```

### SHA2
```typescript
const sha2 = new SHA2Wrapper();
const data = toBytes("This is my array to hash");
const hash512 = sha2.hash512(data);
const hash256 = sha2.hash256(data);
const matches512: boolean = sha2.verify512(hash512, data);
const matches256: boolean = sha2.verify256(hash256, data);
```

### BLAKE2
```typescript
const blake2 = new Blake2Wrapper();
const data = toBytes("This is my array to hash");
const hash512 = blake2.hash512(data); // BLAKE2b-512
const hash256 = blake2.hash256(data); // BLAKE2s-256, not BLAKE2b-256
const matches512: boolean = blake2.verify512(hash512, data);
const matches256: boolean = blake2.verify256(hash256, data);
```

### Choosing a hasher at runtime
```typescript
const hasher = new HasherFactory().getHasher(HasherType.SHA2); // SHA, SHA2 or Blake2
const hash = hasher.hash256(toBytes("This is my array to hash"));
```

## Passwords

### Cost bounds

`hashPasswordWithParameters` throws for a parameter outside these ranges, and `verify` throws for a stored hash whose costs exceed the upper bounds (such as `$2b$31$...`) instead of tying up memory or CPU. Existing hashes below the minimums still verify.

| Hasher | Bounds |
| --- | --- |
| Argon2 | memory 19–4096 **MiB** (not KiB), iterations 1–10, parallelism 1–16 |
| SCrypt | log₂ N 10–20, block size `r` 1–32, parallelism `p` 1–16; log₂ N must also be less than 16 · `r` |
| BCrypt | cost 10–16 |

### Argon2
```typescript
const argon2 = new Argon2Wrapper();
const hashed = argon2.hashPassword("ThisOneBadPassword!@");
const isMatch: boolean = argon2.verify(hashed, "ThisOneBadPassword!@");

// Custom parameters: memory cost in MiB (19-4096; 64 means 64 MiB), time cost (iterations, 1-10), parallelism (1-16)
const tuned = argon2.hashPasswordWithParameters("ThisOneBadPassword!@", 64, 3, 1);

// Derive an AES key from a password and salt (Argon2id, 19 MiB, 2 iterations, parallelism 1).
// The salt is not secret: store it next to the ciphertext to re-derive the same key later.
const salt = argon2.generateSalt(); // 16 random bytes
const aes256Key = argon2.deriveAes256KeyWithSalt(toBytes("ThisOneBadPassword!@"), salt);
const aes128Key = argon2.deriveAes128KeyWithSalt(toBytes("ThisOneBadPassword!@"), salt);
const sameAes256Key = argon2.deriveAes256KeyWithSalt(toBytes("ThisOneBadPassword!@"), salt); // equal to aes256Key
// A salt shorter than 16 bytes throws a CasError with code CasErrorCode.InvalidParameters

// Deprecated: these discard their random salt, so the key can never be derived again
const oneTimeAes256Key = argon2.deriveAes256Key(toBytes("ThisOneBadPassword!@"));
const oneTimeAes128Key = argon2.deriveAes128Key(toBytes("ThisOneBadPassword!@"));
```

### BCrypt

Passwords are limited to 72 bytes of UTF-8 (bytes, not characters: `"€"` is 3 bytes). `hashPassword`, `hashPasswordWithParameters` and `verify` throw for a longer password instead of silently truncating it.

```typescript
const bcrypt = new BCryptWrapper();
const hashed = bcrypt.hashPassword("ThisOneBadPassword!@");
const isMatch: boolean = bcrypt.verify(hashed, "ThisOneBadPassword!@");
const tuned = bcrypt.hashPasswordWithParameters("ThisOneBadPassword!@", 13); // cost, 10-16
```

### SCrypt
```typescript
const scrypt = new ScryptWrapper();
const hashed = scrypt.hashPassword("ScryptRocks");
const isMatch: boolean = scrypt.verify(hashed, "ScryptRocks");
// Custom parameters: log2 N (10-20), block size r (1-32), parallelism p (1-16); memory is about 128 * r * 2^log2N bytes
const tuned = scrypt.hashPasswordWithParameters("ScryptRocks", 17, 8, 1);
```

### PBKDF2 key derivation

The iteration count must be at least 600,000 and a caller-supplied salt at least 16 bytes; anything weaker throws. Store the salt and iteration count alongside whatever the key protects.

```typescript
const pbkdf2 = new Pbkdf2Wrapper();
const password = toBytes("ThisOneBadPassword!@");
const { derivedKey, salt } = pbkdf2.derive(password, 600_000); // 32 byte key + random salt
// Re-derive the same key later from the stored salt
const sameKey = pbkdf2.deriveWithSalt(password, 600_000, salt);
```

### Choosing a password hasher at runtime
```typescript
const hasher = PasswordHasherFactory.getHasher(PasswordHasherType.Argon2); // Argon2, Bcrypt or Scrypt
const hashed: string = hasher.hashPassword("ThisOneBadPassword!@");
const isMatch: boolean = hasher.verify(hashed, "ThisOneBadPassword!@");
```

## Key Exchange

### X25519 → AES key over an insecure channel
```typescript
const x25519 = new X25519Wrapper();
const alice = x25519.generateSecretAndPublicKey();
const bob = x25519.generateSecretAndPublicKey();

// Each side combines its own secret key with the other side's public key.
// Throws if the other side's public key is a low-order point (it would force an all-zero secret).
const aliceShared = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);
const bobShared = x25519.generateSharedSecret(bob.secretKey, alice.publicKey);
// aliceShared and bobShared are identical

// Turn the shared secret into an AES key. Pass both public keys, in either order:
// the key is bound to them and to the cipher, so it differs per cipher and per pair of peers.
// Keys differ from those of earlier SDK versions, so both peers must upgrade together.
const aes = new AESWrapper();
const aliceKey = aes.aes256KeyNonceX25519DiffieHellman(aliceShared, alice.publicKey, bob.publicKey);
const bobKey = aes.aes256KeyNonceX25519DiffieHellman(bobShared, bob.publicKey, alice.publicKey);
// aliceKey and bobKey are identical
const nonce = aes.generateAESNonce();
const ciphertext = aes.aes256Encrypt(aliceKey, nonce, toBytes("Hello Bob"));
const plaintext = toText(aes.aes256Decrypt(bobKey, nonce, ciphertext));

// AES-128 from the same shared secret (an unrelated key, not a prefix of the AES-256 one)
const aes128Key = aes.aes128KeyNonceX25519DiffieHellman(aliceShared, alice.publicKey, bob.publicKey);

// AES-GCM-SIV equivalents
const siv = new AESGCMSIVWrapper();
const sivKey256 = siv.aes256KeyFromX25519SharedSecret(aliceShared, alice.publicKey, bob.publicKey);
const sivKey128 = siv.aes128KeyFromX25519SharedSecret(aliceShared, alice.publicKey, bob.publicKey);
```

## Message Authentication

### HMAC
```typescript
const hmac = new HmacWrapper();
const key = toBytes("my-shared-hmac-key");
const message = toBytes("This is my message to authenticate");

// HMAC-SHA256
const tag = hmac.hmacSignBytes(key, message);
const isValid: boolean = hmac.hmacVerifyBytes(key, message, tag);

// An empty (or null) message is valid and authenticates the empty message
const emptyTag = hmac.hmacSignBytes(key, null);

// HMAC-SHA512
const tag512 = hmac.hmacSha512SignBytes(key, message);
const isValid512: boolean = hmac.hmacSha512VerifyBytes(key, message, tag512);
```

## Sponges

### Ascon-128 AEAD
```typescript
const ascon = new AsconWrapper();
const key = ascon.ascon128Key();

// Recommended: seal / open manage the nonce for you (AAD is optional).
// The sealed blob is nonce (16 bytes) || ciphertext || tag (16 bytes).
const aad = toBytes("message-id: 42");
const sealed = ascon.ascon128Seal(key, toBytes("This is my message to encrypt"), aad);
const opened = ascon.ascon128Open(key, sealed, aad);

// Caller-supplied nonce: never use a nonce twice with the same key
const nonce = ascon.ascon128Nonce();
const ciphertext = ascon.ascon128Encrypt(key, nonce, toBytes("This is my message to encrypt"));
const plaintext = ascon.ascon128Decrypt(key, nonce, ciphertext);

// Caller-supplied nonce with AAD (same nonce rule); decrypt throws CasErrorCode.DecryptionFailed for other AAD
const header = toBytes("record-id: 7");
const aadNonce = ascon.ascon128Nonce();
const aadCiphertext = ascon.ascon128EncryptWithAad(key, aadNonce, toBytes("This is my message to encrypt"), header);
const aadPlaintext = ascon.ascon128DecryptWithAad(key, aadNonce, aadCiphertext, header);
```

## Hybrid Encryption

### HPKE
```typescript
const hpke = new HpkeWrapper();
const recipient = hpke.generateKeyPair(); // publicKey, secretKey, and a random infoStr (see below)

// info binds the derived keys to a context, and both sides must pass the same bytes.
// Use a fixed, application-specific value rather than a random one.
const info = toBytes("my-app/v1/file-encryption");
const encrypted = hpke.encrypt(toBytes("This is my message to encrypt"), recipient.publicKey, info);
const plaintext = hpke.decrypt(
  encrypted.ciphertext,
  recipient.secretKey,
  encrypted.encapsulatedKey,
  encrypted.tag,
  info,
);

// Optional additional authenticated data: bound to the ciphertext but not encrypted or
// returned, so the recipient must pass the same bytes or decrypt throws
const aad = toBytes("message-id: 42");
const withAad = hpke.encrypt(toBytes("This is my message to encrypt"), recipient.publicKey, info, aad);
const plaintextWithAad = hpke.decrypt(
  withAad.ciphertext,
  recipient.secretKey,
  withAad.encapsulatedKey,
  withAad.tag,
  info,
  aad,
);

// A random info string (also returned as recipient.infoStr) is not domain separation:
// it must be sent or stored alongside the message for the recipient to decrypt.
const randomInfo = hpke.generateInfoString();
```

## Compression

### Zstandard
```typescript
const zstd = new ZTSDWrapper();
const compressed = zstd.compress(toBytes("This is my data to compress"), 3); // level -22 to 22

// Output is capped at 64 MiB by default; larger output throws
// "decompressed output exceeds the size limit" (decompression-bomb protection).
const decompressed = zstd.decompress(compressed);

// Raise (or lower) the cap with maxOutputSize in bytes. Only raise it for trusted input.
const large = zstd.decompress(compressed, 256 * 1024 * 1024);
```

## Post-Quantum

### ML-KEM-1024 (FIPS 203) key encapsulation
```typescript
const mlKem = new MlKem1024Wrapper();
const { publicKey, secretKey } = mlKem.generateKeyPair();
// Sender encapsulates to the recipient's public key
const { ciphertext, sharedSecret } = mlKem.encapsulate(publicKey);
// Recipient recovers the same 32 byte shared secret
const recovered = mlKem.decapsulate(secretKey, ciphertext);
// Use it as an AES-256 key
const aesKey = new AESWrapper().aes256KeyFromBytes(recovered);
```

### ML-DSA-65 (FIPS 204) signatures
```typescript
const mlDsa = new MlDsa65Wrapper();
const { signingKey, verificationKey } = mlDsa.generateKeyPair();
const message = toBytes("This is my message to sign");
const signature = mlDsa.sign(message, signingKey);
const isValid: boolean = mlDsa.verify(message, signature, verificationKey);
```

### SLH-DSA (FIPS 205, SHAKE-128f) signatures
```typescript
const slhDsa = new SlhDsaWrapper();
const { signingKey, verificationKey } = slhDsa.generateKeyPair();
const message = toBytes("This is my message to sign");
const signature = slhDsa.sign(message, signingKey); // ~17 KB, slower than other signers
const isValid: boolean = slhDsa.verify(message, signature, verificationKey);
```

## Error handling

Errors raised by the underlying cas-lib carry a stable `code` from `CasErrorCode` (such as `"CAS_DECRYPTION_FAILED"`). Branch on the code, not the message text. Argument checks done by the wrapper classes, such as passing empty data, throw a plain `Error` with no `code`, and `isCasError` returns `false` for them.

```typescript
const aes = new AESWrapper();
const key = aes.aes256Key();
const nonce = aes.generateAESNonce();
const ciphertext = aes.aes256Encrypt(key, nonce, toBytes("This is my secret message"));
ciphertext[0] ^= 0x01; // tampered in transit

try {
  aes.aes256Decrypt(key, nonce, ciphertext);
} catch (err) {
  if (isCasError(err, CasErrorCode.DecryptionFailed)) {
    // wrong key, nonce or AAD, or tampered data: reject the message
  } else if (isCasError(err)) {
    console.error(err.code, err.message); // any other cas-lib error
  } else {
    throw err; // wrapper validation error or a bug
  }
}

// A decompression bomb is reported with its own code
const zstd = new ZTSDWrapper();
try {
  zstd.decompress(zstd.compress(new Array(1024).fill(0), 3), 512);
} catch (err) {
  if (isCasError(err, CasErrorCode.DecompressionLimitExceeded)) {
    // output would exceed maxOutputSize
  }
}
```
