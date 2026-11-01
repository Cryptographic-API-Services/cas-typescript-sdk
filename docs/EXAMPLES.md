# Usage Examples

Every wrapper is exported from the package root:

```typescript
import {
  AESWrapper,
  AESGCMSIVWrapper,
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

### AES-GCM (128 / 256)
```typescript
const aes = new AESWrapper();
const key = aes.aes256Key(); // or aes.aes128Key()
const nonce = aes.generateAESNonce();
const ciphertext = aes.aes256Encrypt(key, nonce, toBytes("This is my message to encrypt"));
const plaintext = toText(aes.aes256Decrypt(key, nonce, ciphertext));

// AES-128 uses the matching methods
const key128 = aes.aes128Key();
const ciphertext128 = aes.aes128Encrypt(key128, nonce, toBytes("hello"));
const plaintext128 = aes.aes128Decrypt(key128, nonce, ciphertext128);

// Bring your own key (throws if the length is wrong: 16 bytes for 128, 32 bytes for 256)
const ownKey = aes.aes256KeyFromBytes(existing32ByteKey);
const ownKey128 = aes.aes128KeyFromBytes(existing32ByteKey.slice(0, 16));
```

### AES-GCM-SIV (nonce-misuse resistant)
```typescript
const siv = new AESGCMSIVWrapper();
const key = siv.aes256Key(); // or siv.aes128Key()
const nonce = siv.generateNonce();
const ciphertext = siv.aes256Encrypt(key, nonce, toBytes("This is my message to encrypt"));
const plaintext = siv.aes256Decrypt(key, nonce, ciphertext);

// AES-128-GCM-SIV
const key128 = siv.aes128Key();
const ciphertext128 = siv.aes128Encrypt(key128, nonce, toBytes("hello"));
const plaintext128 = siv.aes128Decrypt(key128, nonce, ciphertext128);

// Bring your own key (16 bytes for 128, 32 bytes for 256)
const ownKey = siv.aes256KeyFromBytes(existing32ByteKey);
const ownKey128 = siv.aes128KeyFromBytes(existing32ByteKey.slice(0, 16));
```

### ChaCha20-Poly1305
```typescript
const chacha = new ChaCha20Poly1305Wrapper();
const key = chacha.generateKey();
const nonce = chacha.generateNonce();
const ciphertext = chacha.encrypt(key, nonce, toBytes("This is my message to encrypt"));
const plaintext = chacha.decrypt(key, nonce, ciphertext);
```

## Asymmetric

### RSA signatures
```typescript
const rsa = new RSAWrapper();
const keys: CASRSAKeyPairResult = rsa.getKeyPair(4096); // 1024, 2048 or 4096
const message = toBytes("This is my message to sign");
const signature = rsa.sign(keys.privateKey, message);
const isValid: boolean = rsa.verify(keys.publicKey, message, signature);
```

## Digital Signatures

### Ed25519
```typescript
const ed25519 = new Ed25519Wrapper();
const keyPair = ed25519.getKeyPair();
const message = toBytes("This is my message to sign");
const signature = ed25519.signBytes(keyPair.privateKey, message);
const isValid: boolean = ed25519.verifyBytes(keyPair.publicKey, message, signature);

// Verify with the 32 byte private key instead of the public key (non-strict verification)
const isValidWithKeyPair: boolean = ed25519.verifyWithKeyPairBytes(keyPair.privateKey, message, signature);
```

## Hashers

`SHAWrapper` (SHA3), `SHA2Wrapper` and `Blake2Wrapper` share the same interface. `verify512` / `verify256` take the existing hash first, then the data to check.

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
const hash512 = blake2.hash512(data);
const hash256 = blake2.hash256(data);
const matches512: boolean = blake2.verify512(hash512, data);
const matches256: boolean = blake2.verify256(hash256, data);
```

### Choosing a hasher at runtime
```typescript
const hasher = new HasherFactory().getHasher(HasherType.SHA2); // SHA, SHA2 or Blake2
const hash = hasher.hash256(toBytes("This is my array to hash"));
```

## Passwords

### Argon2
```typescript
const argon2 = new Argon2Wrapper();
const hashed = argon2.hashPassword("ThisOneBadPassword!@");
const isMatch: boolean = argon2.verify(hashed, "ThisOneBadPassword!@");

// Custom parameters: memory cost (MiB), time cost (iterations), parallelism
const tuned = argon2.hashPasswordWithParameters("ThisOneBadPassword!@", 19, 2, 1);

// Derive a one-time AES key from a password (the salt is discarded, so it cannot be re-derived)
const aes256Key = argon2.deriveAes256Key(toBytes("ThisOneBadPassword!@"));
const aes128Key = argon2.deriveAes128Key(toBytes("ThisOneBadPassword!@"));
```

### BCrypt
```typescript
const bcrypt = new BCryptWrapper();
const hashed = bcrypt.hashPassword("ThisOneBadPassword!@");
const isMatch: boolean = bcrypt.verify(hashed, "ThisOneBadPassword!@");
const tuned = bcrypt.hashPasswordWithParameters("ThisOneBadPassword!@", 12); // cost
```

### SCrypt
```typescript
const scrypt = new ScryptWrapper();
const hashed = scrypt.hashPassword("ScryptRocks");
const isMatch: boolean = scrypt.verify(hashed, "ScryptRocks");
// Custom parameters: log2 CPU cost, block size, parallelism
const tuned = scrypt.hashPasswordWithParameters("ScryptRocks", 17, 8, 1);
```

### PBKDF2 key derivation
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

// Each side combines its own secret key with the other side's public key
const aliceShared = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);
const bobShared = x25519.generateSharedSecret(bob.secretKey, alice.publicKey);
// aliceShared and bobShared are identical

// Turn the shared secret into an AES key
const aes = new AESWrapper();
const aliceKey = aes.aes256KeyNonceX25519DiffieHellman(aliceShared);
const bobKey = aes.aes256KeyNonceX25519DiffieHellman(bobShared);
const nonce = aes.generateAESNonce();
const ciphertext = aes.aes256Encrypt(aliceKey, nonce, toBytes("Hello Bob"));
const plaintext = toText(aes.aes256Decrypt(bobKey, nonce, ciphertext));

// AES-128 from the same shared secret
const aes128Key = aes.aes128KeyNonceX25519DiffieHellman(aliceShared);

// AES-GCM-SIV equivalents
const siv = new AESGCMSIVWrapper();
const sivKey256 = siv.aes256KeyFromX25519SharedSecret(aliceShared);
const sivKey128 = siv.aes128KeyFromX25519SharedSecret(aliceShared);
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

// HMAC-SHA512
const tag512 = hmac.hmacSha512SignBytes(key, message);
const isValid512: boolean = hmac.hmacSha512VerifyBytes(key, message, tag512);
```

## Sponges

### Ascon-128 AEAD
```typescript
const ascon = new AsconWrapper();
const key = ascon.ascon128Key();
const nonce = ascon.ascon128Nonce();
const ciphertext = ascon.ascon128Encrypt(key, nonce, toBytes("This is my message to encrypt"));
const plaintext = ascon.ascon128Decrypt(key, nonce, ciphertext);
```

## Hybrid Encryption

### HPKE
```typescript
const hpke = new HpkeWrapper();
const recipient = hpke.generateKeyPair(); // publicKey, secretKey, infoStr
const encrypted = hpke.encrypt(toBytes("This is my message to encrypt"), recipient.publicKey, recipient.infoStr);
const plaintext = hpke.decrypt(
  encrypted.ciphertext,
  recipient.secretKey,
  encrypted.encapsulatedKey,
  encrypted.tag,
  recipient.infoStr,
);

// A fresh info string can also be generated on its own
const infoStr = hpke.generateInfoString();
```

## Compression

### Zstandard
```typescript
const zstd = new ZTSDWrapper();
const compressed = zstd.compress(toBytes("This is my data to compress"), 3); // level -22 to 22
const decompressed = zstd.decompress(compressed);
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
