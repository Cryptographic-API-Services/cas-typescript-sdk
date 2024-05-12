### Symmetric
- AES 256
```typescript
const aesWrapper: AESWrapper = new AESWrapper();
const aesKey = aesWrapper.aes128Key();
const aesNonce = aesWrapper.aesNonce();
const toEncrypt: string = "This is my array to encrypt";
const encoder = new TextEncoder();
const tohashBytes: Array<number> = Array.from(encoder.encode(toEncrypt));
const ciphertext = aesWrapper.aes128Encrypt(aesKey, aesNonce, tohashBytes);
const plaintxt = aesWrapper.aes128Decrypt(aesKey, aesNonce, ciphertext);
```

### Asymmetric 
-RSA
```typescript
const rsaWrapper: RSAWrapper = new RSAWrapper();
const keys: RsaKeyPairResult = rsaWrapper.generateKeys(4096);
const tohashed: string = "This is my array to encrypt";
const encoder = new TextEncoder();
const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
const ciphertext = rsaWrapper.encrypt(keys.publicKey, tohashBytes);
const plaintext = rsaWrapper.decrypt(keys.privateKey, ciphertext);
```


### Digital Signature
-ED25519 SHA
```typescript
const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA256)
const toHash: string = "This is my array to encrypt";
const encoder = new TextEncoder();
const toHashBytes: Array<number> = Array.from(encoder.encode(toHash));
const dsResult = shaDsWrapper.createED25519(toHashBytes);
const verify = shaDsWrapper.verifyED25519(dsResult.publicKey, toHashBytes, dsResult.signature);
```

-RSA SHA
```typescript
const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA512)
const tohashed: string = "This is my array to encrypt";
const notOriginal: string = "This is not a fun time";
const encoder = new TextEncoder();
const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
const badBytes: Array<number> = Array.from(encoder.encode(notOriginal));
const dsResult: RSADigitalSignatureResult = shaDsWrapper.createRsa(4096, tohashBytes);
const verify = shaDsWrapper.verifyRSa(dsResult.publicKey, badBytes, dsResult.signature);
```


### Hashers 
-SHA3 512
```typescript
const wrapper = new SHAWrapper();
const tohashed: string = "This is my array to hash";
const encoder = new TextEncoder();
const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
const hashed = wrapper.hash512(tohashBytes);
```

-SHA3 256
```typescript
const wrapper = new SHAWrapper();
const tohashed: string = "This is my array to hash";
const encoder = new TextEncoder();
const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
const hashed = wrapper.hash256(tohashBytes);
```

### Hybrid Encryption
-AES/RSA Encryption
```typescript
const hybridWrapper = new HybridEncryptionWrapper();
let initalizer = new AESRSAHybridInitializer(128, 4096);
const tohashed: string = "This is my encrypt text for rsa hybrid";
const encoder = new TextEncoder();
const toEncrypt: Array<number> = Array.from(encoder.encode(tohashed));
let result: AesRsaHybridEncryptResult = hybridWrapper.encrypt(toEncrypt, initalizer);
let plaintext: Array<number> = hybridWrapper.decrypt(initalizer.rsaKeyPair.privateKey, result);
```

### Key Exchange 
-X25519 
```typescript
const wrapper = new X25519Wrapper();
const alice = wrapper.generateSecretAndPublicKey();
const bob = wrapper.generateSecretAndPublicKey();

const alice_shared_secret = wrapper.generateSharedSecret(
      alice.secretKey,
      bob.publicKey,
    );
const bob_shared_secret = wrapper.generateSharedSecret(
      bob.secretKey,
      alice.publicKey,
    );

var result = areEqual(alice_shared_secret, bob_shared_secret);
```

### Sponges
-Ascon 128
```typescript
const wrapper: AsconWrapper = new AsconWrapper();
const key: Array<number> = wrapper.ascon128Key();
const nonce: Array<number> = wrapper.ascon128Nonce();
const tohashed: string = "This is my array to encrypt";
const encoder = new TextEncoder();
const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
const ciphertext = wrapper.ascon128Encrypt(key, nonce, tohashBytes);
const plaintext = wrapper.ascon128Decrypt(key, nonce, ciphertext);
```

### Passwords
- BCrypt
```typescript
const hasher: BCryptWrapper = new BCryptWrapper();
const password: string = "ThisOneBadPassword!@";
const hashedPassword: string = hasher.hashPassword(password);
```

- SCrypt
```typescript
const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Scrypt,
    );
const password: string = "ScryptRocks";
const hashed: string = hasher.hashPassword(password);
```

- Argon2
```typescript
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Argon2,
    );
    const password: string = "ScryptRocks";
    const hashed: string = hasher.hashPassword(password);
```