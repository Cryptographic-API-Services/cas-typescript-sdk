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