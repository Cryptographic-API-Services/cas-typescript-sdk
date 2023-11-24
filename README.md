# eas-javascript

![GitHub issues](https://img.shields.io/github/issues/Encryption-Api-Services/eas-javascript)
![GitHub](https://img.shields.io/github/license/Encryption-Api-Services/eas-javascript)

This NPM package is intended to be used in conjunction with making a user account at [Encryption API Service](https://encryptionapiservices.com) and uptaining a API key to generate a token. The SDK makes authenticated API calls to the main [EAS API](https://github.com/Encryption-API-Services/NETCore-API).  We have done ton's of work for you on the API side of things organizing and researching some of the most popular and performant crytographic packages and implementing them in the systems level language [Rust](https://www.rust-lang.org/). We have also saved you the time of learning to work with Rust FFI in our [performant_encryption](https://github.com/Encryption-API-Services/performant_encryption) crate which is what the API calls in this SDK are utilizing.

The NPM home page for this package can be found [here](https://www.npmjs.com/package/@encryption-api-services/eas-javascript).

# Examples

## Getting a Token
```typescript
import { EASConfiguration, TokenCache } from "@encryption-api-services/eas-javascript";

// Insert your API key here
EASConfiguration.apiKey = ""; 

const tokenFunction = async () => {
    const tokenService = new TokenCache();
    const token = await tokenService.getToken();
    console.log(token);
}
```
## ED25519-Dalek (Signatures)
```typescript
import { EASConfiguration, ED25519DalekService, TokenCache } from "@encryption-api-services/eas-javascript";

// Insert your API key here
EASConfiguration.apiKey = ""; 
const tokenCache = new TokenCache();
const ed25519Service = new ED25519DalekService();

const ed25519Test = async () => {
    const token = await tokenCache.getToken();
    const keyPair = await ed25519Service.generateKeyPair(token);
    const signature = await ed25519Service.sign(token, keyPair.keyPair, "Hello World");
    const verify = await ed25519Service.verify(token, signature.publicKey, signature.signature, "Hello World");
    console.log(verify);
};

ed25519Test();
```

## AES256 Encrypt / Decrypt
```typescript
import { EASConfiguration, SymmetricEncryptionService, TokenCache } from "@encryption-api-services/eas-javascript";
import { Aes256DecryptResponse } from "@encryption-api-services/eas-javascript/lib/types/symmetric/aes-256-decrypt-response";
import { Aes256EncryptResponse } from "@encryption-api-services/eas-javascript/lib/types/symmetric/aes-256-encrypt-response";

// Insert your API key here
EASConfiguration.apiKey = ""; 
const tokenService = new TokenCache();
const symmetricService = new SymmetricEncryptionService();

const aesEncryptFunction = async (): Promise<Aes256EncryptResponse> => {
    const token = await tokenService.getToken();
    return await symmetricService.aes256Encrypt(token, "Hello World!");
};

const aesDecryptFunction = async (encryptedResult: Aes256EncryptResponse): Promise<Aes256DecryptResponse> => {
    const token = await tokenService.getToken();
    return await symmetricService.aes256Decrypt(token, encryptedResult.encrypted, encryptedResult.key, encryptedResult.nonce);
};


aesEncryptFunction().then((response: Aes256EncryptResponse) => {
    return aesDecryptFunction(response);
}).then((response: Aes256DecryptResponse) => {
    console.log(response.decrypted);
})
```

## Password Hashing / Verify (Argon2)
```typescript
import { EASConfiguration, PasswordService, TokenCache } from "@encryption-api-services/eas-javascript";
import { Argon2HashPasswordResponse } from "@encryption-api-services/eas-javascript/lib/types/password/argon2-hash-password-response";
import { Argon2VerifyResponse } from "@encryption-api-services/eas-javascript/lib/types/password/argon2-verify-response";

// Insert your API key here
EASConfiguration.apiKey = ""; 
const tokenService = new TokenCache();
const passwordService = new PasswordService();

const encryptPassword = async (password: string): Promise<Argon2HashPasswordResponse> => {
    const token = await tokenService.getToken();
    return await passwordService.argon2HashPassword(token, password);
}

const verifyPassword = async (password: string, encrypted: string) => {
    const token = await tokenService.getToken();
    return await passwordService.argon2Verify(token, encrypted, password);
};

const password = "MyBadPassword";
encryptPassword(password).then((response) => {
    return verifyPassword(password, response.hashedPassword);
}).then((result: Argon2VerifyResponse) => {
    console.log(result);
});
```

## RSA Key Pair Generation, Encrypt, and Decrypt
```typescript
import { EASConfiguration, RsaService, TokenCache } from "@encryption-api-services/eas-javascript";
import { RsaDecryptResponse } from "@encryption-api-services/eas-javascript/lib/types/rsa/rsa-decrypt-response";
import { RsaEncryptWithPublicResponse } from "@encryption-api-services/eas-javascript/lib/types/rsa/rsa-encrypt-with-public-response";
import { RsaGetKeyPairResponse } from "@encryption-api-services/eas-javascript/lib/types/rsa/rsa-key-pair";

// Insert your API key here
EASConfiguration.apiKey = ""; 
const tokenService = new TokenCache();
const rsaService = new RsaService();

const getRsKeys = async (): Promise<RsaGetKeyPairResponse> => {
    const token = await tokenService.getToken();
    return await rsaService.getRsaKeys(token, 4096);
}

const encryptRsa = async (publicKey: string): Promise<RsaEncryptWithPublicResponse> => {
    const token = await tokenService.getToken();
    const encrypted = await rsaService.encryptWithPublicKey(token, publicKey, "Hello World!");
    return encrypted;
}

const decryptRsa = async (privateKey: string, dataToDecrypt: string): Promise<RsaDecryptResponse> => {
    const token = await tokenService.getToken();
    return await rsaService.decryptWithPrivateKey(token, privateKey, dataToDecrypt);
}

getRsKeys().then((keys: RsaGetKeyPairResponse) => {
    console.log(keys);
    encryptRsa(keys.publicKey).then((encrypted: RsaEncryptWithPublicResponse) => {
        console.log(encrypted);
        decryptRsa(keys.privateKey, encrypted.encryptedData).then((decrypted: RsaDecryptResponse) => {
            console.log(decrypted);
        });
    });
});
```
