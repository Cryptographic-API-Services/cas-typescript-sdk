import { assert } from "chai";
import { EASConfiguration, SymmetricEncryptionService, TokenCache } from "../src";
import { Aes256EncryptResponse } from "../src/types/symmetric/aes-256-encrypt-response";
import { Aes256DecryptResponse } from "../src/types/symmetric/aes-256-decrypt-response";
import { Aes128EncryptResponse } from "../src/types/symmetric/aes-128-encrypt-response";
import { Aes128DecryptResponse } from "../src/types/symmetric/aes-128-decrypt-response";
import { MD5HashResponse } from "../src/types/symmetric/md5-hash-response";
import { MD5VerifyResponse } from "../src/types/symmetric/md5-verify-response";
import { Blake2HashResponse } from "../src/types/symmetric/blake2/blake2-hash-response";
import { Blake2VerifyResponse } from "../src/types/symmetric/blake2/blake2-verify-response";
import { HashShaResponse } from "../src/types/symmetric/hash-sha-response";

describe("Symmetric Service Tests", () => {
    EASConfiguration.apiKey = process.env.EasApiKey || '';
    const tokenCache: TokenCache = new TokenCache();
    const symmetricEncryptionService: SymmetricEncryptionService = new SymmetricEncryptionService();

    it("should encrypt with AES256", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "Hello World";
        const encryptResponse: Aes256EncryptResponse = await symmetricEncryptionService.aes256Encrypt(token, dataToEncrypt);
        assert.isNotNull(encryptResponse.encrypted);
        assert.isNotNull(encryptResponse.key);
        assert.isNotNull(encryptResponse.nonce);
    });

    it("should decrypt with AES256", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "Hello World";
        const encryptResponse: Aes256EncryptResponse = await symmetricEncryptionService.aes256Encrypt(token, dataToEncrypt);
        const decryptedResponse: Aes256DecryptResponse = await symmetricEncryptionService.aes256Decrypt(token, encryptResponse.encrypted, encryptResponse.key, encryptResponse.nonce);
        assert.equal(decryptedResponse.decrypted, dataToEncrypt);
    });

    it("should encrypt with AES128", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "Hello World";
        const encryptResponse: Aes128EncryptResponse = await symmetricEncryptionService.aes128Encrypt(token, dataToEncrypt);
        assert.isNotNull(encryptResponse.encrypted);
        assert.isNotNull(encryptResponse.key);
        assert.isNotNull(encryptResponse.nonce);
    });

    it("should decrypt with AES128", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "Hello World";
        const encryptResponse: Aes128EncryptResponse = await symmetricEncryptionService.aes128Encrypt(token, dataToEncrypt);
        const decryptedResponse: Aes128DecryptResponse = await symmetricEncryptionService.aes128Decrypt(token, encryptResponse.encrypted, encryptResponse.key, encryptResponse.nonce);
        assert.equal(decryptedResponse.decrypted, dataToEncrypt);
    });

    it("should hash with MD5", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "Hello World";
        const hash: MD5HashResponse = await symmetricEncryptionService.md5Hash(token, dataToEncrypt);
        assert.isNotNull(hash.hash);
    });

    it("should verify with MD5", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "Hello World";
        const hash: MD5HashResponse = await symmetricEncryptionService.md5Hash(token, dataToEncrypt);
        const verify: MD5VerifyResponse = await symmetricEncryptionService.md5Verify(token, hash.hash, dataToEncrypt);
        assert.isTrue(verify.isValid);
    });

    it("should hash with Blake2", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "hello world";
        const hash: Blake2HashResponse = await symmetricEncryptionService.blake2Hash(token, 256, dataToEncrypt);
        assert.isNotNull(hash.hashedData);
        assert.isString(hash.hashedData);
        assert.equal(hash.hashedData, "muxoBnlFYRB+WUsfaoprDJKgy6ms9eXpPMoG94GBOws=");
    });

    it("should verify with Blake2", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "hello world";
        const dataToVerify = "hello world";
        const hash: Blake2HashResponse = await symmetricEncryptionService.blake2Hash(token, 512, dataToEncrypt);
        const verify: Blake2VerifyResponse = await symmetricEncryptionService.blake2Verify(token, 512, dataToVerify, hash.hashedData);
        assert.isNotNull(hash.hashedData);
        assert.isString(hash.hashedData);
        assert.equal(hash.hashedData, "Ahzth5kpbOylV4MquUGlC0oR+DR4zxQfUfkz9lOrn7zAWgN83b7QbjCb8zSULE5YzfGkbiN5EczX/Pl4fLx/0A==");
        assert.equal(verify.isValid, true);
    });

    it("should hash with SHA256", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "hello world";
        const hash: HashShaResponse = await symmetricEncryptionService.shaHash(token, dataToEncrypt, 256);
        assert.isNotNull(hash.hash);
        assert.notEqual(hash.hash, dataToEncrypt);
    });

    it("should hash with SHA512", async () => {
        const token: string = await tokenCache.getToken();
        const dataToEncrypt = "hello world";
        const hash: HashShaResponse = await symmetricEncryptionService.shaHash(token, dataToEncrypt, 512);
        assert.isNotNull(hash.hash);
        assert.notEqual(hash.hash, dataToEncrypt);
    });
});