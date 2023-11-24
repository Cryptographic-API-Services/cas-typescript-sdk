import { assert } from "chai";
import { EASConfiguration, HybridEncryptionService, TokenCache } from "../src";
import { AesRsaHybridEncryptResponse } from "../src/types/hybrid/aes-rsa-hybrid-encrypt-response";
import { NonceGenerator } from "../src/helpers/nonce-generator";
import { AesRsaHybridDecryptResponse } from "../src/types/hybrid/aes-rsa-hybrid-decrypt-response";

describe("Hybrid Encryption Service Tests", () => {
    EASConfiguration.apiKey = process.env.EasApiKey || '';
    const tokenCache: TokenCache = new TokenCache();
    const hybridEncryptionService: HybridEncryptionService = new HybridEncryptionService();

    it("should encrypt with hybrid encryption", async () => {
        const dataToEncrypt = "123456adsfcva";
        const token = await tokenCache.getToken();
        const nonce: string = new NonceGenerator().generateNonce();
        const encryptResponse: AesRsaHybridEncryptResponse = await hybridEncryptionService.encryptAESRsaHybrid(token, nonce, 4096, dataToEncrypt, 256);
        assert.isNotNull(encryptResponse.encryptedAesKey);
        assert.isNotNull(encryptResponse.encryptedData);
        assert.isNotNull(encryptResponse.privateKey);
        assert.isNotNull(encryptResponse.publicKey);
    });

    it("should decrypt with hybrid encryption", async () => {
        const dataToEncrypt = "123456adsfcva";
        const token = await tokenCache.getToken();
        const nonce: string = new NonceGenerator().generateNonce();
        const encryptResponse: AesRsaHybridEncryptResponse = await hybridEncryptionService.encryptAESRsaHybrid(token, nonce, 4096, dataToEncrypt, 128);
        const decryptResponse: AesRsaHybridDecryptResponse = await hybridEncryptionService.decryptAESRsaHybrid(token, encryptResponse.privateKey, encryptResponse.encryptedAesKey, nonce, encryptResponse.encryptedData, 128);
        assert.isNotNull(decryptResponse.decryptedData);
        assert.equal(dataToEncrypt, decryptResponse.decryptedData);
    });
});