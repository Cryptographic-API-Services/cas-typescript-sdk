import { assert } from "chai";
import { EASConfiguration, RsaService, TokenCache } from "../src";
import { RsaGetKeyPairResponse } from "../src/types/rsa/rsa-key-pair";
import { RsaSignWithKeyResponse } from "../src/types/rsa/rsa-sign-with-key-response";
import { RsaVerifyResponse } from "../src/types/rsa/rsa-verify-response";
import { RsaEncryptWithPublicResponse } from "../src/types/rsa/rsa-encrypt-with-public-response";
import { RsaDecryptWithoutPrivateKeyResponse } from "../src/types/rsa/rsa-decrypt-without-private-key-response";
import { RsaEncryptWithoutKeyResponse } from "../src/types/rsa/rsa-encrypt-without-key-response";

describe("Rsa Service Tests", () => {
    EASConfiguration.apiKey = process.env.EasApiKey || '';
    const tokenCache: TokenCache = new TokenCache();
    const rsaService: RsaService = new RsaService();
    
    it("should generate an RSA 4096 key pair", async () => {
        const token = await tokenCache.getToken();
        const keyPair: RsaGetKeyPairResponse = await rsaService.getRsaKeys(token, 4096);
        assert.isNotNull(keyPair.publicKey);
        assert.isNotNull(keyPair.privateKey);
    });

    it("should sign with an RSA key", async () => {
        const token = await tokenCache.getToken();
        const keyPair: RsaGetKeyPairResponse = await rsaService.getRsaKeys(token, 4096);
        const signRespoinse: RsaSignWithKeyResponse = await rsaService.signWithKey(token, keyPair.privateKey, "test");
        assert.isNotNull(signRespoinse.signature);
    });

    it("should verify an RSA signature", async () => {
        const token = await tokenCache.getToken();
        const dataToSign = "test";
        const keyPair: RsaGetKeyPairResponse = await rsaService.getRsaKeys(token, 4096);
        const signRespoinse: RsaSignWithKeyResponse = await rsaService.signWithKey(token, keyPair.privateKey, dataToSign);
        const verifyResponse: RsaVerifyResponse = await rsaService.verify(token, keyPair.publicKey, signRespoinse.signature, dataToSign);
        assert.isTrue(verifyResponse.isValid);
    });

    it("should encrypt with an RSA public key", async () => {
        const token = await tokenCache.getToken();
        const dataToSign = "test";
        const keyPair: RsaGetKeyPairResponse = await rsaService.getRsaKeys(token, 4096);
        const encryptResponse: RsaEncryptWithPublicResponse = await rsaService.encryptWithPublicKey(token, keyPair.publicKey, dataToSign);
        assert.isNotNull(encryptResponse.encryptedData);
    });

    it("should decrypt with an RSA private key", async () => {
        const token = await tokenCache.getToken();
        const dataToSign = "test";
        const keyPair: RsaGetKeyPairResponse = await rsaService.getRsaKeys(token, 4096);
        const encryptResponse: RsaEncryptWithPublicResponse = await rsaService.encryptWithPublicKey(token, keyPair.publicKey, dataToSign);
        const decryptResponse: RsaDecryptWithoutPrivateKeyResponse = await rsaService.decryptWithPrivateKey(token, keyPair.privateKey, encryptResponse.encryptedData);
        assert.equal(decryptResponse.decryptedData, dataToSign);
    });

    it("should encrypt without an RSA 4096 key", async () => {
        const token = await tokenCache.getToken();
        const dataToSign = "test";
        const encrypted: RsaEncryptWithoutKeyResponse = await rsaService.encryptWithoutKey(token, dataToSign, 4096);
        assert.isNotNull(encrypted.encryptedData);
        assert.isNotNull(encrypted.publicKey);
    });

    it("should decrypt without and RSA 4096 private key", async () => {
        const token = await tokenCache.getToken();
        const dataToSign = "test";
        const encrypted: RsaEncryptWithoutKeyResponse = await rsaService.encryptWithoutKey(token, dataToSign, 4096);
        const decryptedResponse: RsaDecryptWithoutPrivateKeyResponse = await rsaService.decryptWithoutKey(token, encrypted.publicKey, encrypted.encryptedData);
        assert.equal(dataToSign, decryptedResponse.decryptedData);
    });

    it("should sign without an RSA 4096 private key", async () => {
        const token = await tokenCache.getToken();
        const dataToSign = "test";
        const signedResponse: RsaSignWithKeyResponse = await rsaService.signWithoutKey(token, dataToSign, 4096);
        assert.isNotNull(signedResponse.signature);
    });
});