import { assert } from "chai";
import { EASConfiguration, SignatureService, TokenCache } from "../src";
import { SHA512RsaSignResponse } from "../src/types/signatures/sha512-rsa-sign-response";
import { SHA512ED25519DalekSignResponse } from "../src/types/signatures/sha-512-ed25519-dalek-sign-response";
import { SHA512ED25519DalekVerifyResponse } from "../src/types/signatures/sha-512-ed25519-dalek-verify-response";
import { HmacSignResponse } from "../src/types/signatures/hmac-sign-response";
import { HmacVerifyResponse } from "../src/types/signatures/hmac-verify-response";

describe("Signature Service Tests", () => {
    EASConfiguration.apiKey = process.env.EasApiKey || '';
    const tokenCache: TokenCache = new TokenCache();
    const signatureService = new SignatureService();


    it("should perform a SHA512 RSA Sign", async () => {
        const token: string = await tokenCache.getToken();
        const dataToSign: string = "This is a test";
        const response: SHA512RsaSignResponse = await signatureService.sha512RsaSign(token, dataToSign, 4096);
        assert.isNotNull(response.privateKey);
        assert.isNotNull(response.publicKey);
        assert.isNotNull(response.signature);
    });

    it("should perform a SHA512 RSA Verify", async () => {
        const token: string = await tokenCache.getToken();
        const dataToSign: string = "This is a test";
        const response: SHA512RsaSignResponse = await signatureService.sha512RsaSign(token, dataToSign, 4096);
        const verifyResponse = await signatureService.sha512RsaVerify(token, response.publicKey, dataToSign, response.signature);
        assert.isTrue(verifyResponse.isValid);
    });

    it("should perform a SHA512 ED25519 Sign", async () => {
        const token: string = await tokenCache.getToken();
        const dataToSign: string = "This is a test";
        const response: SHA512ED25519DalekSignResponse = await signatureService.sha512ED25519DalekSign(token, dataToSign);
        assert.isNotNull(response.publicKey);
        assert.isNotNull(response.signature);
    });

    it ("should perform a SHA512 ED25519 Verify", async () => {
        const token: string = await tokenCache.getToken();
        const dataToSign: string = "This is a test";
        const response: SHA512ED25519DalekSignResponse = await signatureService.sha512ED25519DalekSign(token, dataToSign);
        const verifyResponse: SHA512ED25519DalekVerifyResponse = await signatureService.sha512ED25519DalekVerify(token, response.publicKey, dataToSign, response.signature);
        assert.isTrue(verifyResponse.isValid);
    });

    it("should perform a HMAC Sign", async () => {
        const token: string = await tokenCache.getToken();
        const key: string = "ThisIsMyKey";
        const dataToSign: string = "This is a test";
        const response: HmacSignResponse = await signatureService.hmacSign(token, key, dataToSign);
        assert.isNotNull(response.signature);
    });

    it("should perform a HMAC Verify", async () => {
        const token: string = await tokenCache.getToken();
        const key: string = "ThisIsMyKey";
        const dataToSign: string = "This is a test";
        const response: HmacSignResponse = await signatureService.hmacSign(token, key, dataToSign);
        const verifyResponse: HmacVerifyResponse = await signatureService.hmacVerify(token, key, dataToSign, response.signature);
        assert.isTrue(verifyResponse.isValid);
    });

    it("should sign with Blake2 ED25519 Dalek", async () => {
        const token: string = await tokenCache.getToken();
        const hashSize: number = 256;
        const dataToSign: string = "123SignThisData";
        const response = await signatureService.blake2ED25519DalekSign(token, hashSize, dataToSign);
        assert.isNotNull(response.publicKey);
        assert.isNotNull(response.signature);
        assert.notEqual(dataToSign, response.signature);
    });

    it("should verify pass with Blake2 ED25519 Dalek Verfiy", async () => {
        const token: string = await tokenCache.getToken();
        const hashSize: number = 512;
        const dataToSign: string = "123SignThisData";
        const response = await signatureService.blake2ED25519DalekSign(token, hashSize, dataToSign);
        const verifyResponse = await signatureService.blake2ED25519DalekVerify(token, hashSize, response.publicKey, dataToSign, response.signature);
        assert.isTrue(verifyResponse.isValid);
    }); 

    it("should verify fail with Blake2 ED25519 Dalek Verfiy", async () => {
        const token: string = await tokenCache.getToken();
        const hashSize: number = 512;
        const dataToSign: string = "123SignThisData";
        const response = await signatureService.blake2ED25519DalekSign(token, hashSize, dataToSign);
        const verifyResponse = await signatureService.blake2ED25519DalekVerify(token, hashSize, response.publicKey, "NotTheRightString", response.signature);
        assert.isFalse(verifyResponse.isValid);
    }); 

    it("should sign with Blake2 RSA", async () => {
        const token: string = await tokenCache.getToken();
        const hashSize: number = 256;
        const dataToSign: string = "123SignThisData";
        const response = await signatureService.blake2RSASign(token, hashSize, 4096, dataToSign);
        assert.isNotNull(response.privateKey);
        assert.isNotNull(response.publicKey);
        assert.isNotNull(response.signature);
    });

    it("should verify pass with Blake2 RSA", async () => {
        const token: string = await tokenCache.getToken();
        const hashSize: number = 256;
        const dataToSign: string = "123SignThisData";
        const response = await signatureService.blake2RSASign(token, hashSize, 4096, dataToSign);
        const verfiy = await signatureService.blake2RSAVerify(token, hashSize, response.publicKey, response.signature, dataToSign);
        assert.isTrue(verfiy.isValid);
    });

    it("should verify fail with Blake2 RSA", async () => {
        const token: string = await tokenCache.getToken();
        const hashSize: number = 256;
        const dataToSign: string = "123SignThisData";
        const response = await signatureService.blake2RSASign(token, hashSize, 4096, dataToSign);
        const verfiy = await signatureService.blake2RSAVerify(token, hashSize, response.publicKey, response.signature, "123asd");
        assert.isFalse(verfiy.isValid);
    });
});