import { assert } from "chai";
import { EASConfiguration, ED25519DalekService, TokenCache } from "../src";
import { ED25519DalekKeyPair } from "../src/types/ed25519-dalek/ed25519-dalek-keypair";
import { ED25519DalekSignResponse } from "../src/types/ed25519-dalek/ed25519-dalek-sign-response";
import { ED25519DalekVerifyResponse } from "../src/types/ed25519-dalek/ed25519-dalek-verify-response";

describe("ED25519 Dalek Service Tests", () => {
    EASConfiguration.apiKey = process.env.EasApiKey || '';
    const tokenCache: TokenCache = new TokenCache();
    const ed25519DalekService: ED25519DalekService = new ED25519DalekService();

    it("should generate an ED25519 Key Pair", async () => {
        const token: string = await tokenCache.getToken();
        const response: ED25519DalekKeyPair = await ed25519DalekService.generateKeyPair(token);
        assert.isNotNull(response.keyPair);
    });

    it("should sign with ED25519 Dalek", async () => {
        const token: string = await tokenCache.getToken();
        const response: ED25519DalekKeyPair = await ed25519DalekService.generateKeyPair(token);
        const dataToSign = "Hello World";
        const signResponse: ED25519DalekSignResponse = await ed25519DalekService.sign(token, response.keyPair, dataToSign);
        assert.isNotNull(signResponse.publicKey);
        assert.isNotNull(signResponse.signature);
    });

    it("should verify with ED25519 Dalek", async () => {
        const token: string = await tokenCache.getToken();
        const response: ED25519DalekKeyPair = await ed25519DalekService.generateKeyPair(token);
        const dataToSign = "Hello World";
        const signResponse: ED25519DalekSignResponse = await ed25519DalekService.sign(token, response.keyPair, dataToSign);
        const verifyResponse: ED25519DalekVerifyResponse = await ed25519DalekService.verify(token, signResponse.publicKey, signResponse.signature, dataToSign);
        assert.isTrue(verifyResponse.isValid);
    });
});