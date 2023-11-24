import { assert } from "chai";
import { EASConfiguration } from "../src";
import { TokenService } from "../src/services/token-service";

describe("Token Service Tests", () => {
    EASConfiguration.apiKey = process.env.EasApiKey || '';
    const tokenService: TokenService = new TokenService();
    
    it("should get a token", async () => {
        const token: string = await tokenService.getToken();
        assert.isNotEmpty(token);
    });

    it("should get a refresh token", async () => {
        const token: string = await tokenService.getToken();
        const tokenRefresh: string = await tokenService.getRefreshToken(token);
        assert.isNotEmpty(tokenRefresh);
    });
});