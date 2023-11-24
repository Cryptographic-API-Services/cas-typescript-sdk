import fetch from 'node-fetch';
import { EASConfiguration } from "../EASConfiguration";
import { GetTokenResponse } from "../types/get-token-response";
import { Response } from 'node-fetch';

export class TokenService {

    public async getToken(): Promise<string> {
        if (!EASConfiguration.apiKey) {
            throw new Error("API Key is not set");
        }
        let url: string = EASConfiguration.baseUrl + "Token";
        let token: Response = await fetch(url, { headers: { "ApiKey" : EASConfiguration.apiKey } });
        let json: GetTokenResponse  = await token.json() as GetTokenResponse;
        return json.token;
    }

    public async getRefreshToken(oldToken: string): Promise<string> {
        let token = "";
        if (!EASConfiguration.apiKey) {
            throw new Error("API Key is not set");
        }
        if (!oldToken) {
            throw new Error("Please pass in an expired token to replace the existing token");
        }
        let url: string = EASConfiguration.baseUrl + "Token/RefreshToken";
        let tokenResponse: Response = await fetch(url, { headers: { "ApiKey" : EASConfiguration.apiKey, "Authorization": `Bearer ${oldToken}` } });
        let json: any = await tokenResponse.json();
        return json.token;
    }
}