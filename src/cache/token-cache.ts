import jwt_decode from "jwt-decode";
import { TokenService } from "../services/token-service";

export class TokenCache {
    public token!: string;
    public expirationTime!: number;
    public tokenService!: TokenService;

    public async setCache(): Promise<void> {
        this.tokenService = new TokenService();
        this.token = await this.tokenService.getToken();
        const decodedToken = jwt_decode(this.token);
        this.setDate(decodedToken);
    }

    public async getToken(): Promise<string> {
        if (!this.token) {
            await this.setCache();
        }
        let now = new Date();
        if (now.getSeconds() >= this.expirationTime) {
            this.token = await this.tokenService.getRefreshToken(this.token);
            const decodedToken = jwt_decode(this.token);
            this.setDate(decodedToken);
        }
        return this.token;
    }

    private setDate(decodedToken: any) {
        const expirationSeconds: number = decodedToken.exp;
        this.expirationTime = new Date(0).setSeconds(expirationSeconds);
    }
}