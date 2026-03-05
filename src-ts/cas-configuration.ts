class CASConfiguration {
    /**
     * Indicates whether the SDK is running in development mode. If true, the SDK will use the local development server URL.
     * Default is false. We do not recommend setting this to true in production environments.
     */
    public isDevelopment: boolean = false;
    /**
     * Indicates whether the SDK is running in staging mode. If true, the SDK will use the staging server URL.
     * Default is false. We do not recommend setting this to true in production environments.
     */
    public isStaging: boolean = false;

    private _apiKey: string | null = null;
    private _url: string = "https://cryptographicapiservices.com";


    public get url(): string {
        if (this.isDevelopment && this.isStaging) {
            throw new Error("Both isDevelopment and isStaging cannot be true at the same time.");
        }

        if (this.isDevelopment) {
            this._url = "http://localhost:5000";
        } else if (this.isStaging) {
            this._url = "https://staging.cryptographicapiservices.com";
        }
        return this._url;
    }

    public set apiKey(value: string) {
        if (!value) {
            throw new Error("API key must be a allocated string.");
        }
        this._apiKey = value;
    }
}

export default new CASConfiguration();