import { setApiKey, setBaseUrl, sendBenchmarkToApi } from "../../index";


export class HttpWrapper {
    public static setBaseUrl(baseUrl: string) {
        if (!baseUrl) {
            throw new Error("Base URL must be a allocated string.");
        }
        setBaseUrl(baseUrl);
    }

    public static setApiKey(apiKey: string) {
        if (!apiKey) {
            throw new Error("API key must be a allocated string.");
        }
        const result = setApiKey(apiKey);
        if (!result) {
            throw new Error("Failed to set API key.");
        }
    }

    public static sendBenchmark(timespan: number, className: string, methodName: string) {
        if (!timespan || !className || !methodName) {
            throw new Error("Timespan, class name, and method name must be provided.");
        }
        sendBenchmarkToApi(timespan, className, methodName);
    }
}