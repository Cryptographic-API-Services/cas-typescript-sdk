import fetch from 'node-fetch';
import { EASConfiguration } from '../EASConfiguration';
import { ED25519DalekKeyPair } from '../types/ed25519-dalek/ed25519-dalek-keypair';
import { ED25519DalekSignResponse } from '../types/ed25519-dalek/ed25519-dalek-sign-response';
import { ED25519DalekSignRequest } from '../types/ed25519-dalek/ed25519-dalek-sign-request';
import { ED25519DalekVerifyResponse } from '../types/ed25519-dalek/ed25519-dalek-verify-response';
import { ED25519DalekVerifyRequest } from '../types/ed25519-dalek/ed25519-dalek-verify-request';

export class ED25519DalekService {
    
    public async generateKeyPair(token: string): Promise<ED25519DalekKeyPair> {
        if (!token) {
            throw new Error("Please pass in a valid token to get an ED25519 key pair");
        }
        let url: string = EASConfiguration.baseUrl + "ED25519/KeyPair";
        let response = await fetch(url, { headers: { "Authorization": `Bearer ${token}` } });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }

    public async sign(token: string, keyPair: string, dataToSign: string): Promise<ED25519DalekSignResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to sign a message with ED25519");
        }
        if (!keyPair) {
            throw new Error("Please pass in a valid key pair to sign a message with ED25519");
        }
        if (!dataToSign) {
            throw new Error("Please pass in a string message to sign with ED25519");
        }
        let url: string = EASConfiguration.baseUrl + "ED25519/SignWithKeyPair";
        let requestBody: ED25519DalekSignRequest = new ED25519DalekSignRequest(keyPair, dataToSign);
        let requestBodySerialized: string = JSON.stringify(requestBody);
        let response = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" }
        });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }

    public async verify(token: string, publicKey: string, signature: string, dataToVerify: string): Promise<ED25519DalekVerifyResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to verify a message with ED25519");
        }
        if (!publicKey) {
            throw new Error("Please pass in a valid public key to verify a message with ED25519");
        }
        if (!signature) {
            throw new Error("Please pass in a valid signature to verify a message with ED25519");
        }
        if (!dataToVerify) {
            throw new Error("Please pass in a string message to verify with ED25519");
        }
        let url: string = EASConfiguration.baseUrl + "ED25519/VerifyWithPublicKey";
        let requestBody: ED25519DalekVerifyRequest = new ED25519DalekVerifyRequest(publicKey, signature, dataToVerify);
        let requestBodySerialized: string = JSON.stringify(requestBody);
        let response = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" }
        });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }
}