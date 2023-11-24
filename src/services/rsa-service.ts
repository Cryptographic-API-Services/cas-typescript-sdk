import fetch from 'node-fetch';
import { EASConfiguration } from "../EASConfiguration";
import { RsaGetKeyPairResponse } from '../types/rsa/rsa-key-pair';
import { RsaSignWithKeyResponse } from '../types/rsa/rsa-sign-with-key-response';
import { RsaSignWithKeyRequest } from '../types/rsa/rsa-sign-with-key-request';
import { RsaVerifyResponse } from '../types/rsa/rsa-verify-response';
import { RsaVerifyRequest } from '../types/rsa/rsa-verify-request';
import { RsaSignWithoutKeyRequest } from '../types/rsa/rsa-sign-without-key-request';
import { RsaDecryptWithoutPrivateKeyRequest } from '../types/rsa/rsa-decrypt-without-private-key-request';
import { RsaDecryptWithoutPrivateKeyResponse } from '../types/rsa/rsa-decrypt-without-private-key-response';
import { RsaEncryptWithoutKeyRequest } from '../types/rsa/rsa-encrypt-without-key-request';
import { RsaEncryptWithoutKeyResponse } from '../types/rsa/rsa-encrypt-without-key-response';
import { RsaDecryptRequest } from '../types/rsa/rsa-decrypt-request';
import { RsaDecryptResponse } from '../types/rsa/rsa-decrypt-response';
import { RsaEncryptWithPublicRequest } from '../types/rsa/rsa-encrypt-with-public-request';
import { RsaEncryptWithPublicResponse } from '../types/rsa/rsa-encrypt-with-public-response';
import { RsaSignWithoutKeyResponse } from '../types/rsa/rsa-sign-without-key-response';

export class RsaService {
    
    public async getRsaKeys(token: string, keySize: number): Promise<RsaGetKeyPairResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to get an RSA key pair");
        }
        if (!keySize) {
            throw new Error("Please pass in a valid key size to get an RSA key pair");
        }
        let url: string = EASConfiguration.baseUrl + `Rsa/GetKeyPair?keySize=${keySize.toString()}`;
        let response = await fetch(url, { headers: { "Authorization": `Bearer ${token}` } });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }

    public async signWithKey(token: string, privateKey: string, dataToSign: string): Promise<RsaSignWithKeyResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to get sign with RSA");
        }
        if (!privateKey) {
            throw new Error("Please pass in a valid private key to sign with RSA");
        }
        if (!dataToSign) {
            throw new Error("Please pass in a valid data to sign with RSA");
        }
        let url: string = EASConfiguration.baseUrl + `Rsa/SignWithKey`;
        let requestBody: RsaSignWithKeyRequest = new RsaSignWithKeyRequest(dataToSign, privateKey);
        let requestBodySeralized: string = JSON.stringify(requestBody);
        let request = await fetch(url, {
            method: "POST",
            body: requestBodySeralized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }

    public async verify(token: string, publicKey: string, signature: string, originalData: string): Promise<RsaVerifyResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to verify with RSA");
        }
        if (!publicKey) {
            throw new Error("Please pass in a valid public key to verify with RSA");
        }
        if (!signature) {
            throw new Error("Please pass in a valid signature to verify with RSA");
        }
        if (!originalData) {
            throw new Error("Please pass in a valid original data string to verify with RSA");
        }
        let url: string = EASConfiguration.baseUrl + `Rsa/Verify`;
        let requestBody: RsaVerifyRequest = new RsaVerifyRequest(signature, publicKey, originalData);
        let requestBodySeralized: string = JSON.stringify(requestBody);
        let response = await fetch(url, {
            method: "POST",
            body: requestBodySeralized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }

    public async encryptWithPublicKey(token: string, publicKey: string, dataToEncrypt: string): Promise<RsaEncryptWithPublicResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to encrypt with RSA");
        }
        if (!publicKey) {
            throw new Error("Please pass in a valid public key to encrypt with RSA");
        }
        if (!dataToEncrypt) {
            throw new Error("Please pass in a valid data to encrypt with RSA");
        }
        let url: string = EASConfiguration.baseUrl + `Rsa/EncryptWithPublic`;
        let requestBody: RsaEncryptWithPublicRequest = new RsaEncryptWithPublicRequest(publicKey, dataToEncrypt);
        let requestBodySeralized: string = JSON.stringify(requestBody);
        let response = await fetch(url, {
            method: "POST",
            body: requestBodySeralized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }

    public async decryptWithPrivateKey(token: string, privateKey: string, dataToDecrypt: string): Promise<RsaDecryptResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to decrypt with RSA");
        }
        if (!privateKey) {
            throw new Error("Please pass in a valid private key to decrypt with RSA");
        }
        if (!dataToDecrypt) {
            throw new Error("Please pass in a valid data to decrypt with RSA");
        }
        let url: string = EASConfiguration.baseUrl + `Rsa/Decrypt`;
        let requestBody: RsaDecryptRequest = new RsaDecryptRequest(privateKey, dataToDecrypt);
        let requestBodySeralized: string = JSON.stringify(requestBody);
        let response = await fetch(url, {
            method: "POST",
            body: requestBodySeralized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }

    public async encryptWithoutKey(token: string, dataToEncrypt: string, keySize: number): Promise<RsaEncryptWithoutKeyResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to encrypt with RSA");
        }
        if (!dataToEncrypt) {
            throw new Error("Please pass in a valid data to encrypt with RSA");
        }
        if (keySize !== 1024 && keySize !== 2048 && keySize !== 4096 ) {
            throw new Error("Please pass in a valid key size to encrypt with RSA");
        }
        let url: string = EASConfiguration.baseUrl + `Rsa/EncryptWithoutPublic`;
        let requestBody: RsaEncryptWithoutKeyRequest = new RsaEncryptWithoutKeyRequest(dataToEncrypt, keySize);
        let requestBodySeralized = JSON.stringify(requestBody);
        let response = await fetch(url, {
            method: "POST",
            body: requestBodySeralized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }

    public async decryptWithoutKey(token: string, publicKey: string, encryptedData: string): Promise<RsaDecryptWithoutPrivateKeyResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to decrypt with RSA");
        }
        if (!publicKey) {
            throw new Error("Please pass in a valid public key to decrypt with RSA");
        }
        if (!encryptedData) {
            throw new Error("Please pass in a valid encrypted data to decrypt with RSA");
        }
        let url: string = EASConfiguration.baseUrl + `Rsa/DecryptWithStoredPrivate`;
        let requestBody: RsaDecryptWithoutPrivateKeyRequest = new RsaDecryptWithoutPrivateKeyRequest(publicKey, encryptedData);
        let requestBodySeralized = JSON.stringify(requestBody);
        let response = await fetch(url, {
            method: "POST",
            body: requestBodySeralized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }

    public async signWithoutKey(token: string, dataToSign: string, keySize: number): Promise<RsaSignWithoutKeyResponse> {
        if (!token) {
            throw new Error("Please pass in a valid token to sign with RSA");
        }
        if (!dataToSign) {
            throw new Error("Please pass in a valid data to sign with RSA");
        }
        if (keySize !== 1024 && keySize !== 2048 && keySize !== 4096 ) {
            throw new Error("Please pass in a valid key size to sign with RSA");
        }
        let url: string = EASConfiguration.baseUrl + `Rsa/SignWithoutKey`;
        let requestBody: RsaSignWithoutKeyRequest = new RsaSignWithoutKeyRequest(dataToSign, keySize);
        let requestBodySeralized = JSON.stringify(requestBody);
        let response = await fetch(url, {
            method: "POST",
            body: requestBodySeralized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(await response.text());
        }
    }
}