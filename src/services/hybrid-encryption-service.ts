import fetch from 'node-fetch';
import { AesRsaHybridEncryptResponse } from '../types/hybrid/aes-rsa-hybrid-encrypt-response';
import { AesRsaHybridEncryptRequest } from '../types/hybrid/aes-rsa-hybrid-encrypt-request';
import { EASConfiguration } from '../EASConfiguration';
import { AesRsaHybridDecryptResponse } from '../types/hybrid/aes-rsa-hybrid-decrypt-response';
import { AesRsaHybridDecryptRequest } from '../types/hybrid/aes-rsa-hybrid-decrypt-request';

export class HybridEncryptionService {

    public async encryptAESRsaHybrid(token: string, nonceKey: string, keySize: number, dataToEncrypt: string, aesType: number): Promise<AesRsaHybridEncryptResponse> {
        if (aesType !== 128 && aesType !== 256) {
            throw new Error("AES Encryption type is not supported");
        }
        if (!token) {
            throw new Error("Token is required to perform AES/RSA Hybrid Encryption");
        }
        if (!nonceKey) {
            throw new Error("NonceKey is required to perform AES/RSA Hybrid Encryption");
        }
        if (keySize !== 1024 && keySize !== 2048 && keySize !== 4096) {
            throw new Error("Valid KeySize is required to perform AES/RSA Hybrid Encryption");
        }
        if (!dataToEncrypt) {
            throw new Error("Data to encrypt is required to perform AES/RSA Hybrid Encryption");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/EncryptAESRSAHybrid";
        let requestBody: AesRsaHybridEncryptRequest = new AesRsaHybridEncryptRequest(nonceKey, keySize, dataToEncrypt, aesType);
        let requestBodySeralized = JSON.stringify(requestBody);
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

    public async decryptAESRsaHybrid(token: string, rsaPrivate: string, encryptedAesKey: string, nonceKey: string, encryptedData: string, aesType: number): Promise<AesRsaHybridDecryptResponse> {
        if (aesType !== 128 && aesType !== 256) {
            throw new Error("AES decryption type is not supported");
        }
        if (!token) {
            throw new Error("Token is required to perform AES/RSA Hybrid Encryption");
        }
        if (!rsaPrivate) {
            throw new Error("RSA Private Key is required to perform AES/RSA Hybrid Encryption");
        }
        if (!encryptedAesKey) {
            throw new Error("Encrypted AES Key is required to perform AES/RSA Hybrid Encryption");
        }
        if (!nonceKey) {
            throw new Error("NonceKey is required to perform AES/RSA Hybrid Encryption");
        }
        if (!encryptedData) {
            throw new Error("Encrypted Data is required to perform AES/RSA Hybrid Encryption");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/DecryptAESRSAHybrid";
        let requestBody: AesRsaHybridDecryptRequest = new AesRsaHybridDecryptRequest(rsaPrivate, encryptedAesKey, nonceKey, encryptedData, aesType);
        let requestBodySeralized = JSON.stringify(requestBody);
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
}