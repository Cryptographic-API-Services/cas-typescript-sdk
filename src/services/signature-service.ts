import fetch from 'node-fetch';
import { EASConfiguration } from '../EASConfiguration';
import { SHA512RsaSignResponse } from '../types/signatures/sha512-rsa-sign-response';
import { SHA512RsaSignRequest } from '../types/signatures/sha512-rsa-sign-request';
import { SHA512RsaVerifyResponse } from '../types/signatures/sha-512-rsa-verify-response';
import { SHA512RsaVerfiyRequest } from '../types/signatures/sha512-rsa-verify-request';
import { SHA512ED25519DalekSignResponse } from '../types/signatures/sha-512-ed25519-dalek-sign-response';
import { SHA512ED25519DalekSignRequest } from '../types/signatures/sha-512-ed25519-dalek-sign-request';
import { SHA512ED25519DalekVerifyResponse } from '../types/signatures/sha-512-ed25519-dalek-verify-response';
import { SHA512ED25519DalekVerifyRequest } from '../types/signatures/sha-512-ed25519-dalek-verify-request';
import { HmacSignResponse } from '../types/signatures/hmac-sign-response';
import { HmacSignRequest } from '../types/signatures/hmac-sign-request';
import { HmacVerifyResponse } from '../types/signatures/hmac-verify-response';
import { HmacVerifyRequest } from '../types/signatures/hmac-verify-request';
import { Blake2ED25519DalekVerifyResponse } from '../types/signatures/blake2-ed25519-dalek-verify-response';
import { Blake2ED25519DalekVerifyRequest } from '../types/signatures/blake2-ed25519-dalek-verify-request';
import { Blake2ED25519DalekSignResponse } from '../types/signatures/blake2-ed25519-dalek-sign-response';
import { Blake2ED25519DalekSignRequest } from '../types/signatures/blake2-ed25519-dalek-sign-request';
import { Blake2RsaSignRequest } from '../types/signatures/blake2-rsa-sign-request';
import { Blake2RsaSignResponse } from '../types/signatures/blake2-rsa-sign-response';
import { Blake2RsaVerifyResponse } from '../types/signatures/blake2-rsa-verify-response';
import { Blake2RsaVerifyRequest } from '../types/signatures/blake2-rsa-verify-request';

export class SignatureService {

    public async blake2RSAVerify(token: string, blake2HashSize: number, publicKey: string, signature: string, originalData: string): Promise<Blake2RsaVerifyResponse> {
        if (!token) {
            throw new Error("Token is required to verify with Blake2 RSA Digitial Signature");
        }
        if (blake2HashSize != 256 && blake2HashSize != 512) {
            throw new Error("Blake2 Hash size not supported");
        }
        if (!publicKey) {
            throw new Error("Public key is required to verify with Blake2 RSA Digitial Signature");
        }
        if (!signature) {
            throw new Error("Signature is required to verify with Blake2 RSA Digitial Signature");
        }
        if (!originalData) {
            throw new Error("Original data is required to verify with Blake2 RSA Digitial Signature");
        }
        let url: string = EASConfiguration.baseUrl + "Signature/Blake2RsaVerify";
        let requestBody: Blake2RsaVerifyRequest = new Blake2RsaVerifyRequest(blake2HashSize, publicKey, signature, originalData);
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

    public async blake2RSASign(token: string, hashSize: number, rsaKeySize: number, dataToSign: string): Promise<Blake2RsaSignResponse> {
        if (!token) {
            throw new Error("Token is required to sign with Blake2 RSA Digitial Signature");
        }
        if (hashSize != 256 && hashSize != 512) {
            throw new Error("Blake2 Hash size not supported");
        }
        if (rsaKeySize !== 1024 && rsaKeySize !== 2048 && rsaKeySize !== 4096) {
            throw new Error("RSA Key Size not supported with Blake2 RSA Digitial Signature");
        }
        if (!dataToSign) {
            throw new Error("Data is required to sign with Blake2 RSA Digitial Signature");
        }
        let url: string = EASConfiguration.baseUrl + "Signature/Blake2RsaSign";
        let requestBody: Blake2RsaSignRequest = new Blake2RsaSignRequest(hashSize, rsaKeySize, dataToSign);
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

    public async blake2ED25519DalekSign(token: string, hashSize: number, dataToSign: string): Promise<Blake2ED25519DalekSignResponse> {
        if (!token) {
            throw new Error("Token is required to sign with Blake2 ED25519 Digitial Signature");
        }
        if (hashSize != 256 && hashSize != 512) {
            throw new Error("Blake2 Hash size not supported");
        }
        if (!dataToSign) {
            throw new Error("Data to sign is required to sign with Blake2 ED25519 Digitial Signature");
        }
        let url: string = EASConfiguration.baseUrl + "Signature/Blake2ED25519DalekSign";
        let requestBody: Blake2ED25519DalekSignRequest = new Blake2ED25519DalekSignRequest(hashSize, dataToSign);
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


    public async blake2ED25519DalekVerify(token: string, hashSize: number, publicKey: string, dataToVerify: string, signature: string): Promise<Blake2ED25519DalekVerifyResponse> {
        if (!token) {
            throw new Error("Token is required to verify with Blake2 ED25519 Digitial Signature");
        }
        if (hashSize != 256 && hashSize != 512) {
            throw new Error("Blake2 Hash size not supported");
        }
        if (!publicKey) {
            throw new Error("Public key is required to verify with Blake2 ED25519 Digitial Signature");
        }
        if (!dataToVerify) {
            throw new Error("Data to verify is required to verify with Blake2 ED25519 Digitial Signature");
        }
        if (!signature) {
            throw new Error("Signature is required to verify with Blake2 ED25519 Digitial Signature");
        }
        let url: string = EASConfiguration.baseUrl + "Signature/Blake2ED25519DalekVerify";
        let requestBody: Blake2ED25519DalekVerifyRequest = new Blake2ED25519DalekVerifyRequest(hashSize, publicKey, dataToVerify, signature);
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

    public async sha512RsaSign(token: string, dataToSign: string, keySize: number): Promise<SHA512RsaSignResponse> {
        if (!token) {
            throw new Error('Token is required to sign data with SHA512-RSA');
        }
        if (!dataToSign) {
            throw new Error('Data to sign is required to sign data with SHA512-RSA');
        }
        if (keySize !== 1024 && keySize !== 2048 && keySize !== 4096) {
            throw new Error('Key size must be 1024, 2048, or 4096');
        }
        let url: string = EASConfiguration.baseUrl + "Signature/SHA512SignedRSA";
        let requestBody: SHA512RsaSignRequest = new SHA512RsaSignRequest(dataToSign, keySize);
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

    public async sha512RsaVerify(token: string, publicKey: string, originalData: string, signature: string): Promise<SHA512RsaVerifyResponse> {
        if (!token) {
            throw new Error("Token is required to verify data with SHA512-RSA");
        }
        if (!publicKey) {
            throw new Error("Data to verify is required to verify data with SHA512-RSA");
        }
        if (!originalData) {
            throw new Error("Original data is required to verify data with SHA512-RSA");
        }
        if (!signature) {
            throw new Error("Signature is required to verify data with SHA512-RSA");
        }
        let url: string = EASConfiguration.baseUrl + "Signature/SHA512SignedRSAVerify";
        let requestBody: SHA512RsaVerfiyRequest = new SHA512RsaVerfiyRequest(publicKey, originalData, signature);
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

    public async sha512ED25519DalekSign(token: string, dataToSign: string): Promise<SHA512ED25519DalekSignResponse> {
        if (!token) {
            throw new Error("Token is required to sign data with SHA512-ED25519-Dalek");
        }
        if (!dataToSign) {
            throw new Error("Data to sign is required to sign data with SHA512-ED25519-Dalek");
        }
        let url: string = EASConfiguration.baseUrl + "Signature/SHA512ED25519DalekSign";
        let requestBody: SHA512ED25519DalekSignRequest = new SHA512ED25519DalekSignRequest(dataToSign);
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

    public async sha512ED25519DalekVerify(token: string, publicKey: string, originalData: string, signature: string): Promise<SHA512ED25519DalekVerifyResponse> {
        if (!token) {
            throw new Error("Token is required to verify data with SHA512-ED25519-Dalek");
        }
        if (!publicKey) {
            throw new Error("Public key is required to verify data with SHA512-ED25519-Dalek");
        }
        if (!originalData) {
            throw new Error("Original data is required to verify data with SHA512-ED25519-Dalek");
        }
        if (!signature) {
            throw new Error("Signature is required to verify data with SHA512-ED25519-Dalek");
        }
        let url: string = EASConfiguration.baseUrl + "Signature/SHA512ED25519DalekVerify";
        let requestBody: SHA512ED25519DalekVerifyRequest = new SHA512ED25519DalekVerifyRequest(signature, originalData, publicKey);
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

    public async hmacSign(token: string, key: string, message: string): Promise<HmacSignResponse> {
        if (!token) {
            throw new Error("Token is required to sign data with HMAC");
        }
        if (!key) {
            throw new Error("Key is required to sign data with HMAC");
        }
        if (!message) {
            throw new Error("Message is required to sign data with HMAC");
        }
        let url: string = EASConfiguration.baseUrl + "Signature/HMACSign";
        let requestBody: HmacSignRequest = new HmacSignRequest(key, message);
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

    public async hmacVerify(token: string, key: string, message: string, signature: string): Promise<HmacVerifyResponse> {
        if (!token) {
            throw new Error("Token is required to verify data with HMAC");
        }
        if (!key) {
            throw new Error("Key is required to verify data with HMAC");
        }
        if (!message) {
            throw new Error("Message is required to verify data with HMAC");
        }
        if (!signature) {
            throw new Error("Signature is required to verify data with HMAC");
        }
        let url: string = EASConfiguration.baseUrl + "Signature/HMACVerify";
        let requestBody: HmacVerifyRequest = new HmacVerifyRequest(key, message, signature);
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