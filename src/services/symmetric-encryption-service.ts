import fetch from 'node-fetch';
import { EASConfiguration } from "../EASConfiguration";
import { Aes256EncryptRequest } from "../types/symmetric/aes-256-encrypt-request";
import { Aes256EncryptResponse } from "../types/symmetric/aes-256-encrypt-response";
import { Aes256DecryptResponse } from '../types/symmetric/aes-256-decrypt-response';
import { Aes256DecryptRequest } from '../types/symmetric/aes-256-decrypt-request';
import { Aes128EncryptResponse } from '../types/symmetric/aes-128-encrypt-response';
import { Aes128EncryptRequest } from '../types/symmetric/aes-128-encrypt-request';
import { Aes128DecryptResponse } from '../types/symmetric/aes-128-decrypt-response';
import { Aes128DecryptRequest } from '../types/symmetric/aes-128-decrypt-request';
import { MD5HashResponse } from '../types/symmetric/md5-hash-response';
import { MD5HashRequest } from '../types/symmetric/md5-hash-request';
import { MD5VerifyResponse } from '../types/symmetric/md5-verify-response';
import { MD5VerifyRequest } from '../types/symmetric/md5-verify-request';
import { NonceGenerator } from '../helpers/nonce-generator';
import { Blake2HashRequest } from '../types/symmetric/blake2/blake2-hash-request';
import { Blake2HashResponse } from '../types/symmetric/blake2/blake2-hash-response';
import { Blake2VerifyRequest } from '../types/symmetric/blake2/blake2-verify-request';
import { Blake2VerifyResponse } from '../types/symmetric/blake2/blake2-verify-response';
import { HashShaResponse } from '../types/symmetric/hash-sha-response';
import { HashShaRequest } from '../types/symmetric/hash-sha-request';

export class SymmetricEncryptionService {
    nonceGenerator: NonceGenerator;

    constructor() {
        this.nonceGenerator = new NonceGenerator();
    }

    public async shaHash(token: string, dataToEncrypt: string, hashSize: number): Promise<HashShaResponse> {
        if (!token) {
            throw new Error("Token is required to hash with SHA");
        }
        if (!dataToEncrypt) {
            throw new Error("Data to encrypt is required to hash with SHA");
        }
        if (hashSize !== 256 && hashSize !== 512) {
            throw new Error("Hash size must be 256 or 512 for SHA");
        }
        let url: string = "";
        if (hashSize === 256) {
            url = EASConfiguration.baseUrl + "Encryption/EncryptSHA512";
        } else if (hashSize === 512) {
            url = EASConfiguration.baseUrl + "Encryption/EncryptSHA256";
        }
        let requestBody: HashShaRequest = new HashShaRequest(dataToEncrypt);
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

    public async aes256Encrypt(token: string, dataToEncrypt: string): Promise<Aes256EncryptResponse> {
        if (!token) {
            throw new Error("Token is required to encrypt with AES256-GCM");
        }
        if (!dataToEncrypt) {
            throw new Error("Data to encrypt is required to encrypt with AES256-GCM");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/EncryptAES";
        let requestBody: Aes256EncryptRequest = new Aes256EncryptRequest(dataToEncrypt, this.nonceGenerator.generateNonce(), 256);
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

    public async aes256Decrypt(token: string, dataToDecrypt: string, key: string, nonce: string): Promise<Aes256DecryptResponse> {
        if (!token) {
            throw new Error("Token is required to decrypt with AES256-GCM");
        }
        if (!dataToDecrypt) {
            throw new Error("Data to decrypt is required to decrypt with AES256-GCM");
        }
        if (!key) {
            throw new Error("Key is required to decrypt with AES256-GCM");
        }
        if (!nonce) {
            throw new Error("Nonce is required to decrypt with AES256-GCM");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/DecryptAES";
        let requestBody: Aes256DecryptRequest = new Aes256DecryptRequest(dataToDecrypt, nonce, key, 256);
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

    public async aes128Encrypt(token: string, dataToEncrypt: string): Promise<Aes128EncryptResponse> {
        if (!token) {
            throw new Error("Token is required to encrypt with AES128-GCM");
        }
        if (!dataToEncrypt) {
            throw new Error("Data to encrypt is required to encrypt with AES128-GCM");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/EncryptAES";
        let requestBody: Aes128EncryptRequest = new Aes128EncryptRequest(dataToEncrypt, this.nonceGenerator.generateNonce(), 128);
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

    public async aes128Decrypt(token: string, dataToDecrypt: string, key: string, nonce: string): Promise<Aes128DecryptResponse> {
        if (!token) {
            throw new Error("Token is required to decrypt with AES128-GCM");
        }
        if (!dataToDecrypt) {
            throw new Error("Data to decrypt is required to decrypt with AES128-GCM");
        }
        if (!key) {
            throw new Error("Key is required to decrypt with AES128-GCM");
        }
        if (!nonce) {
            throw new Error("Nonce is required to decrypt with AES128-GCM");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/DecryptAES";
        let requestBody: Aes128DecryptRequest = new Aes128DecryptRequest(dataToDecrypt, nonce, key, 128);
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

    public async md5Hash(token: string, dataToHash: string): Promise<MD5HashResponse> {
        if (!token) {
            throw new Error("Token is required to hash with MD5");
        }
        if (!dataToHash) {
            throw new Error("Data to hash is required to hash with MD5");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/HashMD5";
        let requestBody: MD5HashRequest = new MD5HashRequest(dataToHash);
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

    public async md5Verify(token: string, hashToVerify: string, toHash: string): Promise<MD5VerifyResponse> {
        if (!token) {
            throw new Error("Token is required to verify hash with MD5");
        }
        if (!hashToVerify) {
            throw new Error("Hash to verify is required to verify hash with MD5");
        }
        if (!toHash) {
            throw new Error("Data to hash is required to verify hash with MD5");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/VerifyMD5";
        let requestBody: MD5VerifyRequest = new MD5VerifyRequest(hashToVerify, toHash);
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

    public async blake2Hash(token: string, hashSize: number, toHash: string): Promise<Blake2HashResponse> {
        if (!token) {
            throw new Error("Token is required to hash with Blake2");
        }
        if (hashSize !== 256 && hashSize !== 512) {
            throw new Error("Hash size must be 256 or 512 for Blake2");
        }
        if (!toHash) {
            throw new Error("Data to hash is required to hash with Blake2");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/Blake2";
        let requestBody: Blake2HashRequest = new Blake2HashRequest(hashSize, toHash);
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

    public async blake2Verify(token: string, hashSize: number, dataToVerify: string, hash: string): Promise<Blake2VerifyResponse> {
        if (!token) {
            throw new Error("Token is required to verify hash with Blake2");
        }
        if (hashSize !== 256 && hashSize !== 512) {
            throw new Error("Hash size must be 256 or 512 for Blake2");
        }
        if (!dataToVerify) {
            throw new Error("Data to verify is required to verify hash with Blake2");
        }
        if (!hash) {
            throw new Error("Hash is required to verify hash with Blake2");
        }
        let url: string = EASConfiguration.baseUrl + "Encryption/Blake2Verify";
        let requestBody: Blake2VerifyRequest = new Blake2VerifyRequest(hashSize, dataToVerify, hash);
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