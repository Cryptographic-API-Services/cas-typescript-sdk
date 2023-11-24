import fetch from 'node-fetch';
import { EASConfiguration } from '../EASConfiguration';
import { BCryptHashPasswordRequest } from '../types/password/bcrypt-hash-password-request';
import { BCryptVerifyResponse } from '../types/password/bcrypt-verify-response';
import { BCryptVerifyRequest } from '../types/password/bcrypt-verify-request';
import { BCryptHashPasswordResponse } from '../types/password/bcrypt-hash-password-response';
import { ScryptVerifyRequest } from '../types/password/scrypt-verify-request';
import { ScryptVerifyResponse } from '../types/password/scrypt-verify-response';
import { SCryptHashPasswordResponse } from '../types/password/scrypt-hash-password-response';
import { ScryptHashPasswordRequest } from '../types/password/scrypt-hash-password-request';
import { Argon2HashPasswordResponse } from '../types/password/argon2-hash-password-response';
import { Argon2HashPasswordRequest } from '../types/password/argon2-hash-password-request';
import { Argon2VerifyResponse } from '../types/password/argon2-verify-response';
import { Argon2VerifyRequest } from '../types/password/argon2-verify-request';
import { BcryptHashPasswordBatchRequest } from '../types/password/bcrypt-hash-password-batch-request';
import { ScryptHashPasswordBatchResponse } from '../types/password/scrypt-hash-password-batch-response';
import { ScryptHashPasswordBatchRequest } from '../types/password/scrypt-hash-password-batch-request';
import { Argon2HashPasswordBatchResponse } from '../types/password/argon2-hash-password-batch-response';
import { Argon2HashPasswordBatchRequest } from '../types/password/argon2-hash-password-batch-request';
import { BcryptEncryptBatchResponse } from '../types/password/bcrypt-hash-password-batch-response';

export class PasswordService {
    public async bcryptHashPassword(token: string, password: string): Promise<BCryptHashPasswordResponse> {
        if (!token) {
            throw new Error("No token provided to perform BCrypt hash");
        }
        if (!password) {
            throw new Error("No password provided to perform BCrypt hash");
        }
        let url: string = EASConfiguration.baseUrl + "Password/BCryptEncrypt";
        const requestBody: BCryptHashPasswordRequest = new BCryptHashPasswordRequest(password);
        const requestBodySerialized = JSON.stringify(requestBody);
        const request = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }

    public async bcryptVerify(token: string, hashedPassword: string, password: string): Promise<BCryptVerifyResponse> {
        if (!token) {
            throw new Error("No token provided to perform BCrypt verify");
        }
        if (!hashedPassword) {
            throw new Error("No hashed password provided to perform BCrypt verify");
        }
        if (!password) {
            throw new Error("No password provided to perform BCrypt verify");
        }
        let url: string = EASConfiguration.baseUrl + "Password/BcryptVerify";
        const requestBody: BCryptVerifyRequest = new BCryptVerifyRequest(password, hashedPassword);
        const requestBodySerialized = JSON.stringify(requestBody);
        const request = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }

    public async bcryptHashBatch(token: string, passwords: Array<string>): Promise<BcryptEncryptBatchResponse> {
        if (!token) {
            throw new Error("No token provided to perform BCrypt batch hash");
        }
        if (!passwords || passwords.length < 0) {
            throw new Error("No passwords provided to perform BCrypt batch hash");
        }
        let url: string = EASConfiguration.baseUrl + "Password/BcryptEncryptBatch";
        const requestBody: BcryptHashPasswordBatchRequest = new BcryptHashPasswordBatchRequest(passwords);
        const requestBodySerialized = JSON.stringify(requestBody);
        const request = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }

    public async scryptHashBatch(token: string, passwords: Array<string>): Promise<ScryptHashPasswordBatchResponse> {
        if (!token) {
            throw new Error("No token provided to perform SCrypt batch hash");
        }
        if (!passwords || passwords.length < 0) {
            throw new Error("No passwords provided to perform SCrypt batch hash");
        }
        let url: string = EASConfiguration.baseUrl + "Password/SCryptEncryptBatch";
        const requestBody: ScryptHashPasswordBatchRequest = new ScryptHashPasswordBatchRequest(passwords);
        const requestBodySerialized = JSON.stringify(requestBody);
        const request = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }

    public async argon2HashBatch(token: string, passwords: Array<string>): Promise<Argon2HashPasswordBatchResponse> {
        if (!token) {
            throw new Error("No token provided to perform Argon2 batch hash");
        }
        if (!passwords || passwords.length < 0) {
            throw new Error("No passwords provided to perform Argon2 batch hash");
        }
        let url: string = EASConfiguration.baseUrl + "Password/Argon2HashBatch";
        const requestBody: Argon2HashPasswordBatchRequest = new Argon2HashPasswordBatchRequest(passwords);
        const requestBodySerialized = JSON.stringify(requestBody);
        const request = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }

    public async argon2Verify(token: string, hashedPassword: string, password: string): Promise<Argon2VerifyResponse> {
        if (!token) {
            throw new Error("No token provided to perform Argon2 verify");
        }
        if (!hashedPassword) {
            throw new Error("No hashed password provided to perform Argon2 verify");
        }
        if (!password) {
            throw new Error("No password provided to perform Argon2 verify");
        }
        let url: string = EASConfiguration.baseUrl + "Password/Argon2Verify";
        const requestBody: Argon2VerifyRequest = new Argon2VerifyRequest(password, hashedPassword);
        const requestBodySerialized = JSON.stringify(requestBody);
        let request = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }

    public async argon2HashPassword(token: string, password: string): Promise<Argon2HashPasswordResponse> {
        if (!token) {
            throw new Error("No token provided to perform Argon2 hash");
        }
        if (!password) {
            throw new Error("No password provided to perform Argon2 hash");
        }
        let url: string = EASConfiguration.baseUrl + "Password/Argon2Hash";
        const requestBody: Argon2HashPasswordRequest = new Argon2HashPasswordRequest(password);
        const requestBodySerialized = JSON.stringify(requestBody);
        const request = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }

    public async scryptHashPassword(token: string, password: string): Promise<SCryptHashPasswordResponse> {
        if (!token) {
            throw new Error("No token provided to perform SCrypt hash");
        }
        if (!password) {
            throw new Error("No password provided to perform SCrypt hash");
        }
        let url: string = EASConfiguration.baseUrl + "Password/SCryptEncrypt";
        const requestBody: ScryptHashPasswordRequest = new ScryptHashPasswordRequest(password);
        const requestBodySerialized = JSON.stringify(requestBody);
        const request = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }

    public async scryptVerify(token: string, hashedPassword: string, password: string): Promise<ScryptVerifyResponse> {
        if (!token) {
            throw new Error("No token provided to perform SCrypt verify");
        }
        if (!hashedPassword) {
            throw new Error("No hashed password provided to perform SCrypt verify");
        }
        if (!password) {
            throw new Error("No password provided to perform SCrypt verify");
        }
        let url: string = EASConfiguration.baseUrl + "Password/SCryptVerify";
        const requestBody: ScryptVerifyRequest = new ScryptVerifyRequest(password, hashedPassword);
        const requestBodySerialized = JSON.stringify(requestBody);
        const request = await fetch(url, {
            method: "POST",
            body: requestBodySerialized,
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` }
        });
        if (request.ok) {
            return await request.json();
        } else {
            throw new Error(await request.text());
        }
    }
}