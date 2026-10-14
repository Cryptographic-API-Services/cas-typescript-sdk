import { hmacSha512Sign, hmacSha512Verify, hmacSign, hmacVerify } from "../../index";


export class HmacWrapper {
    
    
    public hmacSignBytes(key: Array<number>, message: Array<number>): Array<number> {
        if (key?.length === 0) {
            throw new Error("Must provide an allocated key");
        }
        if (message?.length === 0) {
            throw new Error("Must provide an allocated message");
        }
        return hmacSign(key, message);
    }

    
    public hmacVerifyBytes(key: Array<number>, message: Array<number>, signature: Array<number>): boolean {
        if (key?.length === 0) {
            throw new Error("Must provide an allocated key");
        }
        if (message?.length === 0) {
            throw new Error("Must provide an allocated message");
        }
        if(signature?.length===0) {
            throw new Error("Must provide an allocated signature");
        }
        return hmacVerify(key, message, signature);
    }

    /**
     * Signs a message with HMAC-SHA2-512.
     * @param key The HMAC key
     * @param message The message to authenticate
     * @returns The 64-byte HMAC-SHA512 tag
     */
    public hmacSha512SignBytes(key: Array<number>, message: Array<number>): Array<number> {
        if (key?.length === 0) {
            throw new Error("Must provide an allocated key");
        }
        if (message?.length === 0) {
            throw new Error("Must provide an allocated message");
        }
        return hmacSha512Sign(key, message);
    }

    /**
     * Verifies an HMAC-SHA2-512 tag in constant time.
     * @param key The HMAC key
     * @param message The message that was authenticated
     * @param signature The 64-byte tag to verify
     * @returns True if the tag is valid for the key and message
     */
    public hmacSha512VerifyBytes(key: Array<number>, message: Array<number>, signature: Array<number>): boolean {
        if (key?.length === 0) {
            throw new Error("Must provide an allocated key");
        }
        if (message?.length === 0) {
            throw new Error("Must provide an allocated message");
        }
        if (signature?.length === 0) {
            throw new Error("Must provide an allocated signature");
        }
        return hmacSha512Verify(key, message, signature);
    }
}