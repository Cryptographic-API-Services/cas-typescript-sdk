import { hmacSign, hmacVerify } from "../../index";


export class HmacWrapper {
    
    
    public hmacSignBytes(key: Uint8Array, message: Uint8Array): Uint8Array {
        if (key?.length === 0) {
            throw new Error("Must provide an allocated key");
        }
        if (message?.length === 0) {
            throw new Error("Must provide an allocated message");
        }
        return hmacSign(key, message);
    }

    
    public hmacVerifyBytes(key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
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
}