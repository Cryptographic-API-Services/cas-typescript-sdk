import { hmacSign, hmacVerify } from "../../index";

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
}