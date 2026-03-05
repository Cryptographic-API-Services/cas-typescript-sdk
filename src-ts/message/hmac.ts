import { hmacSign, hmacVerify } from "../../index";
import { benchmarkMethod } from "../decorators/benchmark-method";

export class HmacWrapper {
    
    @benchmarkMethod()
    public hmacSignBytes(key: Array<number>, message: Array<number>): Array<number> {
        if (key?.length === 0) {
            throw new Error("Must provide an allocated key");
        }
        if (message?.length === 0) {
            throw new Error("Must provide an allocated message");
        }
        return hmacSign(key, message);
    }

    @benchmarkMethod()
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