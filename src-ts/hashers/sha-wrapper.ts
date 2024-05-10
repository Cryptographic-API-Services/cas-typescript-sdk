import { sha256, sha256Verify, sha512, sha512Verify } from "../../index";
import { IHasherBase } from "./hasher-base";

export class SHAWrapper implements IHasherBase {
    hash512(dataToHash: number[]): number[] {
        if (!dataToHash || dataToHash.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        return sha512(dataToHash);
    }

    verify512(dataToHash: number[], dataToVerify: number[]): boolean {
        if (!dataToHash || dataToHash.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        if (!dataToVerify || dataToVerify.length === 0) {
            throw new Error("You must provide an allocated array of data to verify");
        }
        return sha512Verify(dataToHash, dataToVerify);
    }

    hash256(dataToHash: number[]): number[] {
        if (!dataToHash || dataToHash.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        return sha256(dataToHash);
    }

    verify256(dataToHash: number[], dataToVerify: number[]): boolean {
        if (!dataToHash || dataToHash.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        if (!dataToVerify || dataToVerify.length === 0) {
            throw new Error("You must provide an allocated array of data to verify");
        }
        return sha256Verify(dataToHash, dataToVerify);
    }
}