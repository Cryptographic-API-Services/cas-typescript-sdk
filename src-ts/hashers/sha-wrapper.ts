import { sha256, sha256Verify, sha512, sha512Verify } from "../../index.d";
import { IHasherBase } from "./hasher-base";

export class SHAWrapper implements IHasherBase {
    /**
     * Hashes a byte array with SHA3-512.
     * @param dataToHash 
     * @returns number[]
     */
    hash512(dataToHash: number[]): number[] {
        if (!dataToHash || dataToHash.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        return sha512(dataToHash);
    }

    /**
     * Verifies unsigned data against an SHA3-512 hash.
     * @param dataToHash 
     * @param dataToVerify 
     * @returns boolean
     */
    verify512(dataToHash: number[], dataToVerify: number[]): boolean {
        if (!dataToHash || dataToHash.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        if (!dataToVerify || dataToVerify.length === 0) {
            throw new Error("You must provide an allocated array of data to verify");
        }
        return sha512Verify(dataToHash, dataToVerify);
    }

    /**
     * Hashes a byte array with SHA3-256.
     * @param dataToHash 
     * @returns number[]
     */
    hash256(dataToHash: number[]): number[] {
        if (!dataToHash || dataToHash.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        return sha256(dataToHash);
    }

    /**
     * Verifies unsigned data against an SHA3-256 hash.
     * @param dataToHash 
     * @param dataToVerify 
     * @returns boolean
     */
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