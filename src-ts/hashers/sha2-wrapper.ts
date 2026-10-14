import { sha2Hash256, sha2Hash256Verify, sha2Hash512, sha2Hash512Verify } from "../../index";

import { IHasherBase } from "./hasher-base";

export class SHA2Wrapper implements IHasherBase {
    /**
     * Hashes a byte array with SHA2-512.
     * @param dataToHash
     * @returns number[]
     */

    hash512(dataToHash: number[]): number[] {
        if (!dataToHash || dataToHash.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        return sha2Hash512(dataToHash);
    }

    /**
     * Verifies unsigned data against an SHA2-512 hash.
     * @param hashToVerify The SHA2-512 hash to compare against
     * @param dataToVerify The data to hash and compare
     * @returns boolean
     */

    verify512(hashToVerify: number[], dataToVerify: number[]): boolean {
        if (!hashToVerify || hashToVerify.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        if (!dataToVerify || dataToVerify.length === 0) {
            throw new Error("You must provide an allocated array of data to verify");
        }
        return sha2Hash512Verify(hashToVerify, dataToVerify);
    }

    /**
     * Hashes a byte array with SHA2-256.
     * @param dataToHash
     * @returns number[]
     */

    hash256(dataToHash: number[]): number[] {
        if (!dataToHash || dataToHash.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        return sha2Hash256(dataToHash);
    }

    /**
     * Verifies unsigned data against an SHA2-256 hash.
     * @param hashToVerify The SHA2-256 hash to compare against
     * @param dataToVerify The data to hash and compare
     * @returns boolean
     */

    verify256(hashToVerify: number[], dataToVerify: number[]): boolean {
        if (!hashToVerify || hashToVerify.length === 0) {
            throw new Error("You must provide an allocated array of data");
        }
        if (!dataToVerify || dataToVerify.length === 0) {
            throw new Error("You must provide an allocated array of data to verify");
        }
        return sha2Hash256Verify(hashToVerify, dataToVerify);
    }
}
