import { sha2Hash256, sha2Hash256Verify, sha2Hash512, sha2Hash512Verify } from "../../index";

import { HashInput, IHasherBase } from "./hasher-base";

export class SHA2Wrapper implements IHasherBase {
    /**
     * Hashes a byte array with SHA-512.
     * An empty, `null` or `undefined` input hashes as the empty message.
     * @param dataToHash
     * @returns number[]
     */

    hash512(dataToHash: HashInput): number[] {
        return sha2Hash512(dataToHash ?? []);
    }

    /**
     * Verifies unsigned data against an SHA-512 hash.
     * An empty, `null` or `undefined` `dataToVerify` is checked as the empty message.
     * @param hashToVerify The SHA-512 hash to compare against
     * @param dataToVerify The data to hash and compare
     * @returns boolean
     */

    verify512(hashToVerify: HashInput, dataToVerify: HashInput): boolean {
        return sha2Hash512Verify(hashToVerify ?? [], dataToVerify ?? []);
    }

    /**
     * Hashes a byte array with SHA-256.
     * An empty, `null` or `undefined` input hashes as the empty message.
     * @param dataToHash
     * @returns number[]
     */

    hash256(dataToHash: HashInput): number[] {
        return sha2Hash256(dataToHash ?? []);
    }

    /**
     * Verifies unsigned data against an SHA-256 hash.
     * An empty, `null` or `undefined` `dataToVerify` is checked as the empty message.
     * @param hashToVerify The SHA-256 hash to compare against
     * @param dataToVerify The data to hash and compare
     * @returns boolean
     */

    verify256(hashToVerify: HashInput, dataToVerify: HashInput): boolean {
        return sha2Hash256Verify(hashToVerify ?? [], dataToVerify ?? []);
    }
}
