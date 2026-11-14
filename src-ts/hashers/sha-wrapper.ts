import { sha256, sha256Verify, sha512, sha512Verify } from "../../index";

import { HashInput, IHasherBase } from "./hasher-base";

export class SHAWrapper implements IHasherBase {
    /**
     * Hashes a byte array with SHA3-512.
     * An empty, `null` or `undefined` input hashes as the empty message.
     * @param dataToHash
     * @returns number[]
     */

    hash512(dataToHash: HashInput): number[] {
        return sha512(dataToHash ?? []);
    }

    /**
     * Verifies unsigned data against an SHA3-512 hash.
     * An empty, `null` or `undefined` `dataToVerify` is checked as the empty message.
     * @param hashToVerify The SHA3-512 hash to compare against
     * @param dataToVerify The data to hash and compare
     * @returns boolean
     */

    verify512(hashToVerify: HashInput, dataToVerify: HashInput): boolean {
        return sha512Verify(hashToVerify ?? [], dataToVerify ?? []);
    }

    /**
     * Hashes a byte array with SHA3-256.
     * An empty, `null` or `undefined` input hashes as the empty message.
     * @param dataToHash
     * @returns number[]
     */

    hash256(dataToHash: HashInput): number[] {
        return sha256(dataToHash ?? []);
    }

    /**
     * Verifies unsigned data against an SHA3-256 hash.
     * An empty, `null` or `undefined` `dataToVerify` is checked as the empty message.
     * @param hashToVerify The SHA3-256 hash to compare against
     * @param dataToVerify The data to hash and compare
     * @returns boolean
     */

    verify256(hashToVerify: HashInput, dataToVerify: HashInput): boolean {
        return sha256Verify(hashToVerify ?? [], dataToVerify ?? []);
    }
}
