import { blake2Sha512Verify, blake2Sha256Verify, blake2Sha256, blake2Sha512, blake2Sha512Threadpool, blake2Sha512VerifyThreadpool, blake2Sha256Threadpool, blake2Sha256VerifyThreadpool } from "../../index";
import { IHasherBase } from "./hasher-base";

export class Blake2Wrapper implements IHasherBase {

    /**
     * Hashes the input data using Blake2b 512
     * @param dataToHash The data to hash
     * @returns The hashed output
     */
    hash512(dataToHash: number[]): number[] {
        return blake2Sha512(dataToHash);
    }

    /**
     * Hashes the input data using Blake2b 512 in a thread pool
     * @param dataToHash The data to hash
     * @returns The hashed output
     */
    hash512Threadpool(dataToHash: number[]): number[] {
        return blake2Sha512Threadpool(dataToHash);
    }

    /**
     * Verifies the input data against the hashed output using Blake2b 512
     * @param dataToHash The data to hash
     * @param dataToVerify The data to verify
     * @returns True if the verification is successful, false otherwise
     */
    verify512(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha512Verify(dataToHash, dataToVerify);
    }

    /**
     * Verifies the input data against the hashed output using Blake2b 512 in a thread pool
     * @param dataToHash The data to hash
     * @param dataToVerify The data to verify
     * @returns True if the verification is successful, false otherwise
     */
    verify512Threadpool(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha512VerifyThreadpool(dataToHash, dataToVerify);
    }

    /**
     * Hashes the input data using Blake2b 256
     * @param dataToHash The data to hash
     * @returns The hashed output
     */

    hash256(dataToHash: number[]): number[] {
        return blake2Sha256(dataToHash);
    }

    /**
     * Hashes the input data using Blake2b 256 in a thread pool
     * @param dataToHash The data to hash
     * @returns The hashed output
     */

    hash256Threadpool(dataToHash: number[]): number[] {
        return blake2Sha256Threadpool(dataToHash);
    }
    
    /**
     * Verifies the input data against the hashed output using Blake2b 256
     * @param dataToHash The data to hash
     * @param dataToVerify The data to verify
     * @returns True if the verification is successful, false otherwise
     */
    verify256(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha256Verify(dataToHash, dataToVerify);
    }

    /**
     * Verifies the input data against the hashed output using Blake2b 256 in a thread pool
     * @param dataToHash The data to hash
     * @param dataToVerify The data to verify
     * @returns True if the verification is successful, false otherwise
     */
    verify256Threadpool(dataToHash: number[], dataToVerify: number[]): boolean {
        return blake2Sha256VerifyThreadpool(dataToHash, dataToVerify);
    }
}