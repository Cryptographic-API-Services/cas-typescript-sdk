import {
  blake2Sha512Verify,
  blake2Sha256Verify,
  blake2Sha256,
  blake2Sha512,
} from "../../index";

import { HashInput, IHasherBase } from "./hasher-base";

export class Blake2Wrapper implements IHasherBase {
  /**
   * Hashes the input data using BLAKE2b-512 (64-byte digest).
   * An empty, `null` or `undefined` input hashes as the empty message.
   * @param dataToHash The data to hash
   * @returns The hashed output
   */

  hash512(dataToHash: HashInput): number[] {
    return blake2Sha512(dataToHash ?? []);
  }

  /**
   * Verifies the input data against the hashed output using BLAKE2b-512.
   * An empty, `null` or `undefined` `dataToVerify` is checked as the empty message.
   * @param hashToVerify The BLAKE2b-512 hash to compare against
   * @param dataToVerify The data to hash and compare
   * @returns True if the verification is successful, false otherwise
   */

  verify512(hashToVerify: HashInput, dataToVerify: HashInput): boolean {
    return blake2Sha512Verify(hashToVerify ?? [], dataToVerify ?? []);
  }

  /**
   * Hashes the input data using BLAKE2s-256 (32-byte digest).
   * This is BLAKE2s, not BLAKE2b-256: the two produce different digests.
   * An empty, `null` or `undefined` input hashes as the empty message.
   * @param dataToHash The data to hash
   * @returns The hashed output
   */

  hash256(dataToHash: HashInput): number[] {
    return blake2Sha256(dataToHash ?? []);
  }

  /**
   * Verifies the input data against the hashed output using BLAKE2s-256
   * (not BLAKE2b-256).
   * An empty, `null` or `undefined` `dataToVerify` is checked as the empty message.
   * @param hashToVerify The BLAKE2s-256 hash to compare against
   * @param dataToVerify The data to hash and compare
   * @returns True if the verification is successful, false otherwise
   */

  verify256(hashToVerify: HashInput, dataToVerify: HashInput): boolean {
    return blake2Sha256Verify(hashToVerify ?? [], dataToVerify ?? []);
  }
}
