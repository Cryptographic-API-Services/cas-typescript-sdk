import { scryptHash, scryptHashParams, scryptVerify} from "../../index";

import { IPasswordHasherBase } from "./password-hasher-base";

const MIN_LOG_N = 10;
const MAX_LOG_N = 20;
const MAX_BLOCK_SIZE = 32;
const MAX_PARALLELISM = 16;

export class ScryptWrapper implements IPasswordHasherBase {

  /**
   * Hashes a password with SCrypt
   * @param password 
   * @returns string
   */
  
  public hashPassword(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Scrypt");
    }
    return scryptHash(password);
  }

  /**
   * Hashes a password with SCrypt using custom parameters.
   * Every parameter must be an integer within its range; anything else throws.
   * Memory use is about 128 * blockSize * 2^cpuCost bytes.
   * @param password
   * @param cpuCost log2 of the work factor N: 10 to 20 (N = 1024 to 1048576), and less than 16 * blockSize (an scrypt rule).
   * @param blockSize Block size `r`: 1 to 32. cpuCost 16 and above need a block size of at least 2.
   * @param parallelism Parallelization `p`: 1 to 16.
   * @returns string
   */
  
  public hashPasswordWithParameters(password: string, cpuCost: number, blockSize: number, parallelism: number): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Scrypt");
    }
    this.checkRange("cpu cost (log2 N)", cpuCost, MIN_LOG_N, MAX_LOG_N);
    this.checkRange("block size", blockSize, 1, MAX_BLOCK_SIZE);
    this.checkRange("parallelism", parallelism, 1, MAX_PARALLELISM);
    if (cpuCost >= 16 * blockSize) {
      throw new Error("Scrypt cpu cost (log2 N) must be less than 16 * block size");
    }
    return scryptHashParams(password, cpuCost, blockSize, parallelism);
  }

  /**
   * Verifies that a password is the same as the hashed password with SCrypt.
   * The costs stored in the hash are checked before any work is done: a hash above
   * log2 N = 20, r = 32 or p = 16 throws instead of exhausting memory.
   * Hashes below the hashing minimums still verify.
   * @param hashedPassword 
   * @param passwordToVerify 
   * @returns boolean
   */
  
  public verify(hashedPassword: string, passwordToVerify: string): boolean {
    if (!hashedPassword || !passwordToVerify) {
      throw new Error(
        "You must provide a hashed password and a plaintext password to verify with Scrypt",
      );
    }
    return scryptVerify(hashedPassword, passwordToVerify);
  }

  private checkRange(name: string, value: number, min: number, max: number): void {
    if (!Number.isInteger(value) || value < min || value > max) {
      throw new Error(`Scrypt ${name} must be an integer from ${min} to ${max}`);
    }
  }
}
