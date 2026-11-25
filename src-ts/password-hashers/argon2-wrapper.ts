
import {
  argon2DeriveAes128Key,
  argon2DeriveAes128KeyWithSalt,
  argon2DeriveAes256Key,
  argon2DeriveAes256KeyWithSalt,
  argon2GenerateSalt,
  argon2Hash,
  argon2HashParams,
  argon2Verify,
} from "./../../index";
import { IPasswordHasherBase } from "./password-hasher-base";

const MIN_MEMORY_COST_MIB = 19;
const MAX_MEMORY_COST_MIB = 4096;
const MIN_ITERATIONS = 1;
const MAX_ITERATIONS = 10;
const MIN_PARALLELISM = 1;
const MAX_PARALLELISM = 16;

export class Argon2Wrapper implements IPasswordHasherBase {
  /**
   * Hashes a password with Argon2
   * @param password 
   * @returns string
   */

  
  public hashPassword(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    return argon2Hash(password);
  }
  
  /**
   * Hashes a password with Argon2id using custom parameters.
   * Every parameter must be an integer within its range; anything else throws.
   * @param password
   * @param memoryCost Memory cost in mebibytes (MiB), not KiB: 19 to 4096 (4 GiB). `64` means 64 MiB.
   * @param timeCost Number of iterations: 1 to 10.
   * @param parallelism Degree of parallelism: 1 to 16.
   * @returns string
   */
  
  public hashPasswordWithParameters(password: string, memoryCost: number, timeCost: number, parallelism: number): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    this.checkRange("memory cost (MiB)", memoryCost, MIN_MEMORY_COST_MIB, MAX_MEMORY_COST_MIB);
    this.checkRange("time cost", timeCost, MIN_ITERATIONS, MAX_ITERATIONS);
    this.checkRange("parallelism", parallelism, MIN_PARALLELISM, MAX_PARALLELISM);
    return argon2HashParams(memoryCost, timeCost, parallelism, password);
  }

  /**
   * Generates a random 16 byte salt for deriveAes128KeyWithSalt and deriveAes256KeyWithSalt.
   * The salt is not secret: store it next to whatever the key protects and pass it back
   * with the same password to re-derive the same key.
   * @returns Array<number>
   */
  public generateSalt(): Array<number> {
    return argon2GenerateSalt();
  }

  /**
   * Derives a 16 byte AES-128 key from a password and salt with Argon2id.
   * The same password and salt always give the same key. The cost parameters are fixed
   * (19 MiB of memory, 2 iterations, parallelism 1), so a stored salt keeps working across updates.
   * @param password
   * @param salt At least 16 bytes, for example from generateSalt. A shorter salt throws a
   * CasError with code CasErrorCode.InvalidParameters.
   * @returns Array<number>
   */
  public deriveAes128KeyWithSalt(password: Array<number>, salt: Array<number>): Array<number> {
    if (!password || password.length === 0) {
      throw new Error("You must provide a password to derive an AES-128 key with Argon2");
    }
    return argon2DeriveAes128KeyWithSalt(password, salt);
  }

  /**
   * Derives a 32 byte AES-256 key from a password and salt with Argon2id.
   * The same password and salt always give the same key. The cost parameters are fixed
   * (19 MiB of memory, 2 iterations, parallelism 1), so a stored salt keeps working across updates.
   * @param password
   * @param salt At least 16 bytes, for example from generateSalt. A shorter salt throws a
   * CasError with code CasErrorCode.InvalidParameters.
   * @returns Array<number>
   */
  public deriveAes256KeyWithSalt(password: Array<number>, salt: Array<number>): Array<number> {
    if (!password || password.length === 0) {
      throw new Error("You must provide a password to derive an AES-256 key with Argon2");
    }
    return argon2DeriveAes256KeyWithSalt(password, salt);
  }

  /**
   * Derives a 16 byte AES-128 key from a password with Argon2id.
   * A random salt is generated internally and discarded, so the key cannot be
   * re-derived from the password — each call produces a fresh one-time key.
   * @deprecated The salt is discarded, so the key can never be derived again. Use
   * generateSalt and deriveAes128KeyWithSalt instead.
   * @param password
   * @returns Array<number>
   */
  public deriveAes128Key(password: Array<number>): Array<number> {
    if (!password || password.length === 0) {
      throw new Error("You must provide a password to derive an AES-128 key with Argon2");
    }
    return argon2DeriveAes128Key(password);
  }

  /**
   * Derives a 32 byte AES-256 key from a password with Argon2id.
   * A random salt is generated internally and discarded, so the key cannot be
   * re-derived from the password — each call produces a fresh one-time key.
   * @deprecated The salt is discarded, so the key can never be derived again. Use
   * generateSalt and deriveAes256KeyWithSalt instead.
   * @param password
   * @returns Array<number>
   */
  public deriveAes256Key(password: Array<number>): Array<number> {
    if (!password || password.length === 0) {
      throw new Error("You must provide a password to derive an AES-256 key with Argon2");
    }
    return argon2DeriveAes256Key(password);
  }

  /**
   * Verifies that a password is the same as the hashed password with Argon2.
   * The costs stored in the hash are checked before any work is done: a hash above
   * 4096 MiB of memory, 10 iterations or a parallelism of 16 throws instead of
   * exhausting memory or CPU. Hashes below the hashing minimums still verify.
   * @param hashedPassword 
   * @param passwordToVerify 
   * @returns boolean
   */
  public verify(hashedPassword: string, passwordToVerify: string): boolean {
    if (!hashedPassword || !passwordToVerify) {
      throw new Error(
        "You must provide a hashed password and a plaintext password to verify with Argon2",
      );
    }
    return argon2Verify(hashedPassword, passwordToVerify);
  }

  private checkRange(name: string, value: number, min: number, max: number): void {
    if (!Number.isInteger(value) || value < min || value > max) {
      throw new Error(`Argon2 ${name} must be an integer from ${min} to ${max}`);
    }
  }
}
