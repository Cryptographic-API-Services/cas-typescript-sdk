
import { argon2DeriveAes128Key, argon2DeriveAes256Key, argon2Hash, argon2HashParams, argon2Verify} from "./../../index";
import { IPasswordHasherBase } from "./password-hasher-base";

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
   * Hashes a password with Argon2 using custom parameters
   * @param password 
   * @param memoryCost 
   * @param timeCost 
   * @param parallelism 
   * @returns 
   */
  
  public hashPasswordWithParameters(password: string, memoryCost: number, timeCost: number, parallelism: number): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    return argon2HashParams(memoryCost, timeCost, parallelism, password);
  }

  /**
   * Derives a 16 byte AES-128 key from a password with Argon2id.
   * A random salt is generated internally and discarded, so the key cannot be
   * re-derived from the password — each call produces a fresh one-time key.
   * Use Pbkdf2Wrapper.deriveWithSalt if you need a re-derivable key.
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
   * Use Pbkdf2Wrapper.deriveWithSalt if you need a re-derivable key.
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
}
