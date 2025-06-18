import { argon2Hash, argon2HashThreadPool, argon2Verify, argon2VerifyThreadpool } from "./../../index.d";
import { IPasswordHasherBase } from "./password-hasher-base";

export class Argon2Wrapper implements IPasswordHasherBase {

  /**
   * Verifies a password with Argon2 on the threadpool.
   * @param hashedPassword 
   * @param passwordToCheck 
   * @returns boolean
   */
  verifyThreadPool(hashedPassword: string, passwordToCheck: string): boolean {
    if (!hashedPassword) {
      throw new Error("You must provide a password to verify with Argon2");
    }
    if (!passwordToCheck) {
      throw new Error("You must provide a password to check to verify with Argon2");
    }
    return argon2VerifyThreadpool(hashedPassword, passwordToCheck);
  }

  /**
   * Hashes a password with Argon2 on the threadpool.
   * @param password 
   * @returns string
   */
  public hashPasswordThreadPool(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    return argon2HashThreadPool(password);
  }

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
