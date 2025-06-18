import { scryptHash, scryptHashThreadpool, scryptVerify, scryptVerifyThreadpool } from "../../index.d";
import { IPasswordHasherBase } from "./password-hasher-base";

export class ScryptWrapper implements IPasswordHasherBase {

  /**
   * Verifies a password with SCrypt on the threadpool.
   * @param hashedPassword 
   * @param passwordToCheck 
   * @returns boolean
   */
  verifyThreadPool(hashedPassword: string, passwordToCheck: string): boolean {
    if (!hashedPassword || !passwordToCheck) {
      throw new Error(
        "You must provide a hashed password and a plaintext password to verify with Scrypt",
      );
    }
    return scryptVerifyThreadpool(hashedPassword, passwordToCheck);
  }

  /**
   * Hashes a password with SCrypt on the threadpool.
   * @param password 
   * @returns string
   */
  hashPasswordThreadPool(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Scrypt");
    }
    return scryptHashThreadpool(password);
  }

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
   * Verifies that a password is the same as the hashed password with SCrypt.
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
}
