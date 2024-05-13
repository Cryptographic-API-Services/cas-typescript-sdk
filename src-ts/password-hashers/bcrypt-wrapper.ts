import { IPasswordHasherBase } from "./password-hasher-base";
import { bcryptHash, bcryptHashThreadpool, bcryptVerify, bcryptVerifyThreadpool } from "./../../index";

export class BCryptWrapper implements IPasswordHasherBase {

  /**
   * Verifies a password with BCrypt on the threadpool.
   * @param hashedPassword 
   * @param passwordToCheck 
   * @returns boolean
   */
  verifyThreadPool(hashedPassword: string, passwordToCheck: string): boolean {
    if (!hashedPassword || !passwordToCheck) {
      throw new Error(
        "You must provide a hashed password and a plaintext password to verify with Argon2",
      );
    }
    return bcryptVerifyThreadpool(hashedPassword, passwordToCheck);
  }

  /**
   * Hashes a password with BCrypt on the threadpool.
   * @param password 
   * @returns string
   */
  public hashPasswordThreadPool(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    return bcryptHashThreadpool(password);
  }

  /**
   * Hashes a password with BCrypt
   * @param password 
   * @returns string
   */
  public hashPassword(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    return bcryptHash(password);
  }

  /**
   * Verifies that a password is the same as the hashed password with BCrypt.
   * @param hashedPassword 
   * @param passwordToVerify 
   * @returns boolean
   */
  public verify(
    hashedPassword: string,
    passwordToVerify: string,
  ): boolean {
    if (!hashedPassword || !passwordToVerify) {
      throw new Error(
        "You must provide a hashed password and a plaintext password to verify with Argon2",
      );
    }
    return bcryptVerify(hashedPassword, passwordToVerify);
  }
}
