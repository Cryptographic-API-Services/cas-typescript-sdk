import { IPasswordHasherBase } from "./password-hasher-base";
import { bcryptHash, bcryptVerify } from "./../../index";

export class BCryptWrapper implements IPasswordHasherBase {

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
