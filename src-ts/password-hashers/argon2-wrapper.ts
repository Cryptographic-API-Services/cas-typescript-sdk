import { argon2Hash, argon2Verify} from "./../../index";
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
