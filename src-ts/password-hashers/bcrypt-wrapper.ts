import { IPasswordHasherBase } from "./password-hasher-base";
import { bcryptHash, bcryptVerify } from "./../../index";

export class BCryptWrapper implements IPasswordHasherBase {
  
  verifyThreadPool(hashedPassword: string, passwordToCheck: string): boolean {
    throw new Error("Method not implemented.");
  }

  public hashPasswordThreadPool(password: string): string {
    throw new Error("Method not implemented.");
  }

  public hashPassword(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    return bcryptHash(password);
  }

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
