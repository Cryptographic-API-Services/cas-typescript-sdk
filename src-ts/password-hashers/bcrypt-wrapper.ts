import { IPasswordHasherBase } from "./password-hasher-base";
import { bcryptHash, bcryptHashThreadpool, bcryptVerify, bcryptVerifyThreadpool } from "./../../index";

export class BCryptWrapper implements IPasswordHasherBase {

  verifyThreadPool(hashedPassword: string, passwordToCheck: string): boolean {
    if (!hashedPassword || !passwordToCheck) {
      throw new Error(
        "You must provide a hashed password and a plaintext password to verify with Argon2",
      );
    }
    return bcryptVerifyThreadpool(hashedPassword, passwordToCheck);
  }

  public hashPasswordThreadPool(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    return bcryptHashThreadpool(password);
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
