import { argon2Hash, argon2HashThreadPool, argon2Verify, argon2VerifyThreadpool } from "./../../index";
import { IPasswordHasherBase } from "./password-hasher-base";

export class Argon2Wrapper implements IPasswordHasherBase {

  verifyThreadPool(hashedPassword: string, passwordToCheck: string): boolean {
    if (!hashedPassword) {
      throw new Error("You must provide a password to verify with Argon2");
    }
    if (!passwordToCheck) {
      throw new Error("You must provide a password to check to verify with Argon2");
    }
    return argon2VerifyThreadpool(hashedPassword, passwordToCheck);
  }

  public hashPasswordThreadPool(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    return argon2HashThreadPool(password);
  }

  public hashPassword(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Argon2");
    }
    return argon2Hash(password);
  }

  public verify(hashedPassword: string, passwordToVerify: string): boolean {
    if (!hashedPassword || !passwordToVerify) {
      throw new Error(
        "You must provide a hashed password and a plaintext password to verify with Argon2",
      );
    }
    return argon2Verify(hashedPassword, passwordToVerify);
  }
}
