import {argon2Hash, argon2Verify} from "./../../index";
import { IPasswordHasherBase} from "./password-hasher-base";

export class Argon2Wrapper implements IPasswordHasherBase {
  public hashPassword(password: string): string {
    if (!password){
      throw new Error("You must provide a password to hash with Argon2");
    }
    return argon2Hash(password);
  }

  public verify(hashedPassword: string, passwordToVerify: string): boolean {
    if (!hashedPassword || !passwordToVerify) {
      throw new Error("You must provide a hashed password and a plaintext password to verify with Argon2");
    }
    return argon2Verify(hashedPassword, passwordToVerify);
  }
}
