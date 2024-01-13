import os from "os";
import koffi  from "koffi";

export class Argon2Wrapper {
  private lib;
  private argon2_hash: Function;
  private argon2_verify: Function;

  constructor() {
    this.lib = (os.platform() === "win32") ? koffi.load(global.pathToWindowsDll) : koffi.load(global.pathToLinuxSO);
    this.argon2_hash = this.lib.func("argon2_hash", 'string', ['string']);
    this.argon2_verify = this.lib.func("argon2_verify", 'int8', ['string', 'string']);
  }

  public hashPassword(passwordToHash: string): string {
    if (!passwordToHash) {
        throw new Error("You must provide a password to hash");
    }
    return this.argon2_hash(passwordToHash);
  }

  public verifyPassword(hashedPassword: string, passwordToVerify: string): boolean {
    if (!hashedPassword || !passwordToVerify) {
      throw new Error("You must provide a hashed password and a non hash password to verify with Argon2");
    }
    let result: number = this.argon2_verify(hashedPassword, passwordToVerify);
    if (result == 0)
      return false;
    else 
      return true;
  }
}
