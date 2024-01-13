import os from "os";
import koffi  from "koffi";

export class Argon2Wrapper {
  private lib;
  private argon2_hash: Function;

  constructor() {
    this.lib = (os.platform() === "win32") ? koffi.load('./cas_core_lib.dll') : koffi.load("./libcas_core_lib.so");
    this.argon2_hash = this.lib.func("argon2_hash", 'string', ['string'])
  }

  public hashPassword(passwordToHash: string): string | null {
    if (!passwordToHash) {
        throw new Error("You must provide a password to hash");
    }
    return this.argon2_hash(passwordToHash);
  }
}
