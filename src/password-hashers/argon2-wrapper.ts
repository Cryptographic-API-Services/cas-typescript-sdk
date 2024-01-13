import ffi from "ffi-napi";

export class Argon2Wrapper {
  private ffiLibraries;

  constructor() {
    this.ffiLibraries = ffi.Library("./cas_core_lib.dll", {
      "argon2_hash": ["string", ["string"]],
    });
  }

  public hashPassword(passwordToHash: string): string | null {
    if (!passwordToHash) {
        throw new Error("You must provide a password to hash");
    }
    return this.ffiLibraries.argon2_hash(passwordToHash);
  }
}
