import ffi from "ffi-napi";
import os from "os";

export class Argon2Wrapper {
  private ffiLibraries;

  constructor() {
    let platform = os.platform();
    console.log(platform);
    if (platform === "win32") {
        this.ffiLibraries = ffi.Library("./cas_core_lib.dll", {
          "argon2_hash": ["string", ["string"]],
        });
    } else {
        this.ffiLibraries = ffi.Library("./libcas_core_lib.so", {
            "argon2_hash": ["string", ["string"]],
          });
    }
  }

  public hashPassword(passwordToHash: string): string | null {
    if (!passwordToHash) {
        throw new Error("You must provide a password to hash");
    }
    return this.ffiLibraries.argon2_hash(passwordToHash);
  }
}
