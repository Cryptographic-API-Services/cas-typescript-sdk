import path from "path";
global.pathToLinuxSO = path.join(__dirname, "libcas_core_lib.so");
global.pathToWindowsDll = path.join(__dirname, "cas_core_lib.dll");

import { Argon2Wrapper } from "./password-hashers/argon2-wrapper";


export {
    Argon2Wrapper
}