import { expect, test } from "@playwright/test";
import * as sdk from "../src-ts/index";

// Guards the barrel exports for the APIs added with cas-lib 0.2.85 (issue #90),
// so a wrapper cannot be implemented but left out of the published package.
test.describe("Public API exports", () => {
  test("cas-lib 0.2.85 wrappers are exported from the package root", () => {
    expect(typeof sdk.AESGCMSIVWrapper).toBe("function");
    expect(typeof sdk.MlKem1024Wrapper).toBe("function");
    expect(typeof sdk.SlhDsaWrapper).toBe("function");
    expect(typeof sdk.Pbkdf2Wrapper).toBe("function");
  });

  test("new methods on existing wrappers are present", () => {
    expect(typeof new sdk.AESWrapper().aes128KeyFromBytes).toBe("function");
    expect(typeof new sdk.AESWrapper().aes256KeyFromBytes).toBe("function");
    expect(typeof new sdk.Ed25519Wrapper().verifyWithKeyPairBytes).toBe("function");
    expect(typeof new sdk.Argon2Wrapper().deriveAes128Key).toBe("function");
    expect(typeof new sdk.Argon2Wrapper().deriveAes256Key).toBe("function");
  });
});
