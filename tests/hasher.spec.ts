import { test, expect } from "@playwright/test";
import { Blake2Wrapper, SHAWrapper } from "../src-ts/hashers/index";

test.describe("SHA512 Tests", () => {
  test("hash", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    expect(hashed).not.toEqual(tohashBytes);
  });

  test("verify pass", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    expect(verified).toBe(true);
  });

  test("verify fail", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerify = "This Is Not The Same";
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    expect(verified).toBe(false);
  });
});

test.describe("SHA256 Tests", () => {
  test("hash", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash256(tohashBytes);
    expect(hashed).not.toEqual(tohashBytes);
  });

  test("verify pass", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash256(tohashBytes);
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const verified = wrapper.verify256(hashed, toVerifyBytes);
    expect(verified).toBe(true);
  });

  test("verify fail", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash256(tohashBytes);
    const toVerify = "This Is Not The Same";
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
    const verified = wrapper.verify256(hashed, toVerifyBytes);
    expect(verified).toBe(false);
  });
});

test.describe("Blake2 512", () => {
  test("hash", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    expect(hashed).not.toEqual(tohashBytes);
  });

  test("verify pass", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    expect(verified).toBe(true);
  });

  test("verify fail", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerify = "This Is Not The Same";
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    expect(verified).toBe(false);
  });

  test.describe("Blake2 256", () => {
    test("hash", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      expect(hashed).not.toEqual(tohashBytes);
    });

    test("verify pass", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const verified = wrapper.verify256(hashed, toVerifyBytes);
      expect(verified).toBe(true);
    });

    test("verify fail", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      const toVerify = "This Is Not The Same";
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
      const verified = wrapper.verify256(hashed, toVerifyBytes);
      expect(verified).toBe(false);
    });
  });
});
