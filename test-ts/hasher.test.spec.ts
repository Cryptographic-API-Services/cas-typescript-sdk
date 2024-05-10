import { assert } from "chai";
import { SHAWrapper } from "../src-ts/hashers/index";

describe("SHA512 Tests", () => {
  it("hash", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    assert.notEqual(tohashBytes, hashed);
  });

  it("verify pass", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    assert.equal(true, verified);
  });

  it("verify fail", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerify = "This Is Not The Same";
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    assert.equal(false, verified);
  });
});


describe("SHA256 Tests", () => {
    it("hash", () => {
      const wrapper = new SHAWrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      assert.notEqual(tohashBytes, hashed);
    });
  
    it("verify pass", () => {
      const wrapper = new SHAWrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const verified = wrapper.verify256(hashed, toVerifyBytes);
      assert.equal(true, verified);
    });
  
    it("verify fail", () => {
      const wrapper = new SHAWrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      const toVerify = "This Is Not The Same";
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
      const verified = wrapper.verify256(hashed, toVerifyBytes);
      assert.equal(false, verified);
    });
  });