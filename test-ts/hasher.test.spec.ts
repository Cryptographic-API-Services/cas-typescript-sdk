import { assert } from "chai";
import { Blake2Wrapper, SHAWrapper } from "../src-ts/hashers/index";

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

describe("Blake2 512", () => {
  it("hash", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    assert.notEqual(tohashBytes, hashed);
  });

  it("verify pass", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    assert.equal(true, verified);
  });

  it("verify fail", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerify = "This Is Not The Same";
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    assert.equal(false, verified);
  });

  it("hash threadpool", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512Threadpool(tohashBytes);
    assert.notEqual(tohashBytes, hashed);
  });

  it("verify threadpool pass", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512Threadpool(tohashBytes);
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const verified = wrapper.verify512Threadpool(hashed, toVerifyBytes);
    assert.equal(true, verified);
  });

  it("verify threadpool fail", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512Threadpool(tohashBytes);
    const toVerify = "This Is Not The Same";
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
    const verified = wrapper.verify512Threadpool(hashed, toVerifyBytes);
    assert.equal(false, verified);
  });

  describe("Blake2 256", () => {
    it("hash", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      assert.notEqual(tohashBytes, hashed);
    });

    it("verify pass", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const verified = wrapper.verify256(hashed, toVerifyBytes);
      assert.equal(true, verified);
    });

    it("verify fail", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      const toVerify = "This Is Not The Same";
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
      const verified = wrapper.verify256(hashed, toVerifyBytes);
      assert.equal(false, verified);
    });

    it("hash threadpool", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256Threadpool(tohashBytes);
      assert.notEqual(tohashBytes, hashed);
    });

    it("verify threadpool pass", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256Threadpool(tohashBytes);
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const verified = wrapper.verify256Threadpool(hashed, toVerifyBytes);
      assert.equal(true, verified);
    });

    it("verify threadpool fail", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256Threadpool(tohashBytes);
      const toVerify = "This Is Not The Same";
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
      const verified = wrapper.verify256Threadpool(hashed, toVerifyBytes);
      assert.equal(false, verified);
    });
  });
});