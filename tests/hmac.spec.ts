import crypto from "node:crypto";
import {test, expect} from '@playwright/test';
import { HmacWrapper } from "../src-ts/message/index";

test.describe("HMAC Tests", () => {
  test("Sign and Verify", () => {
    const wrapper = new HmacWrapper();
    const key: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const keyBytes: Array<number> = Array.from(encoder.encode(key));
    const message: string = "This is my message";
    const messageBytes = Array.from(encoder.encode(message));
    const signature = wrapper.hmacSignBytes(keyBytes, messageBytes);
    const result = wrapper.hmacVerifyBytes(keyBytes, messageBytes, signature);
    expect(result).toBe(true);
  });
});

test.describe("HMAC empty message", () => {
  const key = Array.from(new TextEncoder().encode("This is my HMAC key"));
  const expected256 = Array.from(crypto.createHmac("sha256", Buffer.from(key)).update(Buffer.alloc(0)).digest());
  const expected512 = Array.from(crypto.createHmac("sha512", Buffer.from(key)).update(Buffer.alloc(0)).digest());

  test("signs and verifies an empty or null message", () => {
    const wrapper = new HmacWrapper();
    for (const message of [[], null, undefined]) {
      expect(wrapper.hmacSignBytes(key, message)).toEqual(expected256);
      expect(wrapper.hmacSha512SignBytes(key, message)).toEqual(expected512);
      expect(wrapper.hmacVerifyBytes(key, message, expected256)).toBe(true);
      expect(wrapper.hmacSha512VerifyBytes(key, message, expected512)).toBe(true);
    }
    expect(wrapper.hmacVerifyBytes(key, [0x61], expected256)).toBe(false);
  });
});
