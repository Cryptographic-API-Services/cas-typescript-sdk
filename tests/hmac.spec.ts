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
