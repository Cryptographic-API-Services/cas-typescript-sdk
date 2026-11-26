import { Blake2Wrapper, HmacWrapper, SHA2Wrapper, SHAWrapper } from "cas-typescript-sdk";
import { formatSize, ONE_KIB, ONE_MIB, randomBytes } from "../payloads";
import { Categories, defineSuite, expectTrue } from "../registry";

const sizes = { name: "size", values: [ONE_KIB, ONE_MIB], format: formatSize };

const sha3 = new SHAWrapper();
const sha2 = new SHA2Wrapper();
const blake2 = new Blake2Wrapper();
const hmac = new HmacWrapper();

export const hasherBenchmarks = defineSuite({
  name: "HasherBenchmarks",
  categories: [Categories.Hashing],
  params: sizes,
  setup: (size: number) => ({ data: randomBytes(size) }),
  benchmarks: [
    { name: "Sha3_256", fn: (c) => sha3.hash256(c.data) },
    { name: "Sha3_512", fn: (c) => sha3.hash512(c.data) },
    { name: "Sha256", fn: (c) => sha2.hash256(c.data) },
    { name: "Sha512", fn: (c) => sha2.hash512(c.data) },
    { name: "Blake2s_256", fn: (c) => blake2.hash256(c.data) },
    { name: "Blake2b_512", fn: (c) => blake2.hash512(c.data) },
  ],
});

export const hmacBenchmarks = defineSuite({
  name: "HmacBenchmarks",
  categories: [Categories.Hashing],
  params: sizes,
  setup: (size: number) => {
    const key = randomBytes(32, 7);
    const data = randomBytes(size);
    return {
      key,
      data,
      sha256Tag: hmac.hmacSignBytes(key, data),
      sha512Tag: hmac.hmacSha512SignBytes(key, data),
    };
  },
  benchmarks: [
    { name: "HmacSha256Sign", fn: (c) => hmac.hmacSignBytes(c.key, c.data) },
    {
      name: "HmacSha256Verify",
      fn: (c) => expectTrue(hmac.hmacVerifyBytes(c.key, c.data, c.sha256Tag), "hmacVerifyBytes"),
    },
    { name: "HmacSha512Sign", fn: (c) => hmac.hmacSha512SignBytes(c.key, c.data) },
    {
      name: "HmacSha512Verify",
      fn: (c) => expectTrue(hmac.hmacSha512VerifyBytes(c.key, c.data, c.sha512Tag), "hmacSha512VerifyBytes"),
    },
  ],
});
