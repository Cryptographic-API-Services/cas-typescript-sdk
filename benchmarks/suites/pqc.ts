import { MlDsa65Wrapper, MlKem1024Wrapper, SlhDsaWrapper } from "cas-typescript-sdk";
import { ONE_KIB, randomBytes } from "../payloads";
import { Categories, defineSuite, expectTrue } from "../registry";

const mlKem = new MlKem1024Wrapper();
const mlDsa = new MlDsa65Wrapper();
const slhDsa = new SlhDsaWrapper();

export const mlKemBenchmarks = defineSuite({
  name: "MlKemBenchmarks",
  categories: [Categories.PostQuantum],
  setup: () => {
    const keyPair = mlKem.generateKeyPair();
    return { keyPair, encapsulated: mlKem.encapsulate(keyPair.publicKey) };
  },
  benchmarks: [
    { name: "GenerateKeyPair", categories: [Categories.KeyGeneration], fn: () => mlKem.generateKeyPair() },
    { name: "Encapsulate", fn: (c) => mlKem.encapsulate(c.keyPair.publicKey) },
    { name: "Decapsulate", fn: (c) => mlKem.decapsulate(c.keyPair.secretKey, c.encapsulated.ciphertext) },
  ],
});

export const mlDsaBenchmarks = defineSuite({
  name: "MlDsaBenchmarks",
  categories: [Categories.PostQuantum],
  setup: () => {
    const message = randomBytes(ONE_KIB);
    const keyPair = mlDsa.generateKeyPair();
    return { message, keyPair, signature: mlDsa.sign(message, keyPair.signingKey) };
  },
  benchmarks: [
    { name: "GenerateKeyPair", categories: [Categories.KeyGeneration], fn: () => mlDsa.generateKeyPair() },
    { name: "Sign", fn: (c) => mlDsa.sign(c.message, c.keyPair.signingKey) },
    {
      name: "Verify",
      fn: (c) => expectTrue(mlDsa.verify(c.message, c.signature, c.keyPair.verificationKey), "MlDsa65Wrapper.verify"),
    },
  ],
});

export const slhDsaBenchmarks = defineSuite({
  name: "SlhDsaBenchmarks",
  categories: [Categories.PostQuantum],
  setup: () => {
    const message = randomBytes(ONE_KIB);
    const keyPair = slhDsa.generateKeyPair();
    return { message, keyPair, signature: slhDsa.sign(message, keyPair.signingKey) };
  },
  benchmarks: [
    { name: "GenerateKeyPair", categories: [Categories.KeyGeneration], fn: () => slhDsa.generateKeyPair() },
    { name: "Sign", fn: (c) => slhDsa.sign(c.message, c.keyPair.signingKey) },
    {
      name: "Verify",
      fn: (c) => expectTrue(slhDsa.verify(c.message, c.signature, c.keyPair.verificationKey), "SlhDsaWrapper.verify"),
    },
  ],
});
