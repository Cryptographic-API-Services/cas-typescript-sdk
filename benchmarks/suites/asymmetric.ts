import { Ed25519Wrapper, HpkeWrapper, RSAWrapper, X25519Wrapper } from "cas-typescript-sdk";
import { ONE_KIB, randomBytes } from "../payloads";
import { Categories, defineSuite, expectTrue } from "../registry";

const rsa = new RSAWrapper();
const ed25519 = new Ed25519Wrapper();
const x25519 = new X25519Wrapper();
const hpke = new HpkeWrapper();

export const rsaBenchmarks = defineSuite({
  name: "RsaBenchmarks",
  categories: [Categories.Asymmetric],
  params: { name: "keySize", values: [2048, 4096] },
  setup: (keySize: number) => {
    const message = randomBytes(ONE_KIB);
    const keyPair = rsa.getKeyPair(keySize);
    return {
      message,
      keyPair,
      signature: rsa.sign(keyPair.privateKey, message),
      pssSignature: rsa.signPss(keyPair.privateKey, message),
    };
  },
  benchmarks: [
    { name: "Pkcs1Sign", fn: (c) => rsa.sign(c.keyPair.privateKey, c.message) },
    {
      name: "Pkcs1Verify",
      fn: (c) => expectTrue(rsa.verify(c.keyPair.publicKey, c.message, c.signature), "RSAWrapper.verify"),
    },
    { name: "PssSign", fn: (c) => rsa.signPss(c.keyPair.privateKey, c.message) },
    {
      name: "PssVerify",
      fn: (c) => expectTrue(rsa.verifyPss(c.keyPair.publicKey, c.message, c.pssSignature), "RSAWrapper.verifyPss"),
    },
  ],
});

/**
 * RSA key generation searches for random primes, so its time varies widely from
 * one call to the next; expect a large ± column. 4096-bit takes seconds per key.
 */
export const rsaKeyGenerationBenchmarks = defineSuite({
  name: "RsaKeyGenerationBenchmarks",
  categories: [Categories.Asymmetric, Categories.KeyGeneration],
  setup: () => undefined,
  benchmarks: [{ name: "GenerateKeyPair2048", fn: () => rsa.getKeyPair(2048) }],
});

export const ed25519Benchmarks = defineSuite({
  name: "Ed25519Benchmarks",
  categories: [Categories.Asymmetric],
  setup: () => {
    const message = randomBytes(ONE_KIB);
    const keyPair = ed25519.getKeyPair();
    return { message, keyPair, signature: ed25519.signBytes(keyPair.privateKey, message) };
  },
  benchmarks: [
    { name: "GenerateKeyPair", categories: [Categories.KeyGeneration], fn: () => ed25519.getKeyPair() },
    { name: "Sign", fn: (c) => ed25519.signBytes(c.keyPair.privateKey, c.message) },
    {
      name: "Verify",
      fn: (c) => expectTrue(ed25519.verifyBytes(c.keyPair.publicKey, c.message, c.signature), "Ed25519Wrapper.verifyBytes"),
    },
  ],
});

export const x25519Benchmarks = defineSuite({
  name: "X25519Benchmarks",
  categories: [Categories.Asymmetric],
  setup: () => ({
    alice: x25519.generateSecretAndPublicKey(),
    bob: x25519.generateSecretAndPublicKey(),
  }),
  benchmarks: [
    {
      name: "GenerateKeyPair",
      categories: [Categories.KeyGeneration],
      fn: () => x25519.generateSecretAndPublicKey(),
    },
    { name: "SharedSecret", fn: (c) => x25519.generateSharedSecret(c.alice.secretKey, c.bob.publicKey) },
  ],
});

export const hpkeBenchmarks = defineSuite({
  name: "HpkeBenchmarks",
  categories: [Categories.Asymmetric],
  setup: () => {
    const plaintext = randomBytes(ONE_KIB);
    const keyPair = hpke.generateKeyPair();
    return { plaintext, keyPair, encrypted: hpke.encrypt(plaintext, keyPair.publicKey, keyPair.infoStr) };
  },
  benchmarks: [
    { name: "GenerateKeyPair", categories: [Categories.KeyGeneration], fn: () => hpke.generateKeyPair() },
    { name: "Encrypt", fn: (c) => hpke.encrypt(c.plaintext, c.keyPair.publicKey, c.keyPair.infoStr) },
    {
      name: "Decrypt",
      fn: (c) =>
        hpke.decrypt(
          c.encrypted.ciphertext,
          c.keyPair.secretKey,
          c.encrypted.encapsulatedKey,
          c.encrypted.tag,
          c.keyPair.infoStr,
        ),
    },
  ],
});
