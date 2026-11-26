import { Argon2Wrapper, BCryptWrapper, Pbkdf2Wrapper, ScryptWrapper } from "cas-typescript-sdk";
import { PASSWORD, randomBytes } from "../payloads";
import { Categories, defineSuite, expectTrue } from "../registry";

const argon2 = new Argon2Wrapper();
const bcrypt = new BCryptWrapper();
const scrypt = new ScryptWrapper();
const pbkdf2 = new Pbkdf2Wrapper();

/** The lowest iteration count Pbkdf2Wrapper accepts (PBKDF2-HMAC-SHA3-256). */
const PBKDF2_ITERATIONS = 600_000;

/**
 * Password hashers are slow on purpose. These measure the SDK's default cost
 * settings (hashPassword), which is what most callers get; tune with
 * hashPasswordWithParameters and compare against these numbers.
 */
export const passwordHasherBenchmarks = defineSuite({
  name: "PasswordHasherBenchmarks",
  categories: [Categories.PasswordHashing],
  setup: () => {
    const passwordBytes = Array.from(Buffer.from(PASSWORD, "utf8"));
    return {
      passwordBytes,
      argon2Hash: argon2.hashPassword(PASSWORD),
      bcryptHash: bcrypt.hashPassword(PASSWORD),
      scryptHash: scrypt.hashPassword(PASSWORD),
      argon2Salt: argon2.generateSalt(),
      pbkdf2Salt: randomBytes(16, 13),
    };
  },
  benchmarks: [
    { name: "Argon2Hash", fn: () => argon2.hashPassword(PASSWORD) },
    { name: "Argon2Verify", fn: (c) => expectTrue(argon2.verify(c.argon2Hash, PASSWORD), "Argon2Wrapper.verify") },
    { name: "Argon2DeriveAes256Key", fn: (c) => argon2.deriveAes256KeyWithSalt(c.passwordBytes, c.argon2Salt) },
    { name: "BcryptHash", fn: () => bcrypt.hashPassword(PASSWORD) },
    { name: "BcryptVerify", fn: (c) => expectTrue(bcrypt.verify(c.bcryptHash, PASSWORD), "BCryptWrapper.verify") },
    { name: "ScryptHash", fn: () => scrypt.hashPassword(PASSWORD) },
    { name: "ScryptVerify", fn: (c) => expectTrue(scrypt.verify(c.scryptHash, PASSWORD), "ScryptWrapper.verify") },
    {
      name: "Pbkdf2Derive600k",
      fn: (c) => pbkdf2.deriveWithSalt(c.passwordBytes, PBKDF2_ITERATIONS, c.pbkdf2Salt),
    },
  ],
});
