import { run, bench, group, summary } from "mitata";

import {
  Argon2Wrapper,
  BCryptWrapper,
  ScryptWrapper,
} from "../src-ts/password-hashers";

// A representative password reused across every case so the benchmark
// measures the hasher cost, not string allocation.
const PASSWORD = "ThisOneBadPassword!@";

const argon2 = new Argon2Wrapper();
const bcrypt = new BCryptWrapper();
const scrypt = new ScryptWrapper();

// Pre-compute a hash per algorithm so the verify benchmarks have a valid
// digest to check against without hashing inside the measured loop.
const argon2Hash = argon2.hashPassword(PASSWORD);
const bcryptHash = bcrypt.hashPassword(PASSWORD);
const scryptHash = scrypt.hashPassword(PASSWORD);

group("hashPassword (default parameters)", () => {
  summary(() => {
    bench("Argon2", () => argon2.hashPassword(PASSWORD));
    bench("BCrypt", () => bcrypt.hashPassword(PASSWORD));
    bench("Scrypt", () => scrypt.hashPassword(PASSWORD));
  });
});

group("verify", () => {
  summary(() => {
    bench("Argon2", () => argon2.verify(argon2Hash, PASSWORD));
    bench("BCrypt", () => bcrypt.verify(bcryptHash, PASSWORD));
    bench("Scrypt", () => scrypt.verify(scryptHash, PASSWORD));
  });
});

group("hashPasswordWithParameters", () => {
  summary(() => {
    // Argon2: memoryCost (KiB), timeCost, parallelism
    bench("Argon2 (m=4096, t=3, p=1)", () =>
      argon2.hashPasswordWithParameters(PASSWORD, 4096, 3, 1),
    );
    // BCrypt: cost (work factor)
    bench("BCrypt (cost=12)", () =>
      bcrypt.hashPasswordWithParameters(PASSWORD, 12),
    );
    // Scrypt: cpuCost (log2 N), blockSize, parallelism
    bench("Scrypt (n=2^15, r=8, p=1)", () =>
      scrypt.hashPasswordWithParameters(PASSWORD, 15, 8, 1),
    );
  });
});

run();