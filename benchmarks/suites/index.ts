import type { Suite } from "../registry";
import {
  ed25519Benchmarks,
  hpkeBenchmarks,
  rsaBenchmarks,
  rsaKeyGenerationBenchmarks,
  x25519Benchmarks,
} from "./asymmetric";
import { zstdBenchmarks } from "./compression";
import { hasherBenchmarks, hmacBenchmarks } from "./hashers";
import { passwordHasherBenchmarks } from "./password-hashers";
import { mlDsaBenchmarks, mlKemBenchmarks, slhDsaBenchmarks } from "./pqc";
import { aesKeyWrapBenchmarks, symmetricBenchmarks } from "./symmetric";

/** Every suite, in the order they run. Register a new suite here. */
export const suites: Suite[] = [
  hasherBenchmarks,
  hmacBenchmarks,
  symmetricBenchmarks,
  aesKeyWrapBenchmarks,
  rsaBenchmarks,
  rsaKeyGenerationBenchmarks,
  ed25519Benchmarks,
  x25519Benchmarks,
  hpkeBenchmarks,
  mlKemBenchmarks,
  mlDsaBenchmarks,
  slhDsaBenchmarks,
  passwordHasherBenchmarks,
  zstdBenchmarks,
];
