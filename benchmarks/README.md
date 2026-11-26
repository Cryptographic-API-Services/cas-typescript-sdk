# cas-typescript-sdk benchmarks

[tinybench](https://github.com/tinylibs/tinybench) suite for the SDK's public API. Each benchmark calls a wrapper the way an application would: the suites import `cas-typescript-sdk`, which resolves to this package's own compiled `lib/`, so the numbers include converting `Array<number>` inputs and outputs across the N-API boundary as well as the Rust cryptography.

| Suite | What it measures |
| --- | --- |
| `HasherBenchmarks` | SHA3-256/512, SHA-256/512, BLAKE2s-256, BLAKE2b-512 over 1 KiB and 1 MiB |
| `HmacBenchmarks` | HMAC-SHA256 and HMAC-SHA512 sign and verify over 1 KiB and 1 MiB |
| `SymmetricBenchmarks` | AES-128/256-GCM, AES-128/256-GCM-SIV, ChaCha20-Poly1305, Ascon-128 seal and open over 1 KiB and 1 MiB |
| `AesKeyWrapBenchmarks` | AES-256 key wrap (RFC 3394) and key wrap with padding (RFC 5649) of a 32-byte key |
| `RsaBenchmarks` | RSA PKCS#1 v1.5 and PSS sign and verify, 2048- and 4096-bit keys |
| `RsaKeyGenerationBenchmarks` | RSA-2048 key generation |
| `Ed25519Benchmarks` | Ed25519 key generation, sign, verify |
| `X25519Benchmarks` | X25519 key generation and shared secret |
| `HpkeBenchmarks` | HPKE key generation, encrypt, decrypt (1 KiB) |
| `MlKemBenchmarks` | ML-KEM-1024 key generation, encapsulate, decapsulate |
| `MlDsaBenchmarks` | ML-DSA-65 key generation, sign, verify |
| `SlhDsaBenchmarks` | SLH-DSA-SHAKE-128f key generation, sign, verify |
| `PasswordHasherBenchmarks` | Argon2, bcrypt and scrypt hash and verify at the default cost, Argon2 key derivation, PBKDF2 at 600,000 iterations |
| `ZstdBenchmarks` | Zstd compress and decompress 1 MiB at levels 1, 3 and 19 |

Inputs are deterministic (seeded), so every run hashes and encrypts the same bytes. Keys, ciphertexts and signatures are made in each suite's `setup`, outside the timed code. Verify benchmarks fail if the call returns `false`, so they can't end up timing the rejection path.

## Running locally

Build the native addon first (`npm run build:rust`, see the root `CLAUDE.md`); `npm run bench` compiles `lib/` and the suite itself, then runs it. Arguments after `--` go to the runner.

```bash
# Everything, with the quick short job (a few minutes)
npm run bench

# One suite or benchmark (a glob over <Suite>.<Benchmark>, case-insensitive), or one category
npm run bench -- --filter '*Hasher*'
npm run bench -- --filter 'MlKem*' --filter 'MlDsaBenchmarks.Sign'
npm run bench -- --category PostQuantum

# Check every benchmark still runs (each runs once; the timings mean nothing)
npm run bench -- --job dry

# More accurate numbers
npm run bench -- --filter '*Symmetric*' --job medium

# List the benchmarks a filter selects, or show every option
npm run bench -- --list --category KeyGeneration
npm run bench -- --help
```

Jobs: `dry` (one call, no warmup), `short` (default: 100 ms warmup, then at least 500 ms and 5 calls), `medium` (250 ms warmup, at least 2 s and 10 calls) and `long` (1 s warmup, at least 5 s and 20 calls). Slow operations such as password hashing take the minimum number of calls; fast ones fill the time budget.

Categories: `Hashing`, `Symmetric`, `Asymmetric`, `PostQuantum`, `PasswordHashing`, `Compression`, `KeyGeneration`.

The console shows one table per suite (and per parameter value): mean, median (p50) and p99 time per call, the relative margin of error of the mean (`±`), calls per second and the number of samples. The run also writes `results.json` (every statistic, plus the environment) and `results.md` (the tables as GitHub Markdown) to `benchmarks/results/` (ignored by git), or to the directory given with `--out <dir>`.

The runner exits with a non-zero code if any benchmark (or a suite's setup) throws.

## CI

`.github/workflows/benchmarks.yml` runs the suite on `ubuntu-latest` with Node.js 26.13.1:

- **Pull requests:** a dry run (`--job dry`), so a PR that breaks a benchmark fails. The timings aren't meaningful.
- **Push to `main`:** a `--job short` run. The results table is in the run's job summary, and `results.json` and `results.md` are in its `benchmark-results` artifact for 90 days.
- **Manual (`workflow_dispatch`):** choose the `--filter`, a `--category` and the job (`dry`, `short`, `medium`, `long`).

Hosted runners are shared VMs: compare runs on the same runner type, and expect a few percent of noise.

## Adding a benchmark

Add an entry to the `benchmarks` array of the suite for its category under `suites/`, or a new suite made with `defineSuite` (and add it to `suites/index.ts`). Build inputs in the suite's `setup`, not in `fn`, and wrap verify-style calls in `expectTrue`. When you add an algorithm to the SDK, add its benchmark in the same change.
