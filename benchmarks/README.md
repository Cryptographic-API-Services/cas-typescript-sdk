# Benchmarks

Micro-benchmarks for the `cas-typescript-sdk` wrappers, powered by
[mitata](https://github.com/evanwashere/mitata).

The benchmarks import the wrappers from `src-ts/` directly (just like the tests),
and the wrappers `require` the native binding from the repo-root `index.js`. So
you **must** build the native addon before running them:

```bash
npm run build:rust   # produces the *.node binding + index.js/index.d.ts
npm run bench        # runs every benchmark suite
```

## Available suites

| Script | File | Covers |
| --- | --- | --- |
| `npm run bench:password-hashers` | `password-hashers.bench.ts` | Argon2, BCrypt, Scrypt — `hashPassword`, `verify`, and `hashPasswordWithParameters` |
| `npm run bench:symmetric` | `symmetric.bench.ts` | AES-128/256-GCM encrypt + decrypt — CAS (`cas-lib`) vs. Node's built-in `crypto` across 1 KiB / 64 KiB / 1 MiB payloads |

`npm run bench` currently aliases the password-hashers suite. As more suites are
added, give each its own `bench:<domain>` script and point `bench` at a runner
that executes them all.

## How it's organized

Each suite groups related cases with mitata's `group()` and wraps comparable
algorithms in `summary()` so the output reports relative throughput (e.g. how
much faster BCrypt-default is than Argon2-default). Any one-time setup — such as
pre-computing a digest for the `verify` cases — happens outside the measured
`bench()` callbacks.

## Adding a new suite

1. Create `benchmarks/<domain>.bench.ts`.
2. Import the wrappers from `../src-ts/<domain>`.
3. Use `group` / `summary` / `bench` from `mitata`, then call `run()` at the end.
4. Add a `bench:<domain>` script to `package.json`.
