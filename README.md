# CAS TypeScript SDK

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/UAGqKfmvUS)

## Overview

CAS TypeScript SDK is a comprehensive cryptographic toolkit for Node.js, designed to provide developers with a unified, high-level interface to industry-standard cryptographic algorithms. This library acts as an abstraction layer over the powerful RustCrypto and Dalek-Cryptography suites, enabling secure and efficient cryptographic operations through a simple TypeScript API.

- **Official NPM Package:** [cas-typescript-sdk](https://www.npmjs.com/package/cas-typescript-sdk)
- **cas-lib version:** 2.x wraps [cas-lib 0.7.1](https://github.com/Cryptographic-API-Services/cas-lib/releases/tag/v0.7.1), pinned exactly in `Cargo.toml`.
- **Release notes:** [Changelog](./CHANGELOG.md)

> **Upgrading from 1.x?** 2.0 has breaking changes: RSA signatures, X25519-derived keys, PBKDF2 minimums, password-hasher bounds, zstd limits and more. Read the [2.0 migration guide](./docs/MIGRATING-2.0.md) before you upgrade.

## Features
- Modern cryptographic primitives: symmetric encryption, asymmetric encryption, digital signatures, hashing, password hashing, key exchange, and more
- Seamless integration with [cas-lib](https://github.com/Cryptographic-API-Services/cas-lib) Rust FFI layer for optimal performance
- TypeScript-first API for type safety and developer productivity
- Unified interface: no need to manage multiple cryptography packages or surf disparate documentation
- Built on trusted, open-source cryptography libraries

## Supported Node.js Versions
The SDK is built and tested against the Node.js LTS release lines:

| Node.js | Tested in CI |
| --- | --- |
| 22.x | Linux, macOS, Windows |
| 24.x | Linux, macOS, Windows |
| 26.x | Linux, macOS, Windows |

The published native addon is compiled once, on Node.js 26, against Node-API (N-API). Node-API is ABI-stable across Node.js versions, so the same prebuilt binary loads on every supported release line. Prebuilt binaries ship for Linux x64 (glibc and musl), Windows x64 and macOS x64.

## Secret key material
The native addon installs [`ZeroAlloc`](https://crates.io/crates/zeroizing-alloc) as its global allocator, so Rust heap memory is zeroed when it is freed. That covers the copies of keys, passwords and shared secrets that the Rust layer and [cas-lib](https://github.com/Cryptographic-API-Services/cas-lib) make while they work.

It does not cover the JavaScript side. Secrets you pass in as `Array<number>` or `string`, and secrets the SDK returns to you (generated keys, private keys, shared secrets, derived keys), live on the V8 heap. They stay there until the garbage collector reclaims them, and neither the SDK nor your code can reliably wipe them: V8 may copy, intern or move strings and arrays. So:

- keep secrets in scope only as long as you need them, and don't cache, log or serialize them;
- prefer byte arrays over strings for secrets, and overwrite them (e.g. `key.fill(0)`) when you are done, knowing this only clears that one copy.

## Documentation & References
We build on the work of leading cryptography projects. For in-depth algorithm details and implementation notes, please refer to:
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)

## Usage Examples
See practical usage and code samples in our [Examples](./docs/EXAMPLES.md). Release notes are in the [Changelog](./CHANGELOG.md), and upgrade steps from 1.x are in the [2.0 migration guide](./docs/MIGRATING-2.0.md).

## Benchmarks
A [tinybench](https://github.com/tinylibs/tinybench) suite covering every algorithm lives in [`benchmarks/`](./benchmarks/README.md). Build the native addon with `npm run build:rust`, then run it with `npm run bench`. CI runs it on every push to `main` and publishes the results with the workflow run.

## Disclaimer
This SDK leverages several cryptographic crates via our core FFI [layer](./src). Please note that many of these crates have not undergone formal security audits. Use this library at your own risk and always review the underlying cryptographic implementations for your security requirements.

---
For questions, support, or to contribute, join our Discord or visit the [GitHub repository](https://github.com/Cryptographic-API-Services/cas-typescript-sdk).


