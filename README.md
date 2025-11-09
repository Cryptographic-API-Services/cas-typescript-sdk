# CAS TypeScript SDK

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/UAGqKfmvUS)

## Overview

CAS TypeScript SDK is a comprehensive cryptographic toolkit for Node.js, designed to provide developers with a unified, high-level interface to industry-standard cryptographic algorithms. This library acts as an abstraction layer over the powerful RustCrypto and Dalek-Cryptography suites, enabling secure and efficient cryptographic operations through a simple TypeScript API.

- **Official NPM Package:** [cas-typescript-sdk](https://www.npmjs.com/package/cas-typescript-sdk)

## Features
- Modern cryptographic primitives: symmetric encryption, asymmetric encryption, digital signatures, hashing, password hashing, key exchange, and more
- Seamless integration with [cas-lib](https://github.com/Cryptographic-API-Services/cas-lib) Rust FFI layer for optimal performance
- TypeScript-first API for type safety and developer productivity
- Unified interface: no need to manage multiple cryptography packages or surf disparate documentation
- Built on trusted, open-source cryptography libraries

## Documentation & References
We build on the work of leading cryptography projects. For in-depth algorithm details and implementation notes, please refer to:
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)

## Usage Examples
See practical usage and code samples in our [Examples](./docs/EXAMPLES.md).

## Disclaimer
This SDK leverages several cryptographic crates via our core FFI [layer](./src). Please note that many of these crates have not undergone formal security audits. Use this library at your own risk and always review the underlying cryptographic implementations for your security requirements.

---
For questions, support, or to contribute, join our Discord or visit the [GitHub repository](https://github.com/Cryptographic-API-Services/cas-typescript-sdk).


