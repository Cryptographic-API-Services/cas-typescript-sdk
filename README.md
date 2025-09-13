# cas-typescript-sdk

[![image](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/7bXXCQj45q)

Ever wanted all of your most useful cryptographic operations in one module and not had to surf documentation for various packages? 
CAS is here to provide a unified development experience as an abstract layer to the RustCrypto and Dalek-Cryptography suite of algorithms.
The official NPM page can be found [here](https://www.npmjs.com/package/cas-typescript-sdk).

**Note: All work is experimental and we understand some benchmarks might not be the most optimal.**\

## Consuming Library Documentation
This Node.js NPM module is dependent on our Rust layer [cas-lib](https://github.com/Cryptographic-API-Services/cas-lib) that contains methods to run industry-standard cryptographic operations.

We utilize some smart people's existing work and we believe their documentation should be reviewed when possible.
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)

## [Examples](./docs/EXAMPLES.md)

## Disclaimer
Many of the cryptographic crates that are utilized in our core FFI [layer](./src) have never had a security audit performed. Utilize this SDK at your own risk.
