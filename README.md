# eas-typescript-sdk

The official NPM page can be found [here](https://www.npmjs.com/package/cas-typescript-sdk).

## Consuming Library Documentation
**Note: All work is experimental and we understand some benchmarks might not be the most optimal.**

This Node.js NPM module is dependent on our Rust layer [here](./src) that contains methods to run industry standard cryptographic operations sequentially, on threads, and the thread pool.

## Consuming Library Documentation
We utilize some smart people's existing work and we believe their documentation should be reviewed when possible.
- [Spin Research](https://github.com/SpinResearch)
- [Dalek-Cryptography](https://github.com/dalek-cryptography)
- [Rust Crypto](https://github.com/RustCrypto)
- [Rayon](https://github.com/rayon-rs/rayon)

## Disclaimer
Many of the cryptographic crates that are utilized in our core FFI [layer](https://github.com/Crytographic-API-Services/cas-core-lib) have never had a security audit performed. Utilize this SDK at your own risk.
