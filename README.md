# eas-typescript-sdk

The official NPM page can be found [here](https://www.npmjs.com/package/cas-typescript-sdk).

## Consuming Library Documentation
**Note: All work is experimental and we understand some benchmarks might not be the most optimal.**

This Node.js NPM module is dependent on our Rust layer that contains methods to run industry standard cryptographic operations sequentially, on threads, and the thread pool. [cas-core-lib](https://github.com/Crytographic-API-Services/cas-core-lib).
This requires an install of the Rust programming language. You can find instructions to do that [here](https://www.rust-lang.org/tools/install).

## Disclaimer
Many of the cryptographic crates that are utilized in our core FFI [layer](https://github.com/Crytographic-API-Services/cas-core-lib) have never had a security audit performed. Utilize this SDK at your own risk.
