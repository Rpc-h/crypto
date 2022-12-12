# rpch-crypto

This crate implements the RPCh Crypto protocol as defined by the specs in the parent repository.
The implementation is WASM compatible and also exposes a TypeScript API via `wasm-bindgen`.

# Building

Rust >= 1.61 is required. Also `wasm-pack` is required for building, which can be installed as `cargo install wasm-pack`.

To install & build, simply run:

`make`

When rebuilding, don't forget to run `make clean` first before running `make`.

# Publishing

Currently, the publishing for this library is done manually.

1. Create a PR on GitHub for the new version
2. Update version in `Cargo.toml` to the new version
3. Merge to main
4. Manually create a new release and publish it
