# rpch-crypto

This crate implements the RPCh Crypto protocol as defined by the specs in the parent repository.
The implementation is WASM compatible and also exposes a TypeScript API via `wasm-bindgen`.

# Building

Rust >= 1.61 is required. Also `wasm-pack` is required for building, which can be installed as `cargo install wasm-pack`.

To install & build, simply run:

`make`

When rebuilding, don't forget to run `make clean` first before running `make`.
