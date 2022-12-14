# rpch-crypto

This crate implements the RPCh Crypto protocol as defined by the specs in the parent repository.
The implementation is WASM compatible and also exposes a TypeScript API via `wasm-bindgen`.

# Building

Rust >= 1.61 is required. Also `wasm-pack` is required for building, which can be installed as `cargo install wasm-pack`.

To install & build, simply run:

`make`

When rebuilding, don't forget to run `make clean` first before running `make`.

# Publishing a new release

1. Create branch based from `main` with a name like `release/<new-version>`
2. Update version with `<new-version>` in `Cargo.toml`
3. Create a PR on GitHub for the new version titled `Release <new-version>`
4. Wait for successful release
5. Merge to main
6. Create a new release on GitHub titled `<new-version>` and publish it
   - Also use `create new tag` option and set it to `<new-version>`
