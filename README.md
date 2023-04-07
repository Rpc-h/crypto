# rpch-crypto

This crate implements the RPCh Crypto protocol as defined by the specs in the parent repository.
The implementation is WASM compatible and also exposes a TypeScript API via `wasm-bindgen`.

## Distributions

| target     | usage             | description                                                                                                                           | example |
| ---------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| web        | Native in browser | Can be natively imported as an ES module in a browser, but must be manually instantiated and loaded.                                  |
| nodejs     | nodeJS            | Uses CommonJS modules, for use with a require statement.                                                                              |
| no-modules | Native in browser | Same as web, except the JS is included on a page and modifies global state, and doesn't support as many wasm-bindgen features as web. |
| bundler    | bundler           | Suitable for interoperation with a Bundler like Webpack.                                                                              |

## Building

Rust >= 1.61 is required. Also `wasm-pack >=0.11.0` is required for building, which can be installed as `cargo install wasm-pack`.

To install & build, simply run:

`make`

When rebuilding, don't forget to run `make clean` first before running `make`.

# Maintainers

## Publishing a new release

1. Create branch based from `main` with a name like `release/<new-version>`
2. Update version with `<new-version>` in `Cargo.toml`
3. Create a PR on GitHub for the new version titled `Release <new-version>`
4. Wait for successful release
5. Merge to main
6. Create a new release on GitHub titled `<new-version>` and publish it
   - Also use `create new tag` option and set it to `<new-version>`
