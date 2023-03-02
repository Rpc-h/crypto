{ pkgs ? import <nixpkgs> { }, ... }:
let
  linuxPkgs = with pkgs; lib.optional stdenv.isLinux (
    inotifyTools
  );
  macosPkgs = with pkgs; lib.optional stdenv.isDarwin (
    with darwin.apple_sdk.frameworks; [
      # macOS file watcher support
      CoreFoundation
      CoreServices
    ]
  );
in
with pkgs;
mkShell {
  buildInputs = [
    ## rust for core development and required utils
    (rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
    wasm-pack

    # custom pkg groups
    macosPkgs
    linuxPkgs
  ];
}
