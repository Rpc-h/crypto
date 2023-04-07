# the version of our library, taken from Cargo.toml
VERSION := $(shell sed -n 's/^ *version.*=.*"\([^"]*\)".*/\1/p' Cargo.toml)
# which targets to build, see wasm-pack build --targets
BUILD_TARGETS := nodejs web no-modules bundler
# the directory of the build output
OUTPUT_DIR := `pwd`/build-wasm

# build_for_target
# 1. uses wasm-pack and builds files for a given target
# 2. update generated "package.json" to include a "main" entry
# 3. update generated "package.json" with a name prefixed with the target of the build
# $(1) = target
define build_for_target
	wasm-pack build --target=bundler --out-dir $(OUTPUT_DIR)/$(1) --out-name index `pwd` --scope rpch;
	jq -r '.main = "index.js" | .name = "@rpch/crypto-via-$(1)"' $(OUTPUT_DIR)/$(1)/package.json > $(OUTPUT_DIR)/$(1)/package.json.tmp;
	mv $(OUTPUT_DIR)/$(1)/package.json.tmp $(OUTPUT_DIR)/$(1)/package.json;
endef

.PHONY := all clean build test

all: clean build test

clean:
	rm -rf $(OUTPUT_DIR)
	cargo clean

build:
	$(foreach target,$(BUILD_TARGETS),$(call build_for_target,$(target)))

test:
	cargo test --manifest-path `pwd`/Cargo.toml && wasm-pack test --node `pwd`
