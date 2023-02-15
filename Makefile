# the name of our library, using scoped NPM syntax
NAME := @rpch/crypto
# the version of our library, taken from Cargo.toml
VERSION := $(shell sed -n 's/^ *version.*=.*"\([^"]*\)".*/\1/p' Cargo.toml)
# which targets to build, see wasm-pack build --targets
TARGETS := nodejs web no-modules
# the directory of the folder we will be publishing
NPM_PKG_DIR := `pwd`/pkg
# the package.json of our package
NPM_PKG_JSON = '{ \
	"name": "${NAME}", \
	"version": "$(VERSION)", \
	"files": ["**/*"], \
	"module": "./index.js", \
	"typing": "./index.d.ts" \
}'

# uses wasm-pack and builds files for a given target
# additionally updates the generated package.json to include "main" entry
# $(1) = target
define build_for_target
	mkdir -p $(NPM_PKG_DIR);
	wasm-pack build --target=$(1) --out-dir $(NPM_PKG_DIR)/$(1) `pwd`;
	jq -r '.main |= "rpch_crypto.js"' $(NPM_PKG_DIR)/$(1)/package.json > $(NPM_PKG_DIR)/$(1)/package.json.tmp;
	mv $(NPM_PKG_DIR)/$(1)/package.json.tmp $(NPM_PKG_DIR)/$(1)/package.json;
endef

# generate npm package folder to be packed for publishing
define generate_npm_package_folder
	mkdir -p $(NPM_PKG_DIR);
	touch $(NPM_PKG_DIR)/index.js;
	touch $(NPM_PKG_DIR)/index.d.ts;
	echo $(NPM_PKG_JSON) > $(NPM_PKG_DIR)/package.json;
endef

.PHONY := all clean build test

all: clean build test

clean:
	rm -rf $(NPM_PKG_DIR)
	cargo clean

build:
	$(foreach target,$(TARGETS),$(call build_for_target,$(target)))
	$(call generate_npm_package_folder)

test:
	cargo test --manifest-path `pwd`/Cargo.toml && wasm-pack test --node `pwd`
