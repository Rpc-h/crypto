# uses wasm-pack and builds files for a given target
define build_for_target
	wasm-pack build --target=$(1) --out-dir `pwd`/pkg/$(1) `pwd`
	jq -r '.main |= "./rpch_crypto.js"' `pwd`/pkg/$(1)/package.json > package.json.tmp
	mv package.json.tmp `pwd`/pkg/$(1)/package.json
endef

.PHONY := all clean build test

all: clean build test

clean:
	rm -rf `pwd`/pkg

build:
	mkdir -p `pwd`/pkg
	$(call build_for_target,nodejs)
	$(call build_for_target,web)
	touch `pwd`/pkg/index.js
	touch `pwd`/pkg/index.d.ts
	echo '{ "module": "./index.js", "typing": "./index.d.ts" }' > `pwd`/pkg/package.json

test:
	cargo test --manifest-path `pwd`/Cargo.toml && wasm-pack test --node `pwd`
