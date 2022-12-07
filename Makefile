.PHONY := all clean build test

all: clean build test

clean:
	rm -rf `pwd`/pkg

build:
	mkdir -p `pwd`/pkg
	wasm-pack build --target=bundler `pwd`

test:
	cargo test --manifest-path `pwd`/Cargo.toml && wasm-pack test --node `pwd`
