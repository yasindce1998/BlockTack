BIN := bin/blocktack

.PHONY: build engine go-build test vet lint clean

build: go-build engine

go-build:
	go build -o $(BIN) ./cmd/blocktack

engine:
	cargo build --release --manifest-path engine-evm/Cargo.toml
	cargo build --release --manifest-path engine-solana/Cargo.toml

test:
	go test ./...
	cargo test --release --manifest-path engine-evm/Cargo.toml
	cargo test --release --manifest-path engine-solana/Cargo.toml

vet:
	go vet ./...

lint: vet
	cargo clippy --manifest-path engine-evm/Cargo.toml -- -D warnings

clean:
	rm -rf bin runs engine-evm/target
