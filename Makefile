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

# Release artifacts (vX.Y.Z). Builds cross-platform CLI binaries and
# linux-amd64 engine release binaries, then assembles a
# self-contained distribution tarball for binary consumers (set
# BLOCKTACK_ROOT to the extracted dir and BLOCKTACK_ENGINES to
# <dir>/engines). Usage: make release VERSION=v0.1.0
release: engine
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=v0.1.0" >&2; exit 2; }
	rm -rf dist && mkdir -p dist
	go build -trimpath -ldflags "-s -w" -o dist/blocktack-linux-amd64 ./cmd/blocktack
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/blocktack-darwin-arm64 ./cmd/blocktack
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/blocktack-darwin-amd64 ./cmd/blocktack
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/blocktack-windows-amd64.exe ./cmd/blocktack
	cp engine-evm/target/release/blocktack-evm dist/
	cp engine-solana/target/release/blocktack-solana dist/
	mkdir -p dist/blocktack-$(VERSION)-linux-amd64/bin dist/blocktack-$(VERSION)-linux-amd64/engines
	cp dist/blocktack-linux-amd64 dist/blocktack-$(VERSION)-linux-amd64/bin/blocktack
	cp dist/blocktack-evm dist/blocktack-solana dist/blocktack-$(VERSION)-linux-amd64/engines/
	cp -r taxonomy playbooks corpus examples dist/blocktack-$(VERSION)-linux-amd64/
	cp README.md LICENSE dist/blocktack-$(VERSION)-linux-amd64/ 2>/dev/null || true
	tar -czf dist/blocktack-$(VERSION)-linux-amd64.tar.gz -C dist blocktack-$(VERSION)-linux-amd64
	cd dist && sha256sum blocktack-linux-amd64 blocktack-darwin-* blocktack-windows-* blocktack-$(VERSION)-*.tar.gz blocktack-evm blocktack-solana > sha256sums.txt
	@echo "release artifacts in dist/"
