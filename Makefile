# whspr build targets
.PHONY: all build test clean release docker \
        linux macos macos-intel macos-arm windows \
        client server install-deps

# Default target
all: build

# Development build
build:
	cargo build

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean
	rm -rf dist/

# Release build (current platform)
release:
	cargo build --release

# Docker build
docker:
	docker compose build

# Install cross-compilation dependencies
install-deps:
	rustup target add x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-gnu x86_64-unknown-linux-musl
	cargo install cargo-zigbuild
	@echo "NOTE: You also need Zig installed. Run: sudo snap install zig --classic --beta"

#
# Cross-compilation targets
#

DIST_DIR := dist

# Linux (static musl binary)
linux: $(DIST_DIR)/linux
$(DIST_DIR)/linux:
	mkdir -p $(DIST_DIR)/linux
	cargo zigbuild --release --target x86_64-unknown-linux-musl --package whspr-client
	cargo zigbuild --release --target x86_64-unknown-linux-musl --package whspr-server
	cp target/x86_64-unknown-linux-musl/release/whspr $(DIST_DIR)/linux/
	cp target/x86_64-unknown-linux-musl/release/whspr-server $(DIST_DIR)/linux/

# macOS Intel
macos-intel: $(DIST_DIR)/macos-intel
$(DIST_DIR)/macos-intel:
	mkdir -p $(DIST_DIR)/macos-intel
	cargo zigbuild --release --target x86_64-apple-darwin --package whspr-client
	cargo zigbuild --release --target x86_64-apple-darwin --package whspr-server
	cp target/x86_64-apple-darwin/release/whspr $(DIST_DIR)/macos-intel/
	cp target/x86_64-apple-darwin/release/whspr-server $(DIST_DIR)/macos-intel/

# macOS Apple Silicon
macos-arm: $(DIST_DIR)/macos-arm
$(DIST_DIR)/macos-arm:
	mkdir -p $(DIST_DIR)/macos-arm
	cargo zigbuild --release --target aarch64-apple-darwin --package whspr-client
	cargo zigbuild --release --target aarch64-apple-darwin --package whspr-server
	cp target/aarch64-apple-darwin/release/whspr $(DIST_DIR)/macos-arm/
	cp target/aarch64-apple-darwin/release/whspr-server $(DIST_DIR)/macos-arm/

# Both macOS architectures
macos: macos-intel macos-arm

# Windows
windows: $(DIST_DIR)/windows
$(DIST_DIR)/windows:
	mkdir -p $(DIST_DIR)/windows
	cargo zigbuild --release --target x86_64-pc-windows-gnu --package whspr-client
	cargo zigbuild --release --target x86_64-pc-windows-gnu --package whspr-server
	cp target/x86_64-pc-windows-gnu/release/whspr.exe $(DIST_DIR)/windows/
	cp target/x86_64-pc-windows-gnu/release/whspr-server.exe $(DIST_DIR)/windows/

# Build client only (all platforms)
client:
	mkdir -p $(DIST_DIR)/{linux,macos-intel,macos-arm,windows}
	cargo zigbuild --release --target x86_64-unknown-linux-musl --package whspr-client
	cargo zigbuild --release --target x86_64-apple-darwin --package whspr-client
	cargo zigbuild --release --target aarch64-apple-darwin --package whspr-client
	cargo zigbuild --release --target x86_64-pc-windows-gnu --package whspr-client
	cp target/x86_64-unknown-linux-musl/release/whspr $(DIST_DIR)/linux/
	cp target/x86_64-apple-darwin/release/whspr $(DIST_DIR)/macos-intel/
	cp target/aarch64-apple-darwin/release/whspr $(DIST_DIR)/macos-arm/
	cp target/x86_64-pc-windows-gnu/release/whspr.exe $(DIST_DIR)/windows/

# Build server only (all platforms)
server:
	mkdir -p $(DIST_DIR)/{linux,macos-intel,macos-arm,windows}
	cargo zigbuild --release --target x86_64-unknown-linux-musl --package whspr-server
	cargo zigbuild --release --target x86_64-apple-darwin --package whspr-server
	cargo zigbuild --release --target aarch64-apple-darwin --package whspr-server
	cargo zigbuild --release --target x86_64-pc-windows-gnu --package whspr-server
	cp target/x86_64-unknown-linux-musl/release/whspr-server $(DIST_DIR)/linux/
	cp target/x86_64-apple-darwin/release/whspr-server $(DIST_DIR)/macos-intel/
	cp target/aarch64-apple-darwin/release/whspr-server $(DIST_DIR)/macos-arm/
	cp target/x86_64-pc-windows-gnu/release/whspr-server.exe $(DIST_DIR)/windows/

# Build all platforms
dist: linux macos windows
	@echo "Build complete. Binaries in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/*/
