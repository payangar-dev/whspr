# whspr build targets
.PHONY: all build test clean release docker \
        linux macos macos-intel macos-arm windows \
        client server install-deps

# Use cargo from rustup if not in PATH
CARGO := $(shell which cargo 2>/dev/null || echo "$(HOME)/.cargo/bin/cargo")
RUSTUP := $(shell which rustup 2>/dev/null || echo "$(HOME)/.cargo/bin/rustup")

# Default target
all: build

# Development build
build:
	$(CARGO) build

# Run tests
test:
	$(CARGO) test

# Clean build artifacts
clean:
	$(CARGO) clean
	rm -rf dist/

# Release build (current platform)
release:
	$(CARGO) build --release

# Docker build
docker:
	docker compose build

# Install cross-compilation dependencies
install-deps:
	$(RUSTUP) target add x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-gnu x86_64-unknown-linux-musl
	$(CARGO) install cargo-zigbuild
	@echo ""
	@echo "NOTE: You also need Zig installed. Run: sudo snap install zig --classic --beta"
	@echo ""
	@echo "WARNING: macOS cross-compilation requires macOS SDK."
	@echo "         Use 'make linux' or 'make windows' from Linux."
	@echo "         For macOS builds, use GitHub Actions (push a tag) or build on a Mac."

#
# Cross-compilation targets
#

DIST_DIR := dist

# Linux (static musl binary)
linux: $(DIST_DIR)/linux
$(DIST_DIR)/linux:
	mkdir -p $(DIST_DIR)/linux
	$(CARGO) zigbuild --release --target x86_64-unknown-linux-musl --package whspr-client
	$(CARGO) zigbuild --release --target x86_64-unknown-linux-musl --package whspr-server
	cp target/x86_64-unknown-linux-musl/release/whspr $(DIST_DIR)/linux/
	cp target/x86_64-unknown-linux-musl/release/whspr-server $(DIST_DIR)/linux/

# macOS Intel
macos-intel: $(DIST_DIR)/macos-intel
$(DIST_DIR)/macos-intel:
	mkdir -p $(DIST_DIR)/macos-intel
	$(CARGO) zigbuild --release --target x86_64-apple-darwin --package whspr-client
	$(CARGO) zigbuild --release --target x86_64-apple-darwin --package whspr-server
	cp target/x86_64-apple-darwin/release/whspr $(DIST_DIR)/macos-intel/
	cp target/x86_64-apple-darwin/release/whspr-server $(DIST_DIR)/macos-intel/

# macOS Apple Silicon
macos-arm: $(DIST_DIR)/macos-arm
$(DIST_DIR)/macos-arm:
	mkdir -p $(DIST_DIR)/macos-arm
	$(CARGO) zigbuild --release --target aarch64-apple-darwin --package whspr-client
	$(CARGO) zigbuild --release --target aarch64-apple-darwin --package whspr-server
	cp target/aarch64-apple-darwin/release/whspr $(DIST_DIR)/macos-arm/
	cp target/aarch64-apple-darwin/release/whspr-server $(DIST_DIR)/macos-arm/

# Both macOS architectures
macos: macos-intel macos-arm

# Windows
windows: $(DIST_DIR)/windows
$(DIST_DIR)/windows:
	mkdir -p $(DIST_DIR)/windows
	$(CARGO) zigbuild --release --target x86_64-pc-windows-gnu --package whspr-client
	$(CARGO) zigbuild --release --target x86_64-pc-windows-gnu --package whspr-server
	cp target/x86_64-pc-windows-gnu/release/whspr.exe $(DIST_DIR)/windows/
	cp target/x86_64-pc-windows-gnu/release/whspr-server.exe $(DIST_DIR)/windows/

# Build client only (all platforms)
client:
	mkdir -p $(DIST_DIR)/{linux,macos-intel,macos-arm,windows}
	$(CARGO) zigbuild --release --target x86_64-unknown-linux-musl --package whspr-client
	$(CARGO) zigbuild --release --target x86_64-apple-darwin --package whspr-client
	$(CARGO) zigbuild --release --target aarch64-apple-darwin --package whspr-client
	$(CARGO) zigbuild --release --target x86_64-pc-windows-gnu --package whspr-client
	cp target/x86_64-unknown-linux-musl/release/whspr $(DIST_DIR)/linux/
	cp target/x86_64-apple-darwin/release/whspr $(DIST_DIR)/macos-intel/
	cp target/aarch64-apple-darwin/release/whspr $(DIST_DIR)/macos-arm/
	cp target/x86_64-pc-windows-gnu/release/whspr.exe $(DIST_DIR)/windows/

# Build server only (all platforms)
server:
	mkdir -p $(DIST_DIR)/{linux,macos-intel,macos-arm,windows}
	$(CARGO) zigbuild --release --target x86_64-unknown-linux-musl --package whspr-server
	$(CARGO) zigbuild --release --target x86_64-apple-darwin --package whspr-server
	$(CARGO) zigbuild --release --target aarch64-apple-darwin --package whspr-server
	$(CARGO) zigbuild --release --target x86_64-pc-windows-gnu --package whspr-server
	cp target/x86_64-unknown-linux-musl/release/whspr-server $(DIST_DIR)/linux/
	cp target/x86_64-apple-darwin/release/whspr-server $(DIST_DIR)/macos-intel/
	cp target/aarch64-apple-darwin/release/whspr-server $(DIST_DIR)/macos-arm/
	cp target/x86_64-pc-windows-gnu/release/whspr-server.exe $(DIST_DIR)/windows/

# Build all platforms
dist: linux macos windows
	@echo "Build complete. Binaries in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/*/
