# falaai-core — pipeline de qualidade.
include mk/hooks.mk

CARGO_DENY_VERSION  ?= 0.20.2
CARGO_AUDIT_VERSION ?= 0.22.2
CARGO_NDK_VERSION   ?= 4.1.2
GITLEAKS_VERSION    ?= 8.28.0

# protoc: exigido pelo build script da libsignal (prost-build). Instalado em .tools/ com
# checksum verificado; o caminho é fixado em .cargo/config.toml (PROTOC).
PROTOC_VERSION := 36.2
PROTOC_DIR     := .tools/protoc
PROTOC_SHA256_osx-aarch_64   := 9cd98a532c5c5e0c4161314de0225de27e4c8a323917b6ea7b1b714d3ae23466
PROTOC_SHA256_osx-x86_64     := 228cc7add4616cc14ca5e80dee83209d44449a7aee95a914ae748fa374efb078
PROTOC_SHA256_linux-aarch_64 := 8b8f18bd2b30346efbc698dd5a73dd7c805f3ef8380f6dfc95c768f3f1852f6a
PROTOC_SHA256_linux-x86_64   := 121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278
PROTOC_OS   := $(subst Darwin,osx,$(subst Linux,linux,$(shell uname -s)))
PROTOC_ARCH := $(subst arm64,aarch_64,$(subst aarch64,aarch_64,$(shell uname -m)))
PROTOC_PLATFORM := $(PROTOC_OS)-$(PROTOC_ARCH)

.PHONY: tools protoc fmt lint test test-integration security build build-mobile check check-fast
tools: hooks protoc ## Instala toolchain e ferramentas pinadas e ativa os hooks
	@command -v rustup >/dev/null || { echo "instale rustup: https://rustup.rs"; exit 1; }
	rustup show active-toolchain
	rustup component add rustfmt clippy
	rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android aarch64-apple-ios aarch64-apple-ios-sim
	cargo install --locked cargo-deny@$(CARGO_DENY_VERSION) cargo-audit@$(CARGO_AUDIT_VERSION) cargo-ndk@$(CARGO_NDK_VERSION)
	@command -v go >/dev/null || { echo "instale Go para o gitleaks: https://go.dev/dl"; exit 1; }
	go install github.com/zricethezav/gitleaks/v8@v$(GITLEAKS_VERSION)

protoc: ## Baixa o protoc pinado para .tools/ (sha256 verificado)
	@if [ "$$(cat $(PROTOC_DIR)/VERSION 2>/dev/null)" = "$(PROTOC_VERSION)" ]; then echo "protoc $(PROTOC_VERSION) já instalado"; else \
	  set -e; \
	  sum="$(PROTOC_SHA256_$(PROTOC_PLATFORM))"; \
	  [ -n "$$sum" ] || { echo "plataforma sem protoc pinado: $(PROTOC_PLATFORM)"; exit 1; }; \
	  zip="protoc-$(PROTOC_VERSION)-$(PROTOC_PLATFORM).zip"; \
	  tmp="$$(mktemp -d)"; \
	  curl -fsSL -o "$$tmp/$$zip" "https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/$$zip"; \
	  echo "$$sum  $$tmp/$$zip" | shasum -a 256 -c -; \
	  rm -rf $(PROTOC_DIR); mkdir -p $(PROTOC_DIR); \
	  unzip -q "$$tmp/$$zip" -d $(PROTOC_DIR); rm -rf "$$tmp"; \
	  echo "$(PROTOC_VERSION)" > $(PROTOC_DIR)/VERSION; \
	  $(PROTOC_DIR)/bin/protoc --version; \
	fi

fmt: ## Formata
	cargo fmt --all

lint: ## rustfmt check e clippy estrito
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features --locked -- -D warnings

test: ## Testes unitários
	cargo test --lib --locked

test-integration: ## Testes de integração (dois cores trocando mensagens, SQLCipher real)
	cargo test --test '*' --locked

security: ## cargo-deny (licenças, advisories, fontes), cargo-audit, gitleaks
	cargo deny --locked check
	cargo audit
	$(GITLEAKS) git --no-banner --redact .

build: ## Build de release do host
	cargo build --release --locked

build-mobile: ## Android (3 ABIs) e iOS (xcframework). Fora do hook; usado nas beads de build
	cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o dist/android build --release --locked
	cargo build --release --locked --target aarch64-apple-ios
	cargo build --release --locked --target aarch64-apple-ios-sim
	rm -rf dist/FalaaiCore.xcframework
	xcodebuild -create-xcframework \
	  -library target/aarch64-apple-ios/release/libfalaai_core.a \
	  -library target/aarch64-apple-ios-sim/release/libfalaai_core.a \
	  -output dist/FalaaiCore.xcframework

check-fast: ## pre-commit
	cargo fmt --all -- --check
	cargo clippy --lib --locked -- -D warnings
	$(GITLEAKS) git --no-banner --redact --staged .

check: lint test test-integration security build ## pre-push e gate do Refinery
