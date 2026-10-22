# falaai-core — pipeline de qualidade.
include mk/hooks.mk

CARGO_DENY_VERSION  ?= 0.20.2
CARGO_AUDIT_VERSION ?= 0.22.2
CARGO_NDK_VERSION   ?= 4.1.2
GITLEAKS_VERSION    ?= 8.28.0
# Ponte com o Flutter: o codegen tem de bater com flutter_rust_bridge em Cargo.toml e
# dart/pubspec.yaml; ele usa o cargo-expand para ler o crate.
FRB_CODEGEN_VERSION  ?= 2.13.0
CARGO_EXPAND_VERSION ?= 1.0.127

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

ANDROID_ABIS := arm64-v8a armeabi-v7a x86_64
# Meta de tamanho do core por ABI Android (blueprint: APK de entrada < 40 MB por ABI).
MOBILE_SIZE_LIMIT ?= 10485760

.PHONY: tools protoc fmt lint test test-integration security build build-mobile build-android build-ios mobile-size bindings bindings-check check check-fast
tools: hooks protoc ## Instala toolchain e ferramentas pinadas e ativa os hooks
	@command -v rustup >/dev/null || { echo "instale rustup: https://rustup.rs"; exit 1; }
	rustup show active-toolchain
	rustup component add rustfmt clippy
	rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android aarch64-apple-ios aarch64-apple-ios-sim
	cargo install --locked cargo-deny@$(CARGO_DENY_VERSION) cargo-audit@$(CARGO_AUDIT_VERSION) cargo-ndk@$(CARGO_NDK_VERSION)
	cargo install --locked flutter_rust_bridge_codegen@$(FRB_CODEGEN_VERSION) cargo-expand@$(CARGO_EXPAND_VERSION)
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

build-mobile: build-android build-ios mobile-size ## Android (3 ABIs) e iOS (xcframework). Fora do hook; usado nas beads de build

build-android: ## .so por ABI em dist/android/. Exige o NDK (ANDROID_NDK_HOME ou ANDROID_HOME/ndk)
	cargo ndk $(addprefix -t ,$(ANDROID_ABIS)) -o dist/android build --release --locked

build-ios: ## xcframework estático em dist/. Exige o Xcode completo (Command Line Tools não têm o SDK iOS)
	@xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1 || { \
	  echo "SDK iphoneos não encontrado: instale o Xcode e selecione-o com 'xcode-select -s' ou DEVELOPER_DIR"; exit 1; }
	cargo build --release --locked --target aarch64-apple-ios
	cargo build --release --locked --target aarch64-apple-ios-sim
	rm -rf dist/FalaaiCore.xcframework
	xcodebuild -create-xcframework \
	  -library target/aarch64-apple-ios/release/libfalaai_core.a \
	  -library target/aarch64-apple-ios-sim/release/libfalaai_core.a \
	  -output dist/FalaaiCore.xcframework

mobile-size: ## Tamanho dos artefatos mobile; falha se uma ABI Android passar de MOBILE_SIZE_LIMIT
	scripts/mobile-size dist $(MOBILE_SIZE_LIMIT) $(ANDROID_ABIS)

bindings: ## Regera a ponte flutter_rust_bridge (src/frb_generated.rs e dart/lib/src/rust) a partir de src/api
	@command -v dart >/dev/null || { echo "instale o Flutter (dart no PATH): https://docs.flutter.dev/get-started"; exit 1; }
	cd dart && dart pub get
	@# O codegen resolve tipos pelo nome no crate inteiro: um nome repetido vira escolha ao acaso.
	@log="$$(mktemp)"; \
	  flutter_rust_bridge_codegen generate >"$$log" 2>&1 || { cat "$$log"; rm -f "$$log"; exit 1; }; \
	  if grep -q "randomly pick one" "$$log"; then \
	    grep "randomly pick one" "$$log"; rm -f "$$log"; \
	    echo "tipo da API com nome repetido no crate: renomeie o tipo interno"; exit 1; \
	  fi; \
	  rm -f "$$log"
	cargo fmt --all

bindings-check: bindings ## Falha se a ponte versionada não bate com src/api
	@test -z "$$(git status --porcelain -- src/frb_generated.rs dart/lib)" || { git status --short -- src/frb_generated.rs dart/lib; echo "ponte desatualizada: rode 'make bindings' e versione o resultado"; exit 1; }

check-fast: ## pre-commit
	cargo fmt --all -- --check
	cargo clippy --lib --locked -- -D warnings
	$(GITLEAKS) git --no-banner --redact --staged .

check: lint test test-integration security build ## pre-push e gate do Refinery
