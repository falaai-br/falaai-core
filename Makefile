# falaai-core — pipeline de qualidade.
include mk/hooks.mk

CARGO_DENY_VERSION  ?= 0.20.2
CARGO_AUDIT_VERSION ?= 0.22.2
CARGO_NDK_VERSION   ?= 4.1.2
GITLEAKS ?= $(shell command -v gitleaks || echo $(HOME)/go/bin/gitleaks)

.PHONY: tools fmt lint test test-integration security build build-mobile check check-fast
tools: hooks ## Instala toolchain e ferramentas pinadas e ativa os hooks
	@command -v rustup >/dev/null || { echo "instale rustup: https://rustup.rs"; exit 1; }
	rustup show active-toolchain
	rustup component add rustfmt clippy
	rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android aarch64-apple-ios aarch64-apple-ios-sim
	cargo install --locked cargo-deny@$(CARGO_DENY_VERSION) cargo-audit@$(CARGO_AUDIT_VERSION) cargo-ndk@$(CARGO_NDK_VERSION)

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
