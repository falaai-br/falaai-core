# mk/hooks.mk — comum a todos os repositórios do FalaAí. Não editar localmente.

# Ferramentas instaladas por 'make tools' ficam fora do PATH padrão em alguns shells
# (hooks do git, sessões de agentes). Garantimos o PATH aqui.
RUSTUP_BIN := $(shell brew --prefix rustup 2>/dev/null)/bin
GOPATH_BIN := $(or $(shell go env GOPATH 2>/dev/null),$(HOME)/go)/bin
export PATH := $(GOPATH_BIN):$(HOME)/.cargo/bin:$(RUSTUP_BIN):/usr/local/go/bin:$(PATH)
# GNU Make 3.81 (macOS) ignora o PATH exportado em comandos executados direto; forçamos via shell.
SHELL := env PATH=$(PATH) /bin/sh
.PHONY: hooks hooks-uninstall hooks-check
hooks: ## Ativa os git hooks versionados neste clone
	@git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true
	@echo "hooks ativos: core.hooksPath=.githooks"
hooks-uninstall: ## Desativa os hooks (não recomendado)
	@git config --unset core.hooksPath || true
hooks-check: ## Falha se os hooks não estiverem ativos
	@test "$$(git config --get core.hooksPath)" = ".githooks" || { echo "hooks inativos: rode 'make hooks'"; exit 1; }

GITLEAKS ?= gitleaks
.PHONY: secrets secrets-staged
secrets: ## Procura segredos no histórico
	@$(GITLEAKS) git --no-banner --redact .
secrets-staged: ## Procura segredos no que está staged
	@$(GITLEAKS) git --no-banner --redact --staged .

.PHONY: help
help: ## Lista os alvos
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'
