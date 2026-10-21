# falaai-core — instruções para agentes

Este repositório faz parte do **FalaAí**, mensageiro brasileiro com criptografia ponta a ponta. O blueprint completo está em <https://github.com/falaai-br/falaai> (pasta `docs/`). Leia o blueprint antes de decisões de arquitetura.

**Este NÃO é um repositório Nova.** Não aplicar `ai-core-basic-decisions` nem NERDs da Nova.

## Stack

Rust (edição 2024, toolchain pinada em `rust-toolchain.toml`, igual à da libsignal). libsignal como dependência git **pinada por commit** (ADR-0001). SQLCipher via rusqlite. Bindings para Flutter via flutter_rust_bridge 2.x.

## Licença

AGPL-3.0 (exigência da libsignal).

## Pipeline de qualidade (obrigatório)

Não existe CI remoto (ADR-0009). O pipeline roda nos git hooks e no Refinery do Gas Town.

- Ao entrar em um clone novo: `make tools` (instala ferramentas pinadas e ativa os hooks).
- `pre-commit` roda `make check-fast`; `commit-msg` exige Conventional Commits; `pre-push` roda `make check`.
- `make check` = `lint` + `test` + `test-integration` + `security` + `build`. Precisa estar verde antes de `gt done`.
- Nunca use `--no-verify` nem `FALAAI_SKIP_HOOKS=1` para contornar uma falha. Corrija a causa.
- Toda mudança de comportamento vem com teste. Bug corrigido vem com teste de regressão.

## Convenções

- Trunk-based em `main`, squash merge, mensagens em Conventional Commits.
- Tarefas vivem como beads no Gas Town e são espelhadas em GitHub Issues (`bd github sync`). Todo commit referencia a bead.
- Documentação, issues e mensagens de commit em português; identificadores de código em inglês.

## Regras de segurança (inegociáveis)

- Nunca escrever primitivas criptográficas. Toda cripto vem da libsignal (só no `falaai-core`).
- Nunca registrar em log: telefone, par remetente/destinatário, IP completo, conteúdo, chaves, ACI em claro.
- Nenhuma tabela, tópico ou log pode guardar quem falou com quem (ADR-0008).

## Específico deste repo

- Rust só existe aqui (ADR-0002). Mantenha o crate pequeno: wrapper de protocolo, stores, storage, messaging, transport, media, api.
- Material de chave nunca atravessa o FFI para o Dart.
- Use `zeroize` em todo buffer com segredo. `unsafe` é proibido (lint `unsafe_code = deny`).
- Builds para Android e iOS: `make build-mobile` (fora do hook, exigido nas beads de build).
