# Git hooks do FalaAí

O pipeline de qualidade roda **localmente**, nos hooks versionados aqui. Não há CI remoto (ADR-0009).

| Hook | Roda | Tempo típico |
|---|---|---|
| `pre-commit` | `make check-fast` (formatação, lint, segredos) | segundos |
| `commit-msg` | Conventional Commits | instantâneo |
| `pre-push` | `make check` (lint, testes unitários, integração, segurança, build) | minutos |

- Ativação: `make tools` (ou `make hooks`) configura `core.hooksPath=.githooks` neste clone.
- Todos são **bloqueantes**. Emergência: `FALAAI_SKIP_HOOKS=1`. O Refinery do Gas Town roda `make check` de novo antes do merge, então pular o hook não pula o gate.
- Agentes: procurem `FALAAI-HOOK: FAIL gate=<nome>` no stderr.
