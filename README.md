# falaai-core

Núcleo criptográfico e de mensagens do **FalaAí**, em Rust. Encapsula a [libsignal](https://github.com/signalapp/libsignal) (PQXDH, Triple Ratchet, Sender Keys, sealed sender), o armazenamento local cifrado (SQLCipher) e a lógica de envio/recebimento. É consumido pelo app Flutter via [flutter_rust_bridge](https://github.com/fzyzcjy/flutter_rust_bridge).

## Módulos

| Módulo | Função |
|---|---|
| `protocol` | Wrapper da libsignal e implementação dos stores |
| `storage` | SQLCipher, chave no Keychain/Keystore |
| `messaging` | Outbox, recibos, efêmeras |
| `transport` | WebSocket do gateway (autenticado e não autenticado, sealed sender) e HTTPS do `accounts`, sobre rustls; pinning pela CA da configuração |
| `media` | Cifra de anexos em streaming |
| `api` | Superfície exposta ao Flutter |

## E2E headless da Fase 0

`make test-e2e` prova a Fase 0 sem aparelho: dois núcleos (Alice e Bob) contra o falaai-server real, com o falaai-signer, o Postgres e o Redis do `compose.yaml` do servidor. O teste (`tests/e2e_phase0.rs`) registra os dois com o OTP de dev, publica os bundles, pega o certificado de remetente no `accounts`, abre sessão pelo bundle buscado no servidor, envia por sealed sender, recebe, decifra, grava e confirma. No Postgres, confere que a `message_queue` não tem coluna de remetente, que o envelope enfileirado não carrega o ACI de quem enviou e que a linha some depois do `Ack`.

Exige Docker com o compose v2.24+ e os checkouts do [falaai-server](https://github.com/falaai-br/falaai-server) e do [falaai-signer](https://github.com/falaai-br/falaai-signer) ao lado deste repositório (ou `FALAAI_SERVER_DIR` e `FALAAI_SIGNER_DIR`):

```sh
make test-e2e
make test-e2e FALAAI_SERVER_DIR=~/src/falaai-server FALAAI_SIGNER_DIR=~/src/falaai-signer
```

O stack sobe num projeto próprio (`falaai-e2e`), com o servidor em `127.0.0.1:18080` (`FALAAI_E2E_PORT`) e sem expor o Postgres e o Redis, então não conflita com o `make dev-up` do servidor. Começa e termina com containers e volumes apagados; `FALAAI_E2E_KEEP=1` mantém o stack no fim. A primeira execução compila o signer e demora.

Enquanto o servidor não tiver o socket não autenticado (`/v1/ws/unidentified`, fls-o65), o envelope (selado do mesmo jeito) vai pelo socket autenticado, e o teste avisa na saída. Com o socket, Alice envia com o socket autenticado recusado, o que prova que a mensagem saiu sem credencial. `FALAAI_E2E_REQUIRE_UNIDENTIFIED=1` faz a falta do socket falhar o teste.

Fica fora do `make check`: sem as variáveis do `scripts/e2e` o teste é ignorado.

## Build mobile

`make build-mobile` gera os artefatos em `dist/` (não versionado) e mede o tamanho:

| Alvo | Saída | Exige |
|---|---|---|
| `make build-android` | `dist/android/{arm64-v8a,armeabi-v7a,x86_64}/libfalaai_core.so` | NDK (`ANDROID_NDK_HOME`, `ANDROID_HOME/ndk/<versão>` ou o SDK padrão do Android Studio), `cargo-ndk` de `make tools` |
| `make build-ios` | `dist/FalaaiCore.xcframework` (`aarch64-apple-ios` + `aarch64-apple-ios-sim`) | Xcode completo; só as Command Line Tools não têm o SDK iOS |
| `make mobile-size` | Tamanho por ABI | Falha se uma `.so` passar de `MOBILE_SIZE_LIMIT` (10 MB) ou faltar |

Enquanto a API para o Flutter (flc-8lr) não existir, o crate não exporta símbolos e o LTO descarta quase tudo; o tamanho medido só vale como referência depois que a API entrar.

## Licença

AGPL-3.0. Ver [LICENSE](LICENSE).
