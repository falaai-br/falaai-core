# falaai-core

Núcleo criptográfico e de mensagens do **FalaAí**, em Rust. Encapsula a [libsignal](https://github.com/signalapp/libsignal) (PQXDH, Triple Ratchet, Sender Keys, sealed sender), o armazenamento local cifrado (SQLCipher) e a lógica de envio/recebimento. É consumido pelo app Flutter via [flutter_rust_bridge](https://github.com/fzyzcjy/flutter_rust_bridge).

## Módulos

| Módulo | Função |
|---|---|
| `protocol` | Wrapper da libsignal e implementação dos stores |
| `storage` | SQLCipher, chave no Keychain/Keystore |
| `messaging` | Outbox, recibos, efêmeras |
| `transport` | WebSocket/HTTPS com pinning |
| `media` | Cifra de anexos em streaming |
| `api` | Superfície exposta ao Flutter |

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
