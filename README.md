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

## Licença

AGPL-3.0. Ver [LICENSE](LICENSE).
