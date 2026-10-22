# Vetores de envelope

Envelopes reais do `falaai-core` para os testes de contrato do `falaai-server`. Gerados por `tests/envelope_vectors.rs`: Alice abre sessão (PQXDH) com Bob, manda um envelope por caso, e Bob decifra todos antes de os vetores serem gravados. Schema: `falaai.v1` do [falaai-proto](https://github.com/falaai-br/falaai-proto) no commit `57fa36c`.

## Arquivos

Por caso (`prekey`, `message`, `receipt`, `call_signal`):

| Arquivo | Conteúdo |
|---|---|
| `<caso>.envelope.bin` | `falaai.v1.Envelope` serializado |
| `<caso>.send.bin` | `falaai.v1.Frame` com `send`: o que o remetente manda no WebSocket |
| `<caso>.deliver.bin` | `falaai.v1.Frame` com `deliver`: o que o destinatário recebe |

`manifest.json` descreve cada caso:

| Campo | Significado |
|---|---|
| `name`, `description` | Identificação do caso |
| `envelope_type` | Valor de `Envelope.type`, pelo nome no `.proto` |
| `content_format` | O que vai em `Envelope.content` (ver abaixo) |
| `ciphertext_kind` | `prekey` (primeira mensagem, abre a sessão) ou `message` |
| `ciphertext_version` | Primeiro byte de `content`: versão do formato da libsignal |
| `client_message_id` | `Envelope.client_message_id`, em hex |
| `destination_aci`, `destination_device_id` | Destino no `Send` |
| `seq`, `server_timestamp` | Valores no `Deliver` de referência |
| `files.<papel>.path`, `files.<papel>.sha256` | Arquivo e SHA-256 dele, com papel `envelope`, `send` ou `deliver` |

## Contrato do servidor

1. Decodificar `<caso>.send.bin` como `Frame` e enfileirar o envelope para `destination_aci` e `destination_device_id`.
2. Entregar ao destinatário um `Frame` com `deliver` cujo `envelope`, serializado, é byte a byte `<caso>.envelope.bin`.
3. Não interpretar `content`: ele é opaco para o servidor e muda de formato sem mudar o contrato.

`<caso>.deliver.bin` é a codificação de referência do `Deliver` com o `seq` e o `server_timestamp` do manifesto, útil para testar o lado que decodifica.

## Fase 0: `content` ainda não é sealed sender

Hoje `content_format` é `libsignal-ciphertext`: o ciphertext como o core devolve, uma `PreKeySignalMessage` ou uma `SignalMessage`. O `.proto` define `content` como a `UnidentifiedSenderMessage` do sealed sender, que ainda não existe no core.

A diferença importa: a `PreKeySignalMessage` leva em claro a identidade pública do remetente e o ACI e o device id dos dois lados. Por isso o teste exige ausência do remetente só fora de `content`. Quando o sealed sender entrar, `content_format` vira `sealed-sender`, os vetores são regerados e a exigência passa a cobrir os bytes inteiros. Decisão e acompanhamento: bead `flc-8u3`.

## Regerar

```bash
make vectors
```

Os ciphertexts são aleatórios, então regerar muda todos os `.bin` e hashes mesmo sem mudança de formato. Regere só quando o teste pedir (o gerador mudou o formato) ou quando o formato de `content` mudar, e revise o diff do `manifest.json`.

O schema está espelhado à mão em `tests/envelope_vectors.rs` até o falaai-proto gerar código Rust (bead `flp-kal`). Uma divergência do espelho aparece no teste de contrato do servidor, que decodifica estes vetores com o código Go gerado do `.proto`.
