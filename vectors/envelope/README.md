# Vetores de envelope

Envelopes reais do `falaai-core` para os testes de contrato do `falaai-server`. Gerados por `tests/envelope_vectors.rs`: Alice abre sessão (PQXDH) com Bob, manda um envelope selado (sealed sender) por caso, e Bob decifra todos antes de os vetores serem gravados. Schema: `falaai.v1` do [falaai-proto](https://github.com/falaai-br/falaai-proto) no commit `57fa36c`.

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
| `content_version` | Primeiro byte de `content`: versão do sealed sender da libsignal (`17` = `0x11`, v1) |
| `client_message_id` | `Envelope.client_message_id`, em hex |
| `destination_aci`, `destination_device_id` | Destino no `Send` |
| `seq`, `server_timestamp` | Valores no `Deliver` de referência |
| `files.<papel>.path`, `files.<papel>.sha256` | Arquivo e SHA-256 dele, com papel `envelope`, `send` ou `deliver` |

## Contrato do servidor

1. Decodificar `<caso>.send.bin` como `Frame` e enfileirar o envelope para `destination_aci` e `destination_device_id`.
2. Entregar ao destinatário um `Frame` com `deliver` cujo `envelope`, serializado, é byte a byte `<caso>.envelope.bin`.
3. Não interpretar `content`: ele é opaco para o servidor e muda de formato sem mudar o contrato.

`<caso>.deliver.bin` é a codificação de referência do `Deliver` com o `seq` e o `server_timestamp` do manifesto, útil para testar o lado que decodifica.

## `content` é sealed sender

`content_format` é `sealed-sender`: a `UnidentifiedSenderMessage` (sealed sender v1) da libsignal, como o core devolve. O tipo da mensagem de dentro (a primeira da sessão, que abre o PQXDH, ou uma da sessão confirmada) e o certificado de remetente só aparecem depois que o destinatário abre o selo; o servidor não tem como distinguir o caso `prekey` dos outros.

O teste exige que o ACI do remetente, em texto ou nos 16 bytes do UUID, não apareça em nenhum dos arquivos, `content` incluído, e que o do destinatário não apareça dentro de `content`. Decisão: bead `flc-8u3`.

## Regerar

```bash
make vectors
```

Os ciphertexts são aleatórios, então regerar muda todos os `.bin` e hashes mesmo sem mudança de formato. Regere só quando o teste pedir (o gerador mudou o formato) ou quando o formato de `content` mudar, e revise o diff do `manifest.json`.

O schema está espelhado à mão em `tests/envelope_vectors.rs` até o falaai-proto gerar código Rust (bead `flp-kal`). Uma divergência do espelho aparece no teste de contrato do servidor, que decodifica estes vetores com o código Go gerado do `.proto`.
