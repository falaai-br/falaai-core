//! Conteúdo E2EE: o que vai dentro do selo, que só o destinatário abre.
//!
//! O `Envelope` do falaai-proto diz ao servidor só o tipo externo (`MESSAGE`, `RECEIPT`); o que
//! há dentro é um [`Content`] serializado em protobuf, definido aqui porque o servidor nunca o
//! vê e o único cliente que o lê é este núcleo. As mensagens de protocolo (recibos de entrega e
//! de leitura, indicador de digitação) viajam como qualquer texto: cifradas pelo ratchet e
//! seladas, indistinguíveis para o servidor dentro do mesmo tipo externo.
//!
//! Formato (proto3, tags fixas; uma tag publicada nunca muda de sentido):
//!
//! ```text
//! message Content { oneof body { Text text = 1; Receipt receipt = 2; Typing typing = 3; } }
//! message Text    { bytes body = 1; }
//! message Receipt { ReceiptType type = 1; repeated bytes client_message_ids = 2; }
//! message Typing  { TypingAction action = 1; }
//! enum ReceiptType  { UNSPECIFIED = 0; DELIVERY = 1; READ = 2; }
//! enum TypingAction { UNSPECIFIED = 0; STARTED = 1; STOPPED = 2; }
//! ```

use prost::Message as _;
use zeroize::Zeroize;

use super::outbox::{CLIENT_MESSAGE_ID_LEN, ClientMessageId};
use crate::protocol::Plaintext;

/// Mensagem dentro do selo. Sem `Debug`: o texto claro não pode ir para log.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Content {
    /// Texto de conversa.
    Text(Plaintext),
    /// Recibo: as mensagens de `client_message_ids`, enviadas por quem recebe o recibo, foram
    /// entregues ou lidas.
    Receipt {
        kind: ReceiptType,
        client_message_ids: Vec<ClientMessageId>,
    },
    /// Quem envia começou ou parou de digitar. Efêmero: nunca é gravado.
    Typing { started: bool },
}

/// O que um recibo confirma.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiptType {
    /// A mensagem chegou ao aparelho e foi decifrada.
    Delivery,
    /// A mensagem foi mostrada a quem a recebeu.
    Read,
}

/// Bytes que não formam um [`Content`]: protobuf malformado, corpo ausente ou desconhecido,
/// recibo sem mensagens ou com id de tamanho errado, tipo ou ação não especificados.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("conteúdo E2EE inválido")]
pub(crate) struct InvalidContent;

impl Content {
    /// Serializa para cifrar. Cópias do texto feitas no caminho são zeradas.
    pub(crate) fn encode(&self) -> Plaintext {
        let mut wire = WireContent {
            body: Some(match self {
                Self::Text(body) => WireBody::Text(WireText {
                    body: body.to_vec(),
                }),
                Self::Receipt {
                    kind,
                    client_message_ids,
                } => WireBody::Receipt(WireReceipt {
                    r#type: WireReceiptType::from(*kind).into(),
                    client_message_ids: client_message_ids.iter().map(|id| id.to_vec()).collect(),
                }),
                Self::Typing { started } => WireBody::Typing(WireTyping {
                    action: if *started {
                        WireTypingAction::Started
                    } else {
                        WireTypingAction::Stopped
                    }
                    .into(),
                }),
            }),
        };
        let encoded = Plaintext::new(wire.encode_to_vec());
        if let Some(WireBody::Text(text)) = &mut wire.body {
            text.body.zeroize();
        }
        encoded
    }

    /// Interpreta o que foi decifrado.
    pub(crate) fn decode(plaintext: &[u8]) -> Result<Self, InvalidContent> {
        let mut wire = WireContent::decode(plaintext).map_err(|_| InvalidContent)?;
        match wire.body.take().ok_or(InvalidContent)? {
            WireBody::Text(mut text) => {
                Ok(Self::Text(Plaintext::new(std::mem::take(&mut text.body))))
            }
            WireBody::Receipt(receipt) => {
                let kind = match WireReceiptType::try_from(receipt.r#type) {
                    Ok(WireReceiptType::Delivery) => ReceiptType::Delivery,
                    Ok(WireReceiptType::Read) => ReceiptType::Read,
                    Ok(WireReceiptType::Unspecified) | Err(_) => return Err(InvalidContent),
                };
                if receipt.client_message_ids.is_empty() {
                    return Err(InvalidContent);
                }
                let client_message_ids = receipt
                    .client_message_ids
                    .iter()
                    .map(|id| ClientMessageId::try_from(id.as_slice()).map_err(|_| InvalidContent))
                    .collect::<Result<_, _>>()?;
                Ok(Self::Receipt {
                    kind,
                    client_message_ids,
                })
            }
            WireBody::Typing(typing) => match WireTypingAction::try_from(typing.action) {
                Ok(WireTypingAction::Started) => Ok(Self::Typing { started: true }),
                Ok(WireTypingAction::Stopped) => Ok(Self::Typing { started: false }),
                Ok(WireTypingAction::Unspecified) | Err(_) => Err(InvalidContent),
            },
        }
    }
}

/// Ids de recibo concatenados, como ficam no banco: `CLIENT_MESSAGE_ID_LEN` bytes cada.
pub(crate) fn join_ids(ids: &[ClientMessageId]) -> Vec<u8> {
    ids.concat()
}

/// O inverso de [`join_ids`]; `None` se o tamanho não é múltiplo do id ou é zero.
pub(crate) fn split_ids(bytes: &[u8]) -> Option<Vec<ClientMessageId>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(CLIENT_MESSAGE_ID_LEN) {
        return None;
    }
    let (ids, rest) = bytes.as_chunks::<CLIENT_MESSAGE_ID_LEN>();
    rest.is_empty().then(|| ids.to_vec())
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
struct WireContent {
    #[prost(oneof = "WireBody", tags = "1, 2, 3")]
    body: Option<WireBody>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
#[prost(skip_debug)]
enum WireBody {
    #[prost(message, tag = "1")]
    Text(WireText),
    #[prost(message, tag = "2")]
    Receipt(WireReceipt),
    #[prost(message, tag = "3")]
    Typing(WireTyping),
}

#[derive(Clone, PartialEq, prost::Message)]
#[prost(skip_debug)]
struct WireText {
    #[prost(bytes = "vec", tag = "1")]
    body: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct WireReceipt {
    #[prost(enumeration = "WireReceiptType", tag = "1")]
    r#type: i32,
    #[prost(bytes = "vec", repeated, tag = "2")]
    client_message_ids: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
enum WireReceiptType {
    Unspecified = 0,
    Delivery = 1,
    Read = 2,
}

impl From<ReceiptType> for WireReceiptType {
    fn from(kind: ReceiptType) -> Self {
        match kind {
            ReceiptType::Delivery => Self::Delivery,
            ReceiptType::Read => Self::Read,
        }
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct WireTyping {
    #[prost(enumeration = "WireTypingAction", tag = "1")]
    action: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
enum WireTypingAction {
    Unspecified = 0,
    Started = 1,
    Stopped = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(body: &[u8]) -> Content {
        Content::Text(Plaintext::new(body.to_vec()))
    }

    #[test]
    fn cada_variante_vai_e_volta() -> Result<(), InvalidContent> {
        let contents = [
            text(b"oi"),
            text(b""),
            Content::Receipt {
                kind: ReceiptType::Delivery,
                client_message_ids: vec![[1; 16]],
            },
            Content::Receipt {
                kind: ReceiptType::Read,
                client_message_ids: vec![[1; 16], [2; 16], [3; 16]],
            },
            Content::Typing { started: true },
            Content::Typing { started: false },
        ];
        for content in contents {
            assert!(Content::decode(&content.encode())? == content);
        }
        Ok(())
    }

    #[test]
    fn texto_vai_na_tag_1_como_bytes() {
        // Content { text: Text { body: "oi" } } em protobuf.
        assert_eq!(text(b"oi").encode().as_slice(), b"\x0a\x04\x0a\x02oi");
        assert!(Content::decode(b"\x0a\x04\x0a\x02oi").ok() == Some(text(b"oi")));
    }

    #[test]
    fn recibo_e_digitacao_tem_as_tags_do_formato() {
        let receipt = Content::Receipt {
            kind: ReceiptType::Read,
            client_message_ids: vec![[7; 16]],
        }
        .encode();
        // Content.receipt (tag 2) { type = READ (tag 1), client_message_ids (tag 2) }.
        let mut expected = vec![0x12, 20, 0x08, 0x02, 0x12, 16];
        expected.extend_from_slice(&[7; 16]);
        assert_eq!(receipt.as_slice(), expected);
        // Content.typing (tag 3) { action = STARTED (tag 1) }.
        assert_eq!(
            Content::Typing { started: true }.encode().as_slice(),
            b"\x1a\x02\x08\x01"
        );
    }

    #[test]
    fn bytes_que_nao_formam_conteudo_sao_recusados() {
        let cases: [&[u8]; 8] = [
            // Protobuf malformado.
            b"\xff\xff",
            // Content vazio, sem corpo.
            b"",
            // Campo desconhecido só.
            b"\x22\x00",
            // Recibo sem tipo.
            b"\x12\x12\x12\x10\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07",
            // Recibo com tipo desconhecido.
            b"\x12\x14\x08\x09\x12\x10\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07",
            // Recibo sem mensagens.
            b"\x12\x02\x08\x01",
            // Recibo com id de 15 bytes.
            b"\x12\x13\x08\x01\x12\x0f\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07",
            // Digitação sem ação.
            b"\x1a\x00",
        ];
        for bytes in cases {
            assert!(Content::decode(bytes).is_err(), "{bytes:02x?}");
        }
    }

    #[test]
    fn ids_concatenados_vao_e_voltam() {
        let ids = vec![[1; 16], [2; 16]];
        let joined = join_ids(&ids);
        assert_eq!(joined.len(), 32);
        assert_eq!(split_ids(&joined), Some(ids));
        assert_eq!(split_ids(&[]), None);
        assert_eq!(split_ids(&[0; 17]), None);
    }
}
