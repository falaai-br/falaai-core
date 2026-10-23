//! Espelho à mão das mensagens de `proto/falaai/v1/{envelope,websocket}.proto`
//! (github.com/falaai-br/falaai-proto@4ade11f), até o falaai-proto gerar código Rust. Os
//! vetores de `tests/envelope_vectors.rs` são decodificados pelo código Go gerado do `.proto`
//! no teste de contrato do servidor, então uma divergência daqui falha lá.

/// `Envelope` do falaai-proto, opaco para o servidor; `content` é a mensagem selada (sealed
/// sender). Outro nome em Rust porque o codegen do flutter_rust_bridge resolve tipos pelo nome
/// no crate inteiro, e `Envelope` já é tipo da API.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct WireEnvelope {
    #[prost(enumeration = "EnvelopeType", tag = "1")]
    pub(crate) r#type: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) client_message_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) content: Vec<u8>,
}

/// Tipo do envelope, fora do selo.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum EnvelopeType {
    Unspecified = 0,
    Message = 1,
    Receipt = 2,
    CallSignal = 3,
}

/// Única mensagem do WebSocket: cada mensagem binária é um `Frame`.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Frame {
    #[prost(oneof = "Payload", tags = "1, 2, 3, 4, 5, 6")]
    pub(crate) payload: Option<Payload>,
}

/// Conteúdo de um [`Frame`].
#[derive(Clone, PartialEq, prost::Oneof)]
pub(crate) enum Payload {
    #[prost(message, tag = "1")]
    Send(Send),
    #[prost(message, tag = "2")]
    SendAck(SendAck),
    #[prost(message, tag = "3")]
    Deliver(Deliver),
    #[prost(message, tag = "4")]
    Ack(Ack),
    #[prost(message, tag = "5")]
    Ping(Ping),
    #[prost(message, tag = "6")]
    Pong(Pong),
}

/// Pede ao servidor que enfileire um envelope para um dispositivo. Nada aqui identifica quem
/// envia.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Send {
    /// ACI do destinatário, 16 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) destination_aci: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub(crate) destination_device_id: u32,
    #[prost(message, optional, tag = "3")]
    pub(crate) envelope: Option<WireEnvelope>,
    /// Obrigatória no socket não autenticado; vazia no autenticado.
    #[prost(bytes = "vec", tag = "4")]
    pub(crate) unidentified_access_key: Vec<u8>,
}

/// Resposta a um [`Send`], correlacionada pelo `client_message_id` do envelope.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct SendAck {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) client_message_id: Vec<u8>,
    #[prost(enumeration = "SendStatus", tag = "2")]
    pub(crate) status: i32,
}

/// Resultado de um [`Send`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum SendStatus {
    Unspecified = 0,
    Accepted = 1,
    Invalid = 2,
    UnknownDestination = 3,
    RateLimited = 4,
    Unauthorized = 5,
}

/// Envelope da fila do dispositivo conectado; entrega at-least-once.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Deliver {
    #[prost(uint64, tag = "1")]
    pub(crate) seq: u64,
    /// Milissegundos desde a época Unix.
    #[prost(uint64, tag = "2")]
    pub(crate) server_timestamp: u64,
    #[prost(message, optional, tag = "3")]
    pub(crate) envelope: Option<WireEnvelope>,
}

/// Confirma que o envelope de `seq` foi persistido; o servidor o apaga da fila.
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Ack {
    #[prost(uint64, tag = "1")]
    pub(crate) seq: u64,
}

/// Mantém a conexão viva; o outro lado ecoa o `id` num [`Pong`].
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Ping {
    #[prost(uint64, tag = "1")]
    pub(crate) id: u64,
}

/// Resposta a um [`Ping`].
#[derive(Clone, PartialEq, prost::Message)]
pub(crate) struct Pong {
    #[prost(uint64, tag = "1")]
    pub(crate) id: u64,
}
