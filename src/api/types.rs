//! Dados que cruzam a fronteira com o Dart. Só chaves públicas, envelopes cifrados e texto já
//! decifrado; chaves públicas e assinaturas vão serializadas no formato da libsignal.

use std::fmt;

use super::error::CoreError;
use crate::messaging::InboxMessage;
use crate::protocol::identity::SafetyCode;
use crate::protocol::keys;
use crate::protocol::store::PeerIdentityStatus;
use crate::protocol::{self, Address, ProtocolError, PublicPreKey, SignedPublicPreKey};

/// Dispositivo de uma conta: ACI (UUID em texto) e device id (1 a 127).
///
/// `Debug` omite o ACI, que nunca pode ir para log em claro.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceAddress {
    /// ACI da conta, UUID em texto.
    pub aci: String,
    /// Dispositivo da conta, de 1 a 127.
    pub device_id: u8,
}

impl fmt::Debug for DeviceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAddress")
            .field("aci", &"<omitido>")
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl From<&Address> for DeviceAddress {
    fn from(address: &Address) -> Self {
        Self {
            aci: address.aci().to_owned(),
            device_id: address.device_id(),
        }
    }
}

impl TryFrom<&DeviceAddress> for Address {
    type Error = ProtocolError;

    fn try_from(address: &DeviceAddress) -> Result<Self, Self::Error> {
        Address::new(&address.aci, address.device_id)
    }
}

/// Pré-chave pública EC descartável.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreKey {
    /// Id da pré-chave.
    pub id: u32,
    /// Chave pública serializada.
    pub public_key: Vec<u8>,
}

impl From<PublicPreKey> for PreKey {
    fn from(key: PublicPreKey) -> Self {
        Self {
            id: key.id,
            public_key: key.public_key,
        }
    }
}

impl From<&PreKey> for PublicPreKey {
    fn from(key: &PreKey) -> Self {
        Self {
            id: key.id,
            public_key: key.public_key.clone(),
        }
    }
}

/// Pré-chave pública assinada pela identidade: EC assinada ou Kyber.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPreKey {
    /// Id da pré-chave.
    pub id: u32,
    /// Chave pública serializada.
    pub public_key: Vec<u8>,
    /// Assinatura da chave pública pela identidade.
    pub signature: Vec<u8>,
}

impl From<SignedPublicPreKey> for SignedPreKey {
    fn from(key: SignedPublicPreKey) -> Self {
        Self {
            id: key.id,
            public_key: key.public_key,
            signature: key.signature,
        }
    }
}

impl From<&SignedPreKey> for SignedPublicPreKey {
    fn from(key: &SignedPreKey) -> Self {
        Self {
            id: key.id,
            public_key: key.public_key.clone(),
            signature: key.signature.clone(),
        }
    }
}

/// Parte pública das chaves da conta, para enviar ao servidor no registro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountKeys {
    /// Registration id do dispositivo.
    pub registration_id: u32,
    /// Chave pública de identidade.
    pub identity_key: Vec<u8>,
    /// Pré-chave EC assinada.
    pub signed_pre_key: SignedPreKey,
    /// Pré-chave Kyber de último recurso, usada quando as descartáveis acabam.
    pub kyber_last_resort_pre_key: SignedPreKey,
    /// Pré-chaves EC descartáveis.
    pub pre_keys: Vec<PreKey>,
    /// Pré-chaves Kyber descartáveis.
    pub kyber_pre_keys: Vec<SignedPreKey>,
}

impl From<keys::PublicAccountKeys> for AccountKeys {
    fn from(keys: keys::PublicAccountKeys) -> Self {
        Self {
            registration_id: keys.registration_id,
            identity_key: keys.identity_key,
            signed_pre_key: keys.signed_pre_key.into(),
            kyber_last_resort_pre_key: keys.kyber_last_resort_pre_key.into(),
            pre_keys: keys.pre_keys.into_iter().map(Into::into).collect(),
            kyber_pre_keys: keys.kyber_pre_keys.into_iter().map(Into::into).collect(),
        }
    }
}

/// Pré-chaves públicas que um contato publicou no servidor, para abrir sessão com ele.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreKeyBundle {
    /// Registration id do dispositivo do contato.
    pub registration_id: u32,
    /// Chave pública de identidade do contato.
    pub identity_key: Vec<u8>,
    /// Pré-chave EC descartável; ausente quando o servidor não tem mais nenhuma.
    pub pre_key: Option<PreKey>,
    /// Pré-chave EC assinada.
    pub signed_pre_key: SignedPreKey,
    /// Pré-chave Kyber, descartável ou de último recurso.
    pub kyber_pre_key: SignedPreKey,
}

impl PreKeyBundle {
    pub(crate) fn to_protocol(
        &self,
        peer: &Address,
    ) -> Result<protocol::PeerBundle, ProtocolError> {
        protocol::PeerBundle::new(
            peer,
            self.registration_id,
            &self.identity_key,
            self.pre_key.as_ref().map(Into::into).as_ref(),
            &(&self.signed_pre_key).into(),
            &(&self.kyber_pre_key).into(),
        )
    }
}

/// Mensagem selada (sealed sender), pronta para o transporte: vai em `Envelope.content` do
/// falaai-proto. Só o destinatário a abre; o servidor não vê o remetente nem o tipo da
/// mensagem dentro do selo.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Bytes selados.
    pub body: Vec<u8>,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("len", &self.body.len())
            .finish()
    }
}

impl From<protocol::Ciphertext> for Envelope {
    fn from(envelope: protocol::Ciphertext) -> Self {
        Self {
            body: envelope.body().to_vec(),
        }
    }
}

impl From<Envelope> for protocol::Ciphertext {
    fn from(envelope: Envelope) -> Self {
        Self::new(envelope.body)
    }
}

/// Onde fica o servidor, da configuração do app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// Base do gateway, sem caminho: `wss://gw.falaai.com.br`. `ws://` só no loopback.
    pub gateway_url: String,
    /// Base do `accounts`, sem caminho: `https://…`. `http://` só no loopback.
    pub accounts_url: String,
    /// Certificados raiz em DER. Vazio confia nas raízes da Mozilla; com certificados, só neles
    /// (pinning pela CA do servidor).
    pub root_certificates: Vec<Vec<u8>>,
}

/// Evento emitido pelo núcleo no stream de [`super::FalaaiCore::events`].
#[derive(Clone, PartialEq, Eq)]
pub enum ChatEvent {
    /// Mensagem decifrada de um contato, já gravada no banco local.
    MessageReceived {
        /// Id da mensagem no banco, o mesmo de [`ReceivedMessage::id`].
        id: i64,
        /// Dispositivo que enviou, conforme o certificado de remetente.
        from: DeviceAddress,
        /// Texto decifrado.
        body: Vec<u8>,
        /// A chave de identidade da conta de `from` mudou nesta mensagem: o código de segurança
        /// da conversa é outro. O app mostra o aviso neste ponto da conversa; se a conversa
        /// estava verificada, o envio fica bloqueado até o usuário agir
        /// ([`super::FalaaiCore::set_identity_verified`]).
        identity_changed: bool,
    },
    /// O servidor gravou na fila do destinatário uma mensagem de
    /// [`super::FalaaiCore::send_message`]; ela saiu da outbox.
    MessageSent {
        /// O id que `send_message` devolveu.
        client_message_id: Vec<u8>,
    },
    /// Uma mensagem de [`super::FalaaiCore::send_message`] foi recusada e saiu da outbox sem
    /// ser enviada; reenviar igual não adianta.
    MessageFailed {
        /// O id que `send_message` devolveu.
        client_message_id: Vec<u8>,
        /// Por quê: [`CoreError::SessionNotFound`], [`CoreError::UntrustedIdentity`],
        /// [`CoreError::UnknownDestination`] ou [`CoreError::InvalidEnvelope`].
        error: CoreError,
    },
}

impl fmt::Debug for ChatEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageReceived {
                id,
                from,
                body,
                identity_changed,
            } => f
                .debug_struct("MessageReceived")
                .field("id", id)
                .field("from", from)
                .field("len", &body.len())
                .field("identity_changed", identity_changed)
                .finish(),
            Self::MessageSent { .. } => f.write_str("MessageSent"),
            Self::MessageFailed { error, .. } => f
                .debug_struct("MessageFailed")
                .field("error", error)
                .finish_non_exhaustive(),
        }
    }
}

/// Mensagem recebida, lida do banco local com [`super::FalaaiCore::received_messages`].
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedMessage {
    /// Id da mensagem no banco. Cresce na ordem em que as mensagens foram gravadas, pelo app ou
    /// pela extensão de notificação; serve de cursor.
    pub id: i64,
    /// Dispositivo que enviou, conforme o certificado de remetente.
    pub from: DeviceAddress,
    /// Instante em que o servidor recebeu o envelope, em milissegundos desde a época Unix.
    pub server_timestamp: u64,
    /// Texto decifrado.
    pub body: Vec<u8>,
    /// A chave de identidade da conta de `from` mudou nesta mensagem, como em
    /// [`ChatEvent::MessageReceived`].
    pub identity_changed: bool,
}

impl fmt::Debug for ReceivedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedMessage")
            .field("id", &self.id)
            .field("from", &self.from)
            .field("server_timestamp", &self.server_timestamp)
            .field("len", &self.body.len())
            .field("identity_changed", &self.identity_changed)
            .finish()
    }
}

impl From<InboxMessage> for ReceivedMessage {
    fn from(message: InboxMessage) -> Self {
        Self {
            id: message.id,
            from: DeviceAddress::from(&message.from),
            server_timestamp: message.server_timestamp,
            body: message.body.to_vec(),
            identity_changed: message.identity_changed,
        }
    }
}

/// Código de segurança de uma conversa (safety number): o fingerprint da libsignal sobre as
/// chaves de identidade e os ACIs dos dois lados. Os dois aparelhos mostram os mesmos dígitos.
///
/// `Debug` omite o código: ele identifica o par de contas.
#[derive(Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    /// 60 dígitos decimais, para mostrar em grupos de 5 e conferir de viva voz.
    pub digits: String,
    /// Bytes para o QR. O outro aparelho lê o QR e confere com
    /// [`super::FalaaiCore::safety_number_matches`].
    pub qr: Vec<u8>,
}

impl fmt::Debug for SafetyNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SafetyNumber")
            .field("digits", &"<omitido>")
            .field("qr_len", &self.qr.len())
            .finish()
    }
}

impl From<SafetyCode> for SafetyNumber {
    fn from(code: SafetyCode) -> Self {
        Self {
            digits: code.digits,
            qr: code.qr,
        }
    }
}

/// Situação da identidade de um contato frente ao que o usuário verificou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityStatus {
    /// Nenhuma chave do contato ainda: não houve bundle nem mensagem dele.
    Unknown,
    /// Chave guardada na primeira vista, sem verificação do usuário. Uma troca é aceita e
    /// avisada, sem bloquear.
    Default,
    /// A chave atual é a que o usuário verificou.
    Verified,
    /// O usuário verificou uma chave e a atual é outra: o envio está bloqueado
    /// (`UntrustedIdentity`) até ele verificar a nova ou aceitar a troca.
    Changed,
}

impl From<PeerIdentityStatus> for IdentityStatus {
    fn from(status: PeerIdentityStatus) -> Self {
        match status {
            PeerIdentityStatus::Unknown => Self::Unknown,
            PeerIdentityStatus::Default => Self::Default,
            PeerIdentityStatus::Verified => Self::Verified,
            PeerIdentityStatus::Changed => Self::Changed,
        }
    }
}
