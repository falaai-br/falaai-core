//! Dados que cruzam a fronteira com o Dart. Só chaves públicas, envelopes cifrados e texto já
//! decifrado; chaves públicas e assinaturas vão serializadas no formato da libsignal.

use std::fmt;

use crate::protocol::keys;
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

/// Evento emitido pelo núcleo no stream de [`super::FalaaiCore::events`].
#[derive(Clone, PartialEq, Eq)]
pub enum ChatEvent {
    /// Mensagem decifrada de um contato.
    MessageReceived {
        /// Dispositivo que enviou, conforme o certificado de remetente.
        from: DeviceAddress,
        /// Texto decifrado.
        body: Vec<u8>,
    },
}

impl fmt::Debug for ChatEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageReceived { from, body } => f
                .debug_struct("MessageReceived")
                .field("from", from)
                .field("len", &body.len())
                .finish(),
        }
    }
}
