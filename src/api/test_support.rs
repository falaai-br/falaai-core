//! Ganchos para os testes de integração em `tests/`. Só existe com a feature `test-support` e
//! fica fora da ponte com o Dart.

use flutter_rust_bridge::frb;

use super::FalaaiCore;
use super::error::CoreError;
use super::types::{DeviceAddress, Envelope};
use crate::protocol::access::{AccessKey, PROFILE_KEY_LEN};
use crate::protocol::certificate::CertificateIssuer;
use crate::protocol::{self, Address};

/// O servidor nos testes: trust root e emissão de certificados de remetente, o papel do
/// `accounts` em produção.
#[frb(ignore)]
pub struct TestAccounts(CertificateIssuer);

impl TestAccounts {
    /// Trust root e chave de servidor novos.
    pub fn new() -> Result<Self, CoreError> {
        Ok(Self(CertificateIssuer::new()?))
    }

    /// Trust root serializado, como vai na configuração do app.
    pub fn trust_root(&self) -> Vec<u8> {
        self.0.trust_root()
    }

    /// Certificado de remetente de `sender`, com identidade pública `identity_key`, válido até
    /// `expiration_millis` (milissegundos desde a época Unix).
    pub fn issue_sender_certificate(
        &self,
        sender: &DeviceAddress,
        identity_key: &[u8],
        expiration_millis: u64,
    ) -> Result<Vec<u8>, CoreError> {
        let sender = Address::try_from(sender)?;
        Ok(self.0.issue(&sender, identity_key, expiration_millis)?)
    }
}

/// Unidentified access key derivada de `profile_key`: o que o destinatário registraria no
/// `accounts` e o gateway compara.
#[frb(ignore)]
pub fn unidentified_access_key(profile_key: &[u8; PROFILE_KEY_LEN]) -> Vec<u8> {
    AccessKey::derive(profile_key).as_bytes().to_vec()
}

/// Tipo da mensagem dentro do selo.
#[frb(ignore)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedKind {
    /// Primeira mensagem de uma sessão ainda não confirmada; carrega o material do PQXDH.
    PreKey,
    /// Mensagem de uma sessão estabelecida.
    Message,
}

impl FalaaiCore {
    /// Grava a profile key da conta de `peer`, o que a troca de profile key dentro do conteúdo
    /// E2EE fará quando existir.
    #[frb(ignore)]
    pub fn set_peer_profile_key(
        &self,
        peer: &DeviceAddress,
        profile_key: &[u8; PROFILE_KEY_LEN],
    ) -> Result<(), CoreError> {
        let peer = Address::try_from(peer)?;
        Ok(self.store.set_peer_profile_key(&peer, profile_key)?)
    }

    /// Abre o selo de um envelope destinado a este núcleo e diz o tipo da mensagem dentro dele,
    /// sem decifrá-la nem tocar no ratchet.
    #[frb(ignore)]
    pub fn sealed_kind(&self, envelope: &Envelope) -> Result<SealedKind, CoreError> {
        let envelope = protocol::Ciphertext::new(envelope.body.clone());
        let kind =
            self.with_sessions(|sessions| super::block_on(sessions.inner_kind(&envelope)))?;
        Ok(match kind {
            protocol::CiphertextKind::PreKey => SealedKind::PreKey,
            protocol::CiphertextKind::Message => SealedKind::Message,
        })
    }
}
