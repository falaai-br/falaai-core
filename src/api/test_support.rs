//! Ganchos para os testes de integração em `tests/`. Só existe com a feature `test-support` e
//! fica fora da ponte com o Dart.

use flutter_rust_bridge::frb;

use super::FalaaiCore;
use super::error::CoreError;
use super::types::{DeviceAddress, Envelope};
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
