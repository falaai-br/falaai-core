//! Certificados do sealed sender.
//!
//! O servidor tem uma chave raiz (o trust root, que vem na configuração do app) e com ela assina
//! o certificado da chave que o `accounts` usa para emitir certificados de remetente. Um
//! certificado de remetente amarra ACI, device id e identidade pública de um dispositivo, vale
//! por pouco tempo e vai dentro da mensagem selada; o destinatário o valida contra o trust root
//! depois de abrir o selo.

use std::time::SystemTime;

use libsignal_protocol::{PublicKey, SignalProtocolError, Timestamp};

use super::ProtocolError;

/// Chave pública raiz do servidor. Todo certificado de remetente precisa encadear até ela.
#[derive(Clone)]
pub(crate) struct TrustRoot(pub(super) PublicKey);

impl TrustRoot {
    /// Lê a chave serializada no formato da libsignal (33 bytes, com o byte de tipo).
    pub(crate) fn new(public_key: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self(
            PublicKey::deserialize(public_key).map_err(SignalProtocolError::from)?,
        ))
    }
}

/// Certificado de remetente do dispositivo local, já validado.
#[derive(Clone)]
pub(crate) struct SenderCertificate(pub(super) libsignal_protocol::SenderCertificate);

impl SenderCertificate {
    /// `true` se o certificado já venceu em `now`.
    pub(super) fn expired(&self, now: Timestamp) -> Result<bool, ProtocolError> {
        Ok(now > self.0.expiration()?)
    }
}

/// Instante atual no formato da libsignal.
pub(super) fn now() -> Result<Timestamp, ProtocolError> {
    Timestamp::try_from(SystemTime::now()).map_err(|_| ProtocolError::Internal)
}

/// Emissor de certificados nos testes, no papel do servidor: trust root, certificado do
/// servidor e certificados de remetente. Em produção quem emite é o `accounts`.
#[cfg(any(test, feature = "test-support"))]
pub(crate) struct CertificateIssuer {
    trust_root: libsignal_protocol::KeyPair,
    server_key: libsignal_protocol::KeyPair,
    server_certificate: libsignal_protocol::ServerCertificate,
}

#[cfg(any(test, feature = "test-support"))]
impl CertificateIssuer {
    /// Id do certificado do servidor nos testes.
    const SERVER_KEY_ID: u32 = 1;

    /// Gera trust root e chave do servidor novos.
    pub(crate) fn new() -> Result<Self, ProtocolError> {
        let rng = &mut rand::rng();
        let trust_root = libsignal_protocol::KeyPair::generate(rng);
        let server_key = libsignal_protocol::KeyPair::generate(rng);
        let server_certificate = libsignal_protocol::ServerCertificate::new(
            Self::SERVER_KEY_ID,
            server_key.public_key,
            &trust_root.private_key,
            rng,
        )?;
        Ok(Self {
            trust_root,
            server_key,
            server_certificate,
        })
    }

    /// Trust root serializado, como vai na configuração do app.
    pub(crate) fn trust_root(&self) -> Vec<u8> {
        self.trust_root.public_key.serialize().to_vec()
    }

    /// Certificado de remetente serializado de `sender`, com identidade pública `identity_key`,
    /// válido até `expiration_millis` (milissegundos desde a época Unix).
    pub(crate) fn issue(
        &self,
        sender: &super::Address,
        identity_key: &[u8],
        expiration_millis: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let identity_key = libsignal_protocol::IdentityKey::decode(identity_key)?;
        let certificate = libsignal_protocol::SenderCertificate::new(
            sender.0.name().to_owned(),
            None,
            *identity_key.public_key(),
            sender.0.device_id(),
            Timestamp::from_epoch_millis(expiration_millis),
            self.server_certificate.clone(),
            &self.server_key.private_key,
            &mut rand::rng(),
        )?;
        Ok(certificate.serialized()?.to_vec())
    }
}
