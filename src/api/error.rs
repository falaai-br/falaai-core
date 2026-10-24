//! Erros que o Dart recebe como exceção tipada.

use crate::messaging::outbox::Rejection;
use crate::protocol::ProtocolError;
use crate::storage::StorageError;
use crate::transport::{Sent, TransportError};

/// Erro de uma chamada ao núcleo. As variantes não carregam endereço, ACI, chave nem conteúdo.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// A chave do banco entregue pela plataforma não tem 32 bytes.
    #[error("chave do banco com tamanho inválido")]
    InvalidDatabaseKey,
    /// O banco não abre com a chave dada: chave errada ou arquivo corrompido.
    #[error("chave do banco incorreta ou arquivo corrompido")]
    WrongDatabaseKey,
    /// Outro processo (a extensão de notificação do iOS) segurou o banco além do timeout.
    #[error("banco ocupado por outro processo")]
    DatabaseBusy,
    /// O banco foi migrado por uma versão mais nova do app.
    #[error("banco de versão mais nova que o app")]
    UnsupportedDatabaseVersion,
    /// Outra falha do banco local.
    #[error("falha no banco local")]
    Storage,
    /// As chaves da conta já foram geradas, ou o endereço local já é outro.
    #[error("conta já criada")]
    AccountExists,
    /// Faltam as chaves da conta ou o endereço local.
    #[error("conta não criada")]
    NoAccount,
    /// ACI ou device id inválido.
    #[error("endereço inválido")]
    InvalidAddress,
    /// Chave pública malformada ou assinatura inválida no bundle, ou trust root malformado.
    #[error("chave inválida")]
    InvalidKey,
    /// Não há sessão com o dispositivo remoto: buscar o bundle e chamar `process_prekey_bundle`.
    #[error("sessão inexistente")]
    SessionNotFound,
    /// A identidade do contato mudou e não foi aceita.
    #[error("identidade remota não confiável")]
    UntrustedIdentity,
    /// Envelope já decifrado antes.
    #[error("mensagem duplicada")]
    DuplicateMessage,
    /// Envelope malformado, adulterado, com certificado de remetente que não valida ou que
    /// referencia pré-chave inexistente.
    #[error("mensagem inválida")]
    InvalidMessage,
    /// Sem certificado de remetente, ou o que há venceu: pedir um novo ao servidor e entregar
    /// com `set_sender_certificate`.
    #[error("sem certificado de remetente válido")]
    NoSenderCertificate,
    /// O certificado de remetente não encadeia até o trust root, venceu ou é de outro
    /// dispositivo ou identidade.
    #[error("certificado de remetente inválido")]
    InvalidSenderCertificate,
    /// Ninguém ouve o stream de eventos, então a mensagem decifrada não teria para onde ir.
    #[error("sem assinante do stream de eventos")]
    NoEventListener,
    /// URL do servidor malformada, com caminho ou sem TLS fora do loopback, ou certificado raiz
    /// malformado.
    #[error("configuração do servidor inválida")]
    InvalidServerConfig,
    /// Falha de rede, de TLS ou tempo esgotado; tentar de novo mais tarde.
    #[error("falha de rede")]
    Network,
    /// Sem conexão com o servidor: chamar `connect`, ou esperar a reconexão.
    #[error("sem conexão com o servidor")]
    NotConnected,
    /// O servidor recusou o token do dispositivo.
    #[error("credencial do dispositivo recusada")]
    Unauthorized,
    /// O servidor respondeu fora do contrato.
    #[error("resposta inválida do servidor")]
    InvalidServerResponse,
    /// O servidor recusou o envelope, ou o `client_message_id` não tem 16 bytes; reenviar igual
    /// não adianta.
    #[error("envelope inválido")]
    InvalidEnvelope,
    /// Destinatário ou dispositivo inexistente.
    #[error("destinatário inexistente")]
    UnknownDestination,
    /// Limite de taxa do servidor; reenviar com backoff.
    #[error("limite de envio atingido")]
    RateLimited,
    /// Estado inesperado do núcleo.
    #[error("erro interno do núcleo")]
    Internal,
}

impl From<ProtocolError> for CoreError {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::InvalidAddress => Self::InvalidAddress,
            ProtocolError::SessionNotFound => Self::SessionNotFound,
            ProtocolError::UntrustedIdentity => Self::UntrustedIdentity,
            ProtocolError::DuplicateMessage => Self::DuplicateMessage,
            ProtocolError::InvalidMessage => Self::InvalidMessage,
            ProtocolError::InvalidKey => Self::InvalidKey,
            ProtocolError::AccountExists => Self::AccountExists,
            ProtocolError::NoAccount => Self::NoAccount,
            ProtocolError::NoSenderCertificate => Self::NoSenderCertificate,
            ProtocolError::InvalidSenderCertificate => Self::InvalidSenderCertificate,
            ProtocolError::Busy => Self::DatabaseBusy,
            ProtocolError::Storage => Self::Storage,
            ProtocolError::Internal => Self::Internal,
        }
    }
}

impl From<StorageError> for CoreError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::InvalidKeyLength => Self::InvalidDatabaseKey,
            StorageError::WrongKeyOrCorrupt => Self::WrongDatabaseKey,
            StorageError::Busy => Self::DatabaseBusy,
            StorageError::UnsupportedVersion => Self::UnsupportedDatabaseVersion,
            StorageError::LockFile | StorageError::Sqlite => Self::Storage,
        }
    }
}

impl From<TransportError> for CoreError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::InvalidEndpoint | TransportError::InvalidRootCertificate => {
                Self::InvalidServerConfig
            }
            TransportError::Network => Self::Network,
            TransportError::NotConnected => Self::NotConnected,
            TransportError::Unauthorized => Self::Unauthorized,
            TransportError::Protocol => Self::InvalidServerResponse,
        }
    }
}

impl From<Rejection> for CoreError {
    fn from(rejection: Rejection) -> Self {
        match rejection {
            Rejection::InvalidEnvelope => Self::InvalidEnvelope,
            Rejection::UnknownDestination => Self::UnknownDestination,
            Rejection::SessionNotFound => Self::SessionNotFound,
            Rejection::UntrustedIdentity => Self::UntrustedIdentity,
        }
    }
}

impl CoreError {
    /// Erro de um envio que o servidor respondeu sem aceitar.
    pub(crate) fn from_sent(sent: Sent) -> Result<(), Self> {
        match sent {
            Sent::Accepted => Ok(()),
            Sent::Invalid => Err(Self::InvalidEnvelope),
            Sent::UnknownDestination => Err(Self::UnknownDestination),
            Sent::RateLimited => Err(Self::RateLimited),
            Sent::Unauthorized => Err(Self::Unauthorized),
        }
    }
}
