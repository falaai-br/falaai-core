//! Erros que o Dart recebe como exceção tipada.

use crate::protocol::ProtocolError;
use crate::storage::StorageError;

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
    /// Chave pública malformada ou assinatura inválida no bundle.
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
    /// Envelope malformado, adulterado ou que referencia pré-chave inexistente.
    #[error("mensagem inválida")]
    InvalidMessage,
    /// Ninguém ouve o stream de eventos, então a mensagem decifrada não teria para onde ir.
    #[error("sem assinante do stream de eventos")]
    NoEventListener,
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
            StorageError::Sqlite => Self::Storage,
        }
    }
}
