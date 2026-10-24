//! Erros do protocolo, sem dados sensíveis.

use libsignal_protocol::SignalProtocolError;

/// Erro do protocolo. As variantes não carregam endereço, ACI nem conteúdo, então podem ir
/// para log; o erro original da libsignal, que pode carregar o endereço, é descartado.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProtocolError {
    /// ACI ou device id inválido.
    #[error("endereço inválido")]
    InvalidAddress,
    /// Não há sessão com o dispositivo remoto.
    #[error("sessão inexistente")]
    SessionNotFound,
    /// Conversa verificada cuja chave de identidade do contato mudou: o envio fica bloqueado
    /// até o usuário verificar a chave nova ou aceitar a troca.
    #[error("identidade remota não confiável")]
    UntrustedIdentity,
    /// Nenhuma chave de identidade guardada para o contato: ainda não houve bundle nem mensagem
    /// dele.
    #[error("identidade do contato desconhecida")]
    UnknownIdentity,
    /// O QR lido não é um código de segurança, ou é de uma versão incompatível.
    #[error("código de segurança inválido")]
    InvalidSafetyNumber,
    /// Mensagem já decifrada antes.
    #[error("mensagem duplicada")]
    DuplicateMessage,
    /// Mensagem malformada, adulterada ou que referencia pré-chave inexistente.
    #[error("mensagem inválida")]
    InvalidMessage,
    /// Chave, assinatura ou acordo de chaves inválido.
    #[error("chave inválida")]
    InvalidKey,
    /// As chaves da conta já foram geradas, ou o endereço local já é outro.
    #[error("conta já criada")]
    AccountExists,
    /// Ainda não há chaves da conta, ou falta o endereço local.
    #[error("conta não criada")]
    NoAccount,
    /// Não há certificado de remetente, ou o que há venceu.
    #[error("sem certificado de remetente válido")]
    NoSenderCertificate,
    /// O certificado de remetente não encadeia até o trust root, venceu ou é de outro
    /// dispositivo ou identidade.
    #[error("certificado de remetente inválido")]
    InvalidSenderCertificate,
    /// Outro processo (o app ou a extensão de notificação) segurou o ratchet além do timeout.
    #[error("ratchet ocupado por outro processo")]
    Busy,
    /// Falha devolvida por um store.
    #[error("falha no armazenamento do protocolo")]
    Storage,
    /// Estado inesperado da libsignal.
    #[error("erro interno do protocolo")]
    Internal,
}

impl From<SignalProtocolError> for ProtocolError {
    fn from(error: SignalProtocolError) -> Self {
        use SignalProtocolError as E;
        match error {
            E::InvalidProtocolAddress { .. } => Self::InvalidAddress,
            E::SessionNotFound(_) => Self::SessionNotFound,
            E::UntrustedIdentity(_) => Self::UntrustedIdentity,
            E::DuplicatedMessage(..) => Self::DuplicateMessage,
            E::InvalidMessage(..)
            | E::InvalidProtobufEncoding
            | E::CiphertextMessageTooShort(_)
            | E::LegacyCiphertextVersion(_)
            | E::UnrecognizedCiphertextVersion(_)
            | E::UnrecognizedMessageVersion(_)
            | E::InvalidPreKeyId
            | E::InvalidSignedPreKeyId
            | E::InvalidKyberPreKeyId
            | E::InvalidRegistrationId(..)
            // Selo adulterado, de versão desconhecida, com certificado de remetente que não
            // valida, ou mandado pelo próprio dispositivo.
            | E::InvalidSealedSenderMessage(_)
            | E::UnknownSealedSenderVersion(_)
            | E::UnknownSealedSenderServerCertificateId(_)
            | E::SealedSenderSelfSend => Self::InvalidMessage,
            E::NoKeyTypeIdentifier
            | E::BadKeyType(_)
            | E::BadKeyLength(..)
            | E::InvalidKeyAgreement
            | E::SignatureValidationFailed
            | E::InvalidMacKeyLength(_)
            | E::BadKEMKeyType(_)
            | E::WrongKEMKeyType(..)
            | E::BadKEMKeyLength(..)
            | E::BadKEMCiphertextLength(..) => Self::InvalidKey,
            E::ApplicationCallbackError(..) => Self::Storage,
            _ => Self::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::{
        DeviceId, ProtocolAddress, SessionNotFound, SignalProtocolError as E,
    };

    use super::*;

    #[test]
    fn erros_com_endereco_viram_variantes_sem_endereco() -> Result<(), Box<dyn std::error::Error>> {
        let address = ProtocolAddress::new("segredo".to_owned(), DeviceId::new(1)?);
        let cases = [
            (
                E::SessionNotFound(SessionNotFound::new(address.clone(), "teste")),
                ProtocolError::SessionNotFound,
            ),
            (
                E::UntrustedIdentity(address.clone()),
                ProtocolError::UntrustedIdentity,
            ),
            (
                E::InvalidRegistrationId(address, 7),
                ProtocolError::InvalidMessage,
            ),
        ];
        for (signal, expected) in cases {
            let ours = ProtocolError::from(signal);
            assert_eq!(ours, expected);
            assert!(!format!("{ours} {ours:?}").contains("segredo"));
        }
        Ok(())
    }
}
