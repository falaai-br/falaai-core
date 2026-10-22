//! Fronteira com a libsignal (ADR-0001).
//!
//! Único módulo do crate que importa `libsignal_protocol`. O restante do core depende só da
//! trait [`Sessions`] e dos tipos daqui, que não expõem tipos da libsignal; o storage entra
//! pela trait [`signal::SignalStores`], implementada sobre o banco local em [`store`]. Um
//! upgrade da libsignal que quebre a API fica contido aqui.

mod error;
pub(crate) mod signal;
pub(crate) mod store;
#[cfg(test)]
mod testing;

use std::fmt;

use libsignal_protocol::{Aci, DeviceId, ProtocolAddress};
use zeroize::Zeroizing;

pub(crate) use error::ProtocolError;

/// Texto claro decifrado; zerado da memória ao sair de escopo.
pub(crate) type Plaintext = Zeroizing<Vec<u8>>;

/// Sessões 1:1 do Signal Protocol: PQXDH para abrir, Triple Ratchet para cada mensagem.
pub(crate) trait Sessions {
    /// Abre sessão com `peer` a partir do bundle de pré-chaves publicado por ele.
    async fn start_session(
        &mut self,
        peer: &Address,
        bundle: &PreKeyBundle,
    ) -> Result<(), ProtocolError>;

    /// Cifra `plaintext` para `peer`. Exige sessão aberta.
    async fn encrypt(
        &mut self,
        peer: &Address,
        plaintext: &[u8],
    ) -> Result<Envelope, ProtocolError>;

    /// Decifra um envelope de `peer`. Um envelope [`EnvelopeKind::PreKey`] abre a sessão do
    /// lado de quem recebe.
    async fn decrypt(
        &mut self,
        peer: &Address,
        envelope: &Envelope,
    ) -> Result<Plaintext, ProtocolError>;
}

/// Dispositivo de uma conta: ACI e device id.
///
/// `Debug` omite o ACI, que nunca pode ir para log em claro.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Address(ProtocolAddress);

impl Address {
    /// Valida o ACI (forma textual do service id) e o device id (1 a 127).
    pub(crate) fn new(aci: &str, device_id: u8) -> Result<Self, ProtocolError> {
        let aci = Aci::parse_from_service_id_string(aci).ok_or(ProtocolError::InvalidAddress)?;
        let device_id = DeviceId::new(device_id).map_err(|_| ProtocolError::InvalidAddress)?;
        Ok(Self(ProtocolAddress::new(
            aci.service_id_string(),
            device_id,
        )))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Address")
            .field("aci", &"<omitido>")
            .field("device_id", &format_args!("{}", self.0.device_id()))
            .finish()
    }
}

/// Pré-chaves públicas de um dispositivo remoto (identidade, EC assinada, Kyber e EC
/// descartável opcional), usadas no PQXDH.
pub(crate) struct PreKeyBundle(libsignal_protocol::PreKeyBundle);

/// Como o destinatário deve decifrar um [`Envelope`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnvelopeKind {
    /// Primeira mensagem de uma sessão ainda não confirmada; carrega o material do PQXDH.
    PreKey,
    /// Mensagem de uma sessão estabelecida.
    Message,
}

/// Mensagem cifrada pronta para o transporte.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    kind: EnvelopeKind,
    body: Vec<u8>,
}

impl Envelope {
    /// Remonta um envelope recebido do transporte.
    pub(crate) fn new(kind: EnvelopeKind, body: Vec<u8>) -> Self {
        Self { kind, body }
    }

    /// Tipo do envelope.
    pub(crate) fn kind(&self) -> EnvelopeKind {
        self.kind
    }

    /// Bytes cifrados, no formato da libsignal.
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("kind", &self.kind)
            .field("len", &self.body.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const ACI: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";

    #[test]
    fn address_aceita_aci_e_device_validos() -> TestResult {
        let address = Address::new(ACI, 1)?;
        assert_eq!(address.0.name(), ACI);
        Ok(())
    }

    #[test]
    fn address_recusa_aci_invalido() {
        for aci in ["", "nao-e-uuid", "PNI:9d0652a3-dcc3-4d11-975f-74d61598733f"] {
            assert_eq!(
                Address::new(aci, 1),
                Err(ProtocolError::InvalidAddress),
                "{aci:?}"
            );
        }
    }

    #[test]
    fn address_recusa_device_id_fora_da_faixa() {
        for device_id in [0, 128, 255] {
            assert_eq!(
                Address::new(ACI, device_id),
                Err(ProtocolError::InvalidAddress)
            );
        }
    }

    #[test]
    fn debug_do_address_omite_o_aci() -> TestResult {
        let debug = format!("{:?}", Address::new(ACI, 3)?);
        assert!(!debug.contains(ACI), "{debug}");
        assert!(debug.contains('3'), "{debug}");
        Ok(())
    }

    #[test]
    fn debug_do_envelope_omite_os_bytes() {
        let debug = format!("{:?}", Envelope::new(EnvelopeKind::Message, vec![0xAB; 4]));
        assert_eq!(debug, "Envelope { kind: Message, len: 4 }");
    }
}
