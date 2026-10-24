//! Fronteira com a libsignal (ADR-0001).
//!
//! Único módulo do crate que importa `libsignal_protocol` e o `zkgroup` da libsignal. O restante do core depende só da
//! trait [`Sessions`] e dos tipos daqui, que não expõem tipos da libsignal; o storage entra
//! pela trait [`signal::SignalStores`], implementada sobre o banco local em [`store`]. Um
//! upgrade da libsignal que quebre a API fica contido aqui.
//!
//! Toda mensagem sai selada (sealed sender): o remetente só aparece dentro do selo, que só o
//! destinatário abre, junto com o certificado de remetente emitido pelo servidor.
//!
//! A identidade de cada contato segue TOFU com safety numbers ([`identity`]): a troca de chave
//! é guardada e avisada, e bloqueia o envio só em conversa verificada ([`store`]).

pub(crate) mod access;
pub(crate) mod certificate;
mod error;
pub(crate) mod identity;
pub(crate) mod keys;
pub(crate) mod signal;
pub(crate) mod store;
#[cfg(test)]
mod testing;

use std::fmt;

use libsignal_protocol::{
    Aci, DeviceId, IdentityKey, ProtocolAddress, PublicKey, SignalProtocolError, kem,
};
use zeroize::Zeroizing;

pub(crate) use error::ProtocolError;

/// Texto claro decifrado; zerado da memória ao sair de escopo.
pub(crate) type Plaintext = Zeroizing<Vec<u8>>;

/// Sessões 1:1 do Signal Protocol: PQXDH para abrir, Triple Ratchet para cada mensagem e sealed
/// sender por fora.
pub(crate) trait Sessions {
    /// Abre sessão com `peer` a partir do bundle de pré-chaves publicado por ele. Como
    /// [`Self::encrypt`] e [`Self::decrypt`], roda numa transação, com o ratchet preso contra
    /// outros processos. Devolve `true` se a chave de identidade do bundle é outra que não a
    /// guardada para a conta de `peer`: a troca foi aceita e deve virar aviso na conversa.
    ///
    /// Em conversa verificada, uma chave diferente da verificada não abre sessão
    /// ([`ProtocolError::UntrustedIdentity`]), mas fica guardada como a atual, sem confiança:
    /// o safety number passa a mostrá-la para o usuário conferir com o contato, e a sessão
    /// antiga também deixa de enviar até ele agir.
    async fn start_session(
        &mut self,
        peer: &Address,
        bundle: &PeerBundle,
    ) -> Result<bool, ProtocolError>;

    /// Guarda o certificado de remetente que o servidor emitiu para o dispositivo local. Falha
    /// com [`ProtocolError::InvalidSenderCertificate`] se não encadeia até o trust root, já
    /// venceu ou é de outro dispositivo ou identidade.
    async fn set_sender_certificate(&mut self, certificate: &[u8]) -> Result<(), ProtocolError>;

    /// Cifra `plaintext` para `peer` e sela com o certificado de remetente. Exige sessão aberta e
    /// certificado válido ([`ProtocolError::NoSenderCertificate`]).
    async fn encrypt(
        &mut self,
        peer: &Address,
        plaintext: &[u8],
    ) -> Result<Ciphertext, ProtocolError>;

    /// Abre o selo, valida o certificado de remetente no instante `server_timestamp`
    /// (milissegundos desde a época Unix), decifra e passa a mensagem a `deliver`. A primeira
    /// mensagem de uma sessão abre a sessão do lado de quem recebe.
    ///
    /// Tudo roda numa transação, com o ratchet preso contra outros processos, e `deliver` roda
    /// antes de ela ser confirmada: se `deliver` falha, o ratchet volta ao estado anterior e o
    /// mesmo envelope pode ser decifrado de novo.
    async fn decrypt<T, E: From<ProtocolError>>(
        &mut self,
        envelope: &Ciphertext,
        server_timestamp: u64,
        deliver: impl FnOnce(Decrypted) -> Result<T, E>,
    ) -> Result<T, E>;
}

/// Mensagem decifrada e o dispositivo que a enviou, tirado do certificado de remetente. Sem
/// `Debug`: o texto claro não pode ir para log.
pub(crate) struct Decrypted {
    pub(crate) from: Address,
    pub(crate) plaintext: Plaintext,
    /// A chave de identidade da conta de `from` era outra antes desta mensagem: a troca foi
    /// aceita (receber nunca bloqueia) e deve virar aviso na conversa.
    pub(crate) identity_changed: bool,
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

    /// ACI na forma textual do service id.
    pub(crate) fn aci(&self) -> &str {
        self.0.name()
    }

    /// Device id, de 1 a 127.
    pub(crate) fn device_id(&self) -> u8 {
        self.0.device_id().into()
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

/// Pré-chave pública EC descartável, serializada no formato da libsignal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicPreKey {
    pub(crate) id: u32,
    pub(crate) public_key: Vec<u8>,
}

/// Pré-chave pública assinada pela identidade (EC assinada ou Kyber), serializada no formato da
/// libsignal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignedPublicPreKey {
    pub(crate) id: u32,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

/// Pré-chaves públicas de um dispositivo remoto (identidade, EC assinada, Kyber e EC
/// descartável opcional), usadas no PQXDH.
pub(crate) struct PeerBundle(libsignal_protocol::PreKeyBundle);

impl PeerBundle {
    /// Monta o bundle que `peer` publicou, a partir das chaves serializadas. Chave malformada
    /// falha aqui com [`ProtocolError::InvalidKey`]; as assinaturas são verificadas ao abrir a
    /// sessão.
    pub(crate) fn new(
        peer: &Address,
        registration_id: u32,
        identity_key: &[u8],
        pre_key: Option<&PublicPreKey>,
        signed_pre_key: &SignedPublicPreKey,
        kyber_pre_key: &SignedPublicPreKey,
    ) -> Result<Self, ProtocolError> {
        let ec_key = |bytes: &[u8]| PublicKey::try_from(bytes).map_err(SignalProtocolError::from);
        let pre_key = pre_key
            .map(|k| Ok::<_, ProtocolError>((k.id.into(), ec_key(&k.public_key)?)))
            .transpose()?;
        Ok(Self(libsignal_protocol::PreKeyBundle::new(
            registration_id,
            peer.0.device_id(),
            pre_key,
            signed_pre_key.id.into(),
            ec_key(&signed_pre_key.public_key)?,
            signed_pre_key.signature.clone(),
            kyber_pre_key.id.into(),
            kem::PublicKey::deserialize(&kyber_pre_key.public_key)?,
            kyber_pre_key.signature.clone(),
            IdentityKey::decode(identity_key)?,
        )?))
    }
}

/// Mensagem selada pronta para o transporte: uma `UnidentifiedSenderMessage` da libsignal. Só o
/// destinatário a abre; para o servidor é opaca e não revela o remetente.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Ciphertext(Vec<u8>);

impl Ciphertext {
    /// Remonta um envelope recebido do transporte.
    pub(crate) fn new(body: Vec<u8>) -> Self {
        Self(body)
    }

    /// Bytes selados, no formato da libsignal.
    pub(crate) fn body(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ciphertext")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Tipo da mensagem dentro do selo. Só os testes olham: o destinatário não precisa, e o
/// servidor não tem como ver.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CiphertextKind {
    /// Primeira mensagem de uma sessão ainda não confirmada; carrega o material do PQXDH.
    PreKey,
    /// Mensagem de uma sessão estabelecida.
    Message,
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
        let debug = format!("{:?}", Ciphertext::new(vec![0xAB; 4]));
        assert_eq!(debug, "Ciphertext { len: 4 }");
    }
}
