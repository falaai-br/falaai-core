//! Safety numbers ("código de segurança" na UI): o fingerprint da libsignal sobre as chaves de
//! identidade e os ACIs dos dois lados de uma conversa. Os dois aparelhos chegam aos mesmos 60
//! dígitos, e o QR de um é conferido pelo outro, em tempo constante, pela própria libsignal.
//! Nada aqui faz hash nem comparação por conta própria.

use libsignal_protocol::{Aci, Fingerprint, FingerprintError};

use super::store::SqliteStore;
use super::{Address, ProtocolError};

/// Versão do fingerprint com o ACI como identificador estável (a 1 usava o telefone).
const VERSION: u32 = 2;

/// Iterações do hash, as mesmas dos apps do Signal: acima de 112 bits de segurança.
const ITERATIONS: u32 = 5200;

/// Código de segurança de uma conversa, nas duas formas.
pub(crate) struct SafetyCode {
    /// 60 dígitos decimais, os mesmos nos dois aparelhos.
    pub(crate) digits: String,
    /// Fingerprint serializado pela libsignal, para o QR. O outro aparelho o confere com
    /// [`safety_number_matches`].
    pub(crate) qr: Vec<u8>,
}

/// Código de segurança da conversa entre `local` e a conta de `peer`, com a chave guardada para
/// ela. Exige as chaves da conta ([`ProtocolError::NoAccount`]) e alguma chave do contato
/// ([`ProtocolError::UnknownIdentity`]).
pub(crate) fn safety_number(
    store: &SqliteStore,
    local: &Address,
    peer: &Address,
) -> Result<SafetyCode, ProtocolError> {
    let fingerprint = fingerprint(store, local, peer)?;
    Ok(SafetyCode {
        digits: fingerprint
            .display_string()
            .map_err(|_| ProtocolError::Internal)?,
        qr: fingerprint
            .scannable
            .serialize()
            .map_err(|_| ProtocolError::Internal)?,
    })
}

/// `true` se `scanned`, lido do QR mostrado no aparelho de `peer`, é o código de segurança desta
/// conversa. Falha com [`ProtocolError::InvalidSafetyNumber`] se não for um código de segurança
/// ou for de outra versão.
pub(crate) fn safety_number_matches(
    store: &SqliteStore,
    local: &Address,
    peer: &Address,
    scanned: &[u8],
) -> Result<bool, ProtocolError> {
    fingerprint(store, local, peer)?
        .scannable
        .compare(scanned)
        .map_err(|error| match error {
            FingerprintError::VersionMismatch { .. } | FingerprintError::ParsingError(_) => {
                ProtocolError::InvalidSafetyNumber
            }
            FingerprintError::InvalidIterationCount(_) => ProtocolError::Internal,
        })
}

fn fingerprint(
    store: &SqliteStore,
    local: &Address,
    peer: &Address,
) -> Result<Fingerprint, ProtocolError> {
    let local_key = store.local_identity_key()?;
    let peer_key = store
        .peer_identity(peer)?
        .ok_or(ProtocolError::UnknownIdentity)?;
    Fingerprint::new(
        VERSION,
        ITERATIONS,
        &aci_bytes(local)?,
        &local_key,
        &aci_bytes(peer)?,
        &peer_key,
    )
    .map_err(|_| ProtocolError::Internal)
}

/// ACI em binário (os 16 bytes do UUID), o identificador estável do fingerprint.
fn aci_bytes(address: &Address) -> Result<Vec<u8>, ProtocolError> {
    Ok(Aci::parse_from_service_id_string(address.aci())
        .ok_or(ProtocolError::InvalidAddress)?
        .service_id_binary())
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::Arc;

    use libsignal_protocol::{IdentityKeyPair, IdentityKeyStore};

    use super::*;
    use crate::protocol::testing::ready;
    use crate::storage::{Database, DatabaseKey};

    type TestResult = Result<(), Box<dyn Error>>;

    /// Um aparelho: identidade própria gravada e a do contato guardada como vista.
    struct Device {
        address: Address,
        store: SqliteStore,
    }

    impl Device {
        fn new(seed: u8, identity: &IdentityKeyPair) -> Result<Self, Box<dyn Error>> {
            let key = DatabaseKey::from_bytes(&[seed; 32])?;
            let store = SqliteStore::new(Arc::new(Database::open_in_memory(&key)?));
            store.create_local_identity(identity, u32::from(seed))?;
            let aci = libsignal_protocol::Aci::from_uuid_bytes([seed; 16]).service_id_string();
            Ok(Self {
                address: Address::new(&aci, 1)?,
                store,
            })
        }

        fn meet(&mut self, peer: &Device, identity: &IdentityKeyPair) -> TestResult {
            ready(
                self.store
                    .save_identity(&peer.address.0, identity.identity_key()),
            )??;
            Ok(())
        }

        fn safety_number(&self, peer: &Device) -> Result<SafetyCode, ProtocolError> {
            safety_number(&self.store, &self.address, &peer.address)
        }

        fn matches(&self, peer: &Device, scanned: &[u8]) -> Result<bool, ProtocolError> {
            safety_number_matches(&self.store, &self.address, &peer.address, scanned)
        }
    }

    fn alice_and_bob() -> Result<(Device, Device), Box<dyn Error>> {
        let rng = &mut rand::rng();
        let (alice_identity, bob_identity) = (
            IdentityKeyPair::generate(rng),
            IdentityKeyPair::generate(rng),
        );
        let mut alice = Device::new(0xA1, &alice_identity)?;
        let mut bob = Device::new(0xB0, &bob_identity)?;
        alice.meet(&bob, &bob_identity)?;
        bob.meet(&alice, &alice_identity)?;
        Ok((alice, bob))
    }

    #[test]
    fn os_dois_lados_veem_os_mesmos_60_digitos_e_conferem_o_qr_um_do_outro() -> TestResult {
        let (alice, bob) = alice_and_bob()?;
        let (from_alice, from_bob) = (alice.safety_number(&bob)?, bob.safety_number(&alice)?);
        assert_eq!(from_alice.digits, from_bob.digits);
        assert_eq!(from_alice.digits.len(), 60);
        assert!(from_alice.digits.bytes().all(|b| b.is_ascii_digit()));

        assert!(alice.matches(&bob, &from_bob.qr)?);
        assert!(bob.matches(&alice, &from_alice.qr)?);
        // O QR carrega local e remoto em ordem: o próprio não confere.
        assert!(!alice.matches(&bob, &from_alice.qr)?);
        Ok(())
    }

    #[test]
    fn codigo_e_estavel_e_muda_com_a_chave_do_contato() -> TestResult {
        let (mut alice, bob) = alice_and_bob()?;
        let before = alice.safety_number(&bob)?;
        assert_eq!(alice.safety_number(&bob)?.digits, before.digits);

        let reinstalled = IdentityKeyPair::generate(&mut rand::rng());
        alice.meet(&bob, &reinstalled)?;
        let after = alice.safety_number(&bob)?;
        assert_ne!(after.digits, before.digits);
        assert!(!alice.matches(&bob, &bob.safety_number(&alice)?.qr)?);
        Ok(())
    }

    #[test]
    fn exige_conta_e_identidade_do_contato() -> TestResult {
        let rng = &mut rand::rng();
        let alice_identity = IdentityKeyPair::generate(rng);
        let alice = Device::new(0xA1, &alice_identity)?;
        let bob = Device::new(0xB0, &IdentityKeyPair::generate(rng))?;
        assert!(matches!(
            alice.safety_number(&bob),
            Err(ProtocolError::UnknownIdentity)
        ));
        assert_eq!(
            alice.matches(&bob, &[]).err(),
            Some(ProtocolError::UnknownIdentity)
        );

        let empty = SqliteStore::new(Arc::new(Database::open_in_memory(
            &DatabaseKey::from_bytes(&[7; 32])?,
        )?));
        assert!(matches!(
            safety_number(&empty, &alice.address, &bob.address),
            Err(ProtocolError::NoAccount)
        ));
        Ok(())
    }

    #[test]
    fn qr_malformado_ou_de_outra_versao_e_recusado() -> TestResult {
        let (alice, bob) = alice_and_bob()?;
        assert_eq!(
            alice.matches(&bob, b"nao-e-um-qr").err(),
            Some(ProtocolError::InvalidSafetyNumber)
        );
        // Campo 1 do protobuf é a versão: 2 no formato atual, 1 no antigo, por telefone.
        let mut old_version = bob.safety_number(&alice)?.qr;
        assert_eq!(&old_version[..2], &[0x08, 0x02]);
        old_version[1] = 0x01;
        assert_eq!(
            alice.matches(&bob, &old_version).err(),
            Some(ProtocolError::InvalidSafetyNumber)
        );
        Ok(())
    }
}
