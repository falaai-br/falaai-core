//! Unidentified access do sealed sender (ADR-0010).
//!
//! Quem envia pelo socket não autenticado prova o direito de enviar com a unidentified access
//! key do destinatário: 16 bytes que a libsignal deriva da profile key dele. A profile key chega
//! ao remetente dentro do canal E2EE e fica no banco local; o servidor só conhece a chave
//! derivada, que o destinatário registrou no `accounts`.

use std::fmt;

use zeroize::Zeroizing;

use super::store::SqliteStore;
use super::{Address, ProtocolError};

/// Tamanho da profile key.
pub(crate) const PROFILE_KEY_LEN: usize = zkgroup::PROFILE_KEY_LEN;

/// Tamanho da unidentified access key.
pub(crate) const ACCESS_KEY_LEN: usize = zkgroup::ACCESS_KEY_LEN;

/// Unidentified access key de um destinatário; zerada da memória ao sair de escopo. Sem
/// `Debug` dos bytes: é credencial.
pub(crate) struct AccessKey(Zeroizing<[u8; ACCESS_KEY_LEN]>);

impl AccessKey {
    /// Deriva a chave de `profile_key` pela libsignal (`ProfileKey::derive_access_key`).
    pub(crate) fn derive(profile_key: &[u8; PROFILE_KEY_LEN]) -> Self {
        let profile_key = zkgroup::profiles::ProfileKey::create(*profile_key);
        Self(Zeroizing::new(profile_key.derive_access_key()))
    }

    /// Chave do contato `peer`, se a profile key dele já chegou. Sem ela, o envio só pode ir
    /// pelo socket autenticado.
    pub(crate) fn of(store: &SqliteStore, peer: &Address) -> Result<Option<Self>, ProtocolError> {
        Ok(store
            .peer_profile_key(peer)?
            .map(|profile_key| Self::derive(&profile_key)))
    }

    /// Bytes da chave, para `Send.unidentified_access_key`.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessKey(<omitida>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vetor conhecido da própria libsignal (`zkgroup/src/api/profiles/profile_key.rs`).
    #[test]
    fn deriva_como_a_libsignal() {
        let profile_key = [
            0x26, 0x19, 0x7b, 0x17, 0xe5, 0xa2, 0xc3, 0x6d, 0x8c, 0x95, 0x18, 0xc3, 0x53, 0x58,
            0xf1, 0x23, 0xc4, 0x76, 0x00, 0x0d, 0xb6, 0xda, 0x75, 0x65, 0xc0, 0xd4, 0x1f, 0x66,
            0x74, 0x46, 0x2c, 0x4d,
        ];
        assert_eq!(
            AccessKey::derive(&profile_key).as_bytes(),
            [
                0xe8, 0x95, 0xc3, 0x0c, 0xf7, 0x80, 0x75, 0x7d, 0x22, 0xf7, 0xa1, 0x79, 0x70, 0x8b,
                0x14, 0xa1
            ]
        );
    }

    #[test]
    fn debug_omite_a_chave() {
        let debug = format!("{:?}", AccessKey::derive(&[0x02; PROFILE_KEY_LEN]));
        assert_eq!(debug, "AccessKey(<omitida>)");
    }
}
