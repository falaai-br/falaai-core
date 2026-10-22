//! [`Sessions`] sobre a libsignal pinada.

use std::time::SystemTime;

use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, IdentityKeyStore, KyberPreKeyStore,
    PreKeySignalMessage, PreKeyStore, SessionStore, SignalMessage, SignedPreKeyStore,
    message_decrypt, message_encrypt, process_prekey_bundle,
};
use zeroize::Zeroizing;

use super::{Address, Ciphertext, CiphertextKind, PeerBundle, Plaintext, ProtocolError, Sessions};

/// Stores da libsignal emprestados juntos: as operações de sessão usam vários ao mesmo tempo.
pub(crate) struct StoreParts<'a> {
    pub(crate) sessions: &'a mut dyn SessionStore,
    pub(crate) identities: &'a mut dyn IdentityKeyStore,
    pub(crate) pre_keys: &'a mut dyn PreKeyStore,
    pub(crate) signed_pre_keys: &'a mut dyn SignedPreKeyStore,
    pub(crate) kyber_pre_keys: &'a mut dyn KyberPreKeyStore,
}

/// Estado persistente do protocolo de um dispositivo local. Implementada pelo storage.
pub(crate) trait SignalStores {
    /// Empresta todos os stores de uma vez.
    fn parts(&mut self) -> StoreParts<'_>;
}

/// [`Sessions`] de um dispositivo local, sobre a libsignal.
pub(crate) struct LibsignalSessions<S> {
    local: Address,
    stores: S,
}

impl<S: SignalStores> LibsignalSessions<S> {
    /// Sessões de `local`, com estado em `stores`.
    pub(crate) fn new(local: Address, stores: S) -> Self {
        Self { local, stores }
    }
}

impl<S: SignalStores> Sessions for LibsignalSessions<S> {
    async fn start_session(
        &mut self,
        peer: &Address,
        bundle: &PeerBundle,
    ) -> Result<(), ProtocolError> {
        let stores = self.stores.parts();
        process_prekey_bundle(
            &peer.0,
            &self.local.0,
            stores.sessions,
            stores.identities,
            &bundle.0,
            SystemTime::now(),
            &mut rand::rng(),
        )
        .await?;
        Ok(())
    }

    async fn encrypt(
        &mut self,
        peer: &Address,
        plaintext: &[u8],
    ) -> Result<Ciphertext, ProtocolError> {
        let stores = self.stores.parts();
        let message = message_encrypt(
            plaintext,
            &peer.0,
            &self.local.0,
            stores.sessions,
            stores.identities,
            SystemTime::now(),
            &mut rand::rng(),
        )
        .await?;
        let kind = match message.message_type() {
            CiphertextMessageType::PreKey => CiphertextKind::PreKey,
            CiphertextMessageType::Whisper => CiphertextKind::Message,
            CiphertextMessageType::SenderKey | CiphertextMessageType::Plaintext => {
                return Err(ProtocolError::Internal);
            }
        };
        Ok(Ciphertext::new(kind, message.serialize().to_vec()))
    }

    async fn decrypt(
        &mut self,
        peer: &Address,
        envelope: &Ciphertext,
    ) -> Result<Plaintext, ProtocolError> {
        let message = match envelope.kind() {
            CiphertextKind::PreKey => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(envelope.body())?,
            ),
            CiphertextKind::Message => {
                CiphertextMessage::SignalMessage(SignalMessage::try_from(envelope.body())?)
            }
        };
        let stores = self.stores.parts();
        let plaintext = message_decrypt(
            &message,
            &peer.0,
            &self.local.0,
            stores.sessions,
            stores.identities,
            stores.pre_keys,
            stores.signed_pre_keys,
            stores.kyber_pre_keys,
            &mut rand::rng(),
        )
        .await?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use libsignal_protocol::{Aci, IdentityKeyPair, InMemSignalProtocolStore};

    use super::*;
    use crate::protocol::testing::{self, ready};

    type TestResult = Result<(), Box<dyn Error>>;

    impl SignalStores for InMemSignalProtocolStore {
        fn parts(&mut self) -> StoreParts<'_> {
            StoreParts {
                sessions: &mut self.session_store,
                identities: &mut self.identity_store,
                pre_keys: &mut self.pre_key_store,
                signed_pre_keys: &mut self.signed_pre_key_store,
                kyber_pre_keys: &mut self.kyber_pre_key_store,
            }
        }
    }

    struct Device {
        address: Address,
        sessions: LibsignalSessions<InMemSignalProtocolStore>,
    }

    impl Device {
        fn new(seed: u8) -> Result<Self, Box<dyn Error>> {
            let aci = Aci::from_uuid_bytes([seed; 16]).service_id_string();
            let address = Address::new(&aci, 1)?;
            let identity = IdentityKeyPair::generate(&mut rand::rng());
            let store = InMemSignalProtocolStore::new(identity, u32::from(seed))?;
            Ok(Self {
                sessions: LibsignalSessions::new(address.clone(), store),
                address,
            })
        }

        fn publish_bundle(&mut self) -> Result<PeerBundle, Box<dyn Error>> {
            testing::publish_bundle(self.sessions.stores.parts(), &self.address)
        }

        fn encrypt(&mut self, to: &Device, plaintext: &[u8]) -> Result<Ciphertext, Box<dyn Error>> {
            Ok(ready(self.sessions.encrypt(&to.address, plaintext))??)
        }

        fn decrypt(
            &mut self,
            from: &Device,
            envelope: &Ciphertext,
        ) -> Result<Result<Plaintext, ProtocolError>, Box<dyn Error>> {
            Ok(ready(self.sessions.decrypt(&from.address, envelope))?)
        }
    }

    /// Alice abre sessão com o bundle de Bob e manda a primeira mensagem.
    fn alice_and_bob() -> Result<(Device, Device, Ciphertext), Box<dyn Error>> {
        let mut alice = Device::new(0xA1)?;
        let mut bob = Device::new(0xB0)?;
        let bundle = bob.publish_bundle()?;
        ready(alice.sessions.start_session(&bob.address, &bundle))??;
        let first = alice.encrypt(&bob, b"oi, bob")?;
        Ok((alice, bob, first))
    }

    #[test]
    fn pqxdh_abre_sessao_e_troca_mensagens_nos_dois_sentidos() -> TestResult {
        let (mut alice, mut bob, first) = alice_and_bob()?;
        assert_eq!(first.kind(), CiphertextKind::PreKey);
        assert_eq!(bob.decrypt(&alice, &first)??.as_slice(), b"oi, bob");

        let reply = bob.encrypt(&alice, b"oi, alice")?;
        assert_eq!(reply.kind(), CiphertextKind::Message);
        assert_eq!(alice.decrypt(&bob, &reply)??.as_slice(), b"oi, alice");

        let next = alice.encrypt(&bob, b"tudo bem?")?;
        assert_eq!(
            next.kind(),
            CiphertextKind::Message,
            "sessão confirmada pela resposta"
        );
        assert_eq!(bob.decrypt(&alice, &next)??.as_slice(), b"tudo bem?");
        Ok(())
    }

    #[test]
    fn cifrar_sem_sessao_falha() -> TestResult {
        let mut alice = Device::new(0xA1)?;
        let bob = Device::new(0xB0)?;
        let result = ready(alice.sessions.encrypt(&bob.address, b"oi"))?;
        assert_eq!(result, Err(ProtocolError::SessionNotFound));
        Ok(())
    }

    #[test]
    fn mensagem_repetida_e_recusada() -> TestResult {
        let (mut alice, mut bob, first) = alice_and_bob()?;
        bob.decrypt(&alice, &first)??;
        let reply = bob.encrypt(&alice, b"oi, alice")?;
        alice.decrypt(&bob, &reply)??;
        assert_eq!(
            alice.decrypt(&bob, &reply)?,
            Err(ProtocolError::DuplicateMessage)
        );
        Ok(())
    }

    #[test]
    fn envelope_adulterado_e_recusado() -> TestResult {
        let (alice, mut bob, first) = alice_and_bob()?;
        let mut body = first.body().to_vec();
        if let Some(last) = body.last_mut() {
            *last ^= 0x01;
        }
        let tampered = Ciphertext::new(CiphertextKind::PreKey, body);
        assert_eq!(
            bob.decrypt(&alice, &tampered)?,
            Err(ProtocolError::InvalidMessage)
        );
        Ok(())
    }

    #[test]
    fn envelope_com_tipo_trocado_e_recusado() -> TestResult {
        let (alice, mut bob, first) = alice_and_bob()?;
        let mislabeled = Ciphertext::new(CiphertextKind::Message, first.body().to_vec());
        assert!(bob.decrypt(&alice, &mislabeled)?.is_err());
        Ok(())
    }
}
