//! [`Sessions`] sobre a libsignal pinada.

use std::time::SystemTime;

use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, IdentityKeyStore, KyberPreKeyStore,
    PreKeySignalMessage, PreKeyStore, SessionStore, SignalMessage, SignedPreKeyStore,
    message_decrypt, message_encrypt, process_prekey_bundle,
};
use zeroize::Zeroizing;

use super::{Address, Envelope, EnvelopeKind, Plaintext, PreKeyBundle, ProtocolError, Sessions};

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
        bundle: &PreKeyBundle,
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
    ) -> Result<Envelope, ProtocolError> {
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
            CiphertextMessageType::PreKey => EnvelopeKind::PreKey,
            CiphertextMessageType::Whisper => EnvelopeKind::Message,
            CiphertextMessageType::SenderKey | CiphertextMessageType::Plaintext => {
                return Err(ProtocolError::Internal);
            }
        };
        Ok(Envelope::new(kind, message.serialize().to_vec()))
    }

    async fn decrypt(
        &mut self,
        peer: &Address,
        envelope: &Envelope,
    ) -> Result<Plaintext, ProtocolError> {
        let message = match envelope.kind() {
            EnvelopeKind::PreKey => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(envelope.body())?,
            ),
            EnvelopeKind::Message => {
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
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use libsignal_protocol::{
        Aci, GenericSignedPreKey, IdentityKeyPair, InMemSignalProtocolStore, KeyPair,
        KyberPreKeyRecord, PreKeyRecord, SignedPreKeyRecord, Timestamp, kem,
    };

    use super::*;

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

    /// Os stores em memória nunca suspendem: um único poll conclui o futuro.
    fn ready<F: Future>(future: F) -> Result<F::Output, &'static str> {
        match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(output) => Ok(output),
            Poll::Pending => Err("futuro pendente com stores em memória"),
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

        /// Gera pré-chaves (EC descartável, EC assinada e Kyber), guarda as privadas no
        /// store e devolve o bundle público, como seria publicado no servidor.
        fn publish_bundle(&mut self) -> Result<PreKeyBundle, Box<dyn Error>> {
            let rng = &mut rand::rng();
            let store = &mut self.sessions.stores;
            let identity = ready(store.identity_store.get_identity_key_pair())??;
            let registration_id = ready(store.identity_store.get_local_registration_id())??;

            let pre_key = KeyPair::generate(rng);
            let signed = KeyPair::generate(rng);
            let signed_signature = identity
                .private_key()
                .calculate_signature(&signed.public_key.serialize(), rng)?;
            let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
            let kyber_signature = identity
                .private_key()
                .calculate_signature(&kyber.public_key.serialize(), rng)?;

            ready(
                store
                    .pre_key_store
                    .save_pre_key(1.into(), &PreKeyRecord::new(1.into(), &pre_key)),
            )??;
            ready(store.signed_pre_key_store.save_signed_pre_key(
                1.into(),
                &SignedPreKeyRecord::new(
                    1.into(),
                    Timestamp::from_epoch_millis(0),
                    &signed,
                    &signed_signature,
                ),
            ))??;
            ready(store.kyber_pre_key_store.save_kyber_pre_key(
                1.into(),
                &KyberPreKeyRecord::new(
                    1.into(),
                    Timestamp::from_epoch_millis(0),
                    &kyber,
                    &kyber_signature,
                ),
            ))??;

            Ok(PreKeyBundle(libsignal_protocol::PreKeyBundle::new(
                registration_id,
                self.address.0.device_id(),
                Some((1.into(), pre_key.public_key)),
                1.into(),
                signed.public_key,
                signed_signature.to_vec(),
                1.into(),
                kyber.public_key,
                kyber_signature.to_vec(),
                *identity.identity_key(),
            )?))
        }

        fn encrypt(&mut self, to: &Device, plaintext: &[u8]) -> Result<Envelope, Box<dyn Error>> {
            Ok(ready(self.sessions.encrypt(&to.address, plaintext))??)
        }

        fn decrypt(
            &mut self,
            from: &Device,
            envelope: &Envelope,
        ) -> Result<Result<Plaintext, ProtocolError>, Box<dyn Error>> {
            Ok(ready(self.sessions.decrypt(&from.address, envelope))?)
        }
    }

    /// Alice abre sessão com o bundle de Bob e manda a primeira mensagem.
    fn alice_and_bob() -> Result<(Device, Device, Envelope), Box<dyn Error>> {
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
        assert_eq!(first.kind(), EnvelopeKind::PreKey);
        assert_eq!(bob.decrypt(&alice, &first)??.as_slice(), b"oi, bob");

        let reply = bob.encrypt(&alice, b"oi, alice")?;
        assert_eq!(reply.kind(), EnvelopeKind::Message);
        assert_eq!(alice.decrypt(&bob, &reply)??.as_slice(), b"oi, alice");

        let next = alice.encrypt(&bob, b"tudo bem?")?;
        assert_eq!(
            next.kind(),
            EnvelopeKind::Message,
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
        let tampered = Envelope::new(EnvelopeKind::PreKey, body);
        assert_eq!(
            bob.decrypt(&alice, &tampered)?,
            Err(ProtocolError::InvalidMessage)
        );
        Ok(())
    }

    #[test]
    fn envelope_com_tipo_trocado_e_recusado() -> TestResult {
        let (alice, mut bob, first) = alice_and_bob()?;
        let mislabeled = Envelope::new(EnvelopeKind::Message, first.body().to_vec());
        assert!(bob.decrypt(&alice, &mislabeled)?.is_err());
        Ok(())
    }
}
