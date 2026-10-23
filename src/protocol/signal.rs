//! [`Sessions`] sobre a libsignal pinada.

use std::time::SystemTime;

use libsignal_protocol::{
    IdentityKeyStore, KyberPreKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore, Timestamp,
    process_prekey_bundle, sealed_sender_decrypt, sealed_sender_encrypt,
};

use super::certificate::{self, SenderCertificate, TrustRoot};
use super::{Address, Ciphertext, Decrypted, PeerBundle, ProtocolError, Sessions};

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
    trust_root: TrustRoot,
    /// Fica só em memória: o app guarda o certificado e o entrega de novo ao abrir o núcleo.
    sender_certificate: Option<SenderCertificate>,
    stores: S,
}

impl<S: SignalStores> LibsignalSessions<S> {
    /// Sessões de `local`, com estado em `stores`, aceitando certificados de remetente que
    /// encadeiam até `trust_root`.
    pub(crate) fn new(local: Address, trust_root: TrustRoot, stores: S) -> Self {
        Self {
            local,
            trust_root,
            sender_certificate: None,
            stores,
        }
    }

    /// Tipo da mensagem dentro do selo, sem tocar no ratchet.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) async fn inner_kind(
        &mut self,
        envelope: &Ciphertext,
    ) -> Result<super::CiphertextKind, ProtocolError> {
        use libsignal_protocol::{CiphertextMessageType, sealed_sender_decrypt_to_usmc};

        let stores = self.stores.parts();
        let content = sealed_sender_decrypt_to_usmc(envelope.body(), stores.identities).await?;
        match content.msg_type()? {
            CiphertextMessageType::PreKey => Ok(super::CiphertextKind::PreKey),
            CiphertextMessageType::Whisper => Ok(super::CiphertextKind::Message),
            CiphertextMessageType::SenderKey | CiphertextMessageType::Plaintext => {
                Err(ProtocolError::InvalidMessage)
            }
        }
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

    async fn set_sender_certificate(&mut self, certificate: &[u8]) -> Result<(), ProtocolError> {
        let invalid = |_| ProtocolError::InvalidSenderCertificate;
        let parsed =
            libsignal_protocol::SenderCertificate::deserialize(certificate).map_err(invalid)?;
        let identity = self
            .stores
            .parts()
            .identities
            .get_identity_key_pair()
            .await?;
        let valid = parsed
            .validate(&self.trust_root.0, certificate::now()?)
            .map_err(invalid)?
            && parsed.sender_uuid().map_err(invalid)? == self.local.0.name()
            && parsed.sender_device_id().map_err(invalid)? == self.local.0.device_id()
            && parsed.key().map_err(invalid)? == *identity.public_key();
        if !valid {
            return Err(ProtocolError::InvalidSenderCertificate);
        }
        self.sender_certificate = Some(SenderCertificate(parsed));
        Ok(())
    }

    async fn encrypt(
        &mut self,
        peer: &Address,
        plaintext: &[u8],
    ) -> Result<Ciphertext, ProtocolError> {
        let now = SystemTime::now();
        let sender = self
            .sender_certificate
            .as_ref()
            .ok_or(ProtocolError::NoSenderCertificate)?;
        if sender.expired(certificate::now()?)? {
            return Err(ProtocolError::NoSenderCertificate);
        }
        let stores = self.stores.parts();
        let sealed = sealed_sender_encrypt(
            &peer.0,
            &sender.0,
            plaintext,
            stores.sessions,
            stores.identities,
            now,
            &mut rand::rng(),
        )
        .await?;
        Ok(Ciphertext::new(sealed))
    }

    async fn decrypt(
        &mut self,
        envelope: &Ciphertext,
        server_timestamp: u64,
    ) -> Result<Decrypted, ProtocolError> {
        let stores = self.stores.parts();
        let decrypted = sealed_sender_decrypt(
            envelope.body(),
            &self.trust_root.0,
            Timestamp::from_epoch_millis(server_timestamp),
            None,
            self.local.0.name().to_owned(),
            self.local.0.device_id(),
            stores.identities,
            stores.sessions,
            stores.pre_keys,
            stores.signed_pre_keys,
            stores.kyber_pre_keys,
        )
        .await?;
        // O certificado foi assinado pelo servidor, mas um ACI fora da forma canônica abriria
        // sessão com outro nome para a mesma conta.
        let from = Address::new(&decrypted.sender_uuid, decrypted.device_id.into())
            .ok()
            .filter(|from| from.aci() == decrypted.sender_uuid)
            .ok_or(ProtocolError::InvalidMessage)?;
        Ok(Decrypted {
            from,
            plaintext: decrypted.message.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use libsignal_protocol::{Aci, IdentityKeyPair, InMemSignalProtocolStore};

    use super::*;
    use crate::protocol::certificate::CertificateIssuer;
    use crate::protocol::testing::{self, ready};
    use crate::protocol::{CiphertextKind, Plaintext};

    type TestResult = Result<(), Box<dyn Error>>;

    /// Um dia, a validade dos certificados de remetente.
    const DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;

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

    fn now_millis() -> Result<u64, Box<dyn Error>> {
        Ok(certificate::now()?.epoch_millis())
    }

    struct Device {
        address: Address,
        identity: Vec<u8>,
        sessions: LibsignalSessions<InMemSignalProtocolStore>,
    }

    impl Device {
        /// Dispositivo que confia em `server` e já tem certificado de remetente emitido por ele.
        fn new(seed: u8, server: &CertificateIssuer) -> Result<Self, Box<dyn Error>> {
            let mut device = Self::without_certificate(seed, server)?;
            let certificate = device.certificate(server, now_millis()? + DAY_MILLIS)?;
            ready(device.sessions.set_sender_certificate(&certificate))??;
            Ok(device)
        }

        fn without_certificate(
            seed: u8,
            server: &CertificateIssuer,
        ) -> Result<Self, Box<dyn Error>> {
            let aci = Aci::from_uuid_bytes([seed; 16]).service_id_string();
            let address = Address::new(&aci, 1)?;
            let identity = IdentityKeyPair::generate(&mut rand::rng());
            let store = InMemSignalProtocolStore::new(identity, u32::from(seed))?;
            let trust_root = TrustRoot::new(&server.trust_root())?;
            Ok(Self {
                sessions: LibsignalSessions::new(address.clone(), trust_root, store),
                identity: identity.identity_key().serialize().to_vec(),
                address,
            })
        }

        /// Certificado deste dispositivo emitido por `server`, válido até `expiration_millis`.
        fn certificate(
            &self,
            server: &CertificateIssuer,
            expiration_millis: u64,
        ) -> Result<Vec<u8>, ProtocolError> {
            server.issue(&self.address, &self.identity, expiration_millis)
        }

        /// Troca o certificado sem validar, como faria um remetente malicioso.
        fn force_certificate(&mut self, certificate: &[u8]) -> TestResult {
            self.sessions.sender_certificate = Some(SenderCertificate(
                libsignal_protocol::SenderCertificate::deserialize(certificate)?,
            ));
            Ok(())
        }

        fn publish_bundle(&mut self) -> Result<PeerBundle, Box<dyn Error>> {
            testing::publish_bundle(self.sessions.stores.parts(), &self.address)
        }

        fn encrypt(&mut self, to: &Device, plaintext: &[u8]) -> Result<Ciphertext, Box<dyn Error>> {
            Ok(ready(self.sessions.encrypt(&to.address, plaintext))??)
        }

        fn kind(&mut self, envelope: &Ciphertext) -> Result<CiphertextKind, Box<dyn Error>> {
            Ok(ready(self.sessions.inner_kind(envelope))??)
        }

        fn decrypt_at(
            &mut self,
            envelope: &Ciphertext,
            server_timestamp: u64,
        ) -> Result<Result<Decrypted, ProtocolError>, Box<dyn Error>> {
            Ok(ready(self.sessions.decrypt(envelope, server_timestamp))?)
        }

        /// Decifra exigindo que o remetente do certificado seja `from`.
        fn decrypt(
            &mut self,
            from: &Device,
            envelope: &Ciphertext,
        ) -> Result<Result<Plaintext, ProtocolError>, Box<dyn Error>> {
            Ok(match self.decrypt_at(envelope, now_millis()?)? {
                Ok(decrypted) => {
                    assert_eq!(decrypted.from, from.address);
                    Ok(decrypted.plaintext)
                }
                Err(error) => Err(error),
            })
        }
    }

    /// Alice abre sessão com o bundle de Bob e manda a primeira mensagem.
    fn alice_and_bob(
        server: &CertificateIssuer,
    ) -> Result<(Device, Device, Ciphertext), Box<dyn Error>> {
        let mut alice = Device::new(0xA1, server)?;
        let mut bob = Device::new(0xB0, server)?;
        let bundle = bob.publish_bundle()?;
        ready(alice.sessions.start_session(&bob.address, &bundle))??;
        let first = alice.encrypt(&bob, b"oi, bob")?;
        Ok((alice, bob, first))
    }

    #[test]
    fn pqxdh_abre_sessao_e_troca_mensagens_seladas_nos_dois_sentidos() -> TestResult {
        let server = CertificateIssuer::new()?;
        let (mut alice, mut bob, first) = alice_and_bob(&server)?;
        assert_eq!(bob.kind(&first)?, CiphertextKind::PreKey);
        assert_eq!(bob.decrypt(&alice, &first)??.as_slice(), b"oi, bob");

        let reply = bob.encrypt(&alice, b"oi, alice")?;
        assert_eq!(alice.kind(&reply)?, CiphertextKind::Message);
        assert_eq!(alice.decrypt(&bob, &reply)??.as_slice(), b"oi, alice");

        let next = alice.encrypt(&bob, b"tudo bem?")?;
        assert_eq!(
            bob.kind(&next)?,
            CiphertextKind::Message,
            "sessão confirmada pela resposta"
        );
        assert_eq!(bob.decrypt(&alice, &next)??.as_slice(), b"tudo bem?");
        Ok(())
    }

    #[test]
    fn selo_nao_carrega_remetente_nem_destinatario_em_claro() -> TestResult {
        let server = CertificateIssuer::new()?;
        let (alice, bob, first) = alice_and_bob(&server)?;
        for address in [&alice.address, &bob.address] {
            let uuid = Aci::parse_from_service_id_string(address.aci())
                .ok_or("aci")?
                .service_id_binary();
            for needle in [address.aci().as_bytes(), &uuid[..]] {
                assert!(!first.body().windows(needle.len()).any(|w| w == needle));
            }
        }
        let identity = &alice.identity[1..];
        assert!(!first.body().windows(identity.len()).any(|w| w == identity));
        Ok(())
    }

    #[test]
    fn cifrar_sem_sessao_falha() -> TestResult {
        let server = CertificateIssuer::new()?;
        let mut alice = Device::new(0xA1, &server)?;
        let bob = Device::new(0xB0, &server)?;
        let result = ready(alice.sessions.encrypt(&bob.address, b"oi"))?;
        assert_eq!(result, Err(ProtocolError::SessionNotFound));
        Ok(())
    }

    #[test]
    fn cifrar_sem_certificado_ou_com_certificado_vencido_falha() -> TestResult {
        let server = CertificateIssuer::new()?;
        let mut alice = Device::without_certificate(0xA1, &server)?;
        let mut bob = Device::new(0xB0, &server)?;
        let bundle = bob.publish_bundle()?;
        ready(alice.sessions.start_session(&bob.address, &bundle))??;
        assert_eq!(
            ready(alice.sessions.encrypt(&bob.address, b"oi"))?,
            Err(ProtocolError::NoSenderCertificate)
        );

        let expired = alice.certificate(&server, now_millis()? - 1)?;
        alice.force_certificate(&expired)?;
        assert_eq!(
            ready(alice.sessions.encrypt(&bob.address, b"oi"))?,
            Err(ProtocolError::NoSenderCertificate)
        );
        Ok(())
    }

    #[test]
    fn certificado_de_remetente_invalido_e_recusado() -> TestResult {
        let server = CertificateIssuer::new()?;
        let rogue = CertificateIssuer::new()?;
        let mut alice = Device::without_certificate(0xA1, &server)?;
        let bob = Device::new(0xB0, &server)?;
        let tomorrow = now_millis()? + DAY_MILLIS;

        let mut garbage = alice.certificate(&server, tomorrow)?;
        if let Some(byte) = garbage.last_mut() {
            *byte ^= 0x01;
        }
        let cases = [
            ("outro servidor", alice.certificate(&rogue, tomorrow)?),
            ("vencido", alice.certificate(&server, now_millis()? - 1)?),
            (
                "outro dispositivo",
                server.issue(&bob.address, &alice.identity, tomorrow)?,
            ),
            (
                "outra identidade",
                server.issue(&alice.address, &bob.identity, tomorrow)?,
            ),
            ("assinatura adulterada", garbage),
            ("malformado", vec![0x0A, 0x01]),
        ];
        for (case, certificate) in cases {
            assert_eq!(
                ready(alice.sessions.set_sender_certificate(&certificate))?,
                Err(ProtocolError::InvalidSenderCertificate),
                "{case}"
            );
        }
        assert!(alice.sessions.sender_certificate.is_none());
        Ok(())
    }

    #[test]
    fn selo_com_certificado_de_outro_servidor_e_recusado() -> TestResult {
        let server = CertificateIssuer::new()?;
        let rogue = CertificateIssuer::new()?;
        let (mut alice, mut bob, _) = alice_and_bob(&server)?;
        let forged = alice.certificate(&rogue, now_millis()? + DAY_MILLIS)?;
        alice.force_certificate(&forged)?;
        let envelope = alice.encrypt(&bob, b"oi")?;
        assert_eq!(
            bob.decrypt(&alice, &envelope)?.err(),
            Some(ProtocolError::InvalidMessage)
        );
        Ok(())
    }

    #[test]
    fn certificado_vale_no_instante_do_servidor_e_nao_no_da_decifragem() -> TestResult {
        let server = CertificateIssuer::new()?;
        let (alice, mut bob, first) = alice_and_bob(&server)?;
        let expiration = alice
            .sessions
            .sender_certificate
            .as_ref()
            .ok_or("sem certificado")?
            .0
            .expiration()?
            .epoch_millis();
        assert_eq!(
            bob.decrypt_at(&first, expiration + 1)?.err(),
            Some(ProtocolError::InvalidMessage),
            "vencido no instante do servidor"
        );
        let decrypted = bob.decrypt_at(&first, expiration)??;
        assert_eq!(decrypted.plaintext.as_slice(), b"oi, bob");
        Ok(())
    }

    #[test]
    fn mensagem_repetida_e_recusada() -> TestResult {
        let server = CertificateIssuer::new()?;
        let (mut alice, mut bob, first) = alice_and_bob(&server)?;
        bob.decrypt(&alice, &first)??;
        let reply = bob.encrypt(&alice, b"oi, alice")?;
        alice.decrypt(&bob, &reply)??;
        assert_eq!(
            alice.decrypt(&bob, &reply)?.err(),
            Some(ProtocolError::DuplicateMessage)
        );
        Ok(())
    }

    #[test]
    fn envelope_adulterado_e_recusado() -> TestResult {
        let server = CertificateIssuer::new()?;
        let (alice, mut bob, first) = alice_and_bob(&server)?;
        let mut body = first.body().to_vec();
        if let Some(last) = body.last_mut() {
            *last ^= 0x01;
        }
        let tampered = Ciphertext::new(body);
        assert_eq!(
            bob.decrypt(&alice, &tampered)?.err(),
            Some(ProtocolError::InvalidMessage)
        );
        Ok(())
    }
}
