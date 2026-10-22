//! Superfície exposta ao Flutter via flutter_rust_bridge.
//!
//! Material de chave não cruza esta fronteira: as chaves privadas nascem e ficam no banco local;
//! saem só chaves públicas, envelopes cifrados e texto já decifrado. O único segredo que entra é
//! a chave do banco, que a plataforma guarda (Keychain/Keystore); ela é zerada depois de abrir o
//! banco e nunca volta ao Dart.
//!
//! As funções são síncronas no Rust e o flutter_rust_bridge as roda no seu pool de threads; no
//! Dart todas devolvem `Future`. Os futuros da libsignal não são `Send` e os stores sobre SQLite
//! nunca suspendem, então são conduzidos na própria thread por [`block_on`].

pub mod error;
pub mod types;

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use flutter_rust_bridge::frb;
use zeroize::Zeroizing;

use self::error::CoreError;
use self::types::{AccountKeys, ChatEvent, DeviceAddress, Envelope, PreKeyBundle};
use crate::frb_generated::StreamSink;
use crate::protocol::signal::LibsignalSessions;
use crate::protocol::store::{SqliteStore, SqliteStores};
use crate::protocol::{self, Address, ProtocolError, Sessions};
use crate::storage::{Database, DatabaseKey};

/// Núcleo aberto sobre o banco local de um dispositivo. No Dart é um handle opaco.
#[frb(opaque)]
pub struct FalaaiCore {
    db: Arc<Database>,
    store: SqliteStore,
    /// Vazio até o endereço local ser conhecido: a libsignal precisa dele nas sessões.
    sessions: Mutex<Option<LibsignalSessions<SqliteStores>>>,
    events: Mutex<Option<Deliver>>,
}

/// Entrega um evento ao assinante; `false` se ele já fechou o stream. Closure e não trait: o
/// codegen exporta para o Dart toda trait de `api`.
type Deliver = Box<dyn Fn(ChatEvent) -> bool + Send>;

impl FalaaiCore {
    /// Abre (ou cria) o banco local em `db_path` com a chave de 32 bytes guardada pela
    /// plataforma.
    pub fn open(db_path: String, db_key: Vec<u8>) -> Result<FalaaiCore, CoreError> {
        let db_key = Zeroizing::new(db_key);
        let key = DatabaseKey::from_bytes(&db_key)?;
        let db = Arc::new(Database::open(Path::new(&db_path), &key)?);
        let store = SqliteStore::new(db.clone());
        let sessions = store
            .local_address()?
            .map(|local| LibsignalSessions::new(local, SqliteStores::new(db.clone())));
        Ok(Self {
            db,
            store,
            sessions: Mutex::new(sessions),
            events: Mutex::new(None),
        })
    }

    /// Gera identidade, registration id e pré-chaves da conta e devolve só a parte pública,
    /// para o registro no servidor. Falha com [`CoreError::AccountExists`] se já foram geradas.
    pub fn generate_account_keys(&self) -> Result<AccountKeys, CoreError> {
        Ok(protocol::keys::generate_account_keys(&self.store)?.into())
    }

    /// Grava o endereço que o servidor atribuiu a este dispositivo no registro e libera as
    /// sessões. Exige [`Self::generate_account_keys`] antes; repetir o mesmo endereço não muda
    /// nada.
    pub fn set_local_address(&self, address: DeviceAddress) -> Result<(), CoreError> {
        let local = Address::try_from(&address)?;
        self.store.set_local_address(&local)?;
        *lock(&self.sessions) = Some(LibsignalSessions::new(
            local,
            SqliteStores::new(self.db.clone()),
        ));
        Ok(())
    }

    /// Abre sessão com `peer` a partir do bundle de pré-chaves que ele publicou (PQXDH).
    pub fn process_prekey_bundle(
        &self,
        peer: DeviceAddress,
        bundle: PreKeyBundle,
    ) -> Result<(), CoreError> {
        let peer = Address::try_from(&peer)?;
        let bundle = bundle.to_protocol(&peer)?;
        self.with_sessions(|sessions| block_on(sessions.start_session(&peer, &bundle)))
    }

    /// Cifra `plaintext` para `peer`. Exige sessão aberta.
    pub fn encrypt(&self, peer: DeviceAddress, plaintext: Vec<u8>) -> Result<Envelope, CoreError> {
        let plaintext = Zeroizing::new(plaintext);
        let peer = Address::try_from(&peer)?;
        let envelope =
            self.with_sessions(|sessions| block_on(sessions.encrypt(&peer, &plaintext)))?;
        Ok(envelope.into())
    }

    /// Decifra um envelope de `peer` e entrega o texto no stream de [`Self::events`] como
    /// [`ChatEvent::MessageReceived`]. `Ok` quer dizer que o evento foi entregue e o envelope
    /// pode ser confirmado ao servidor. Sem assinante, falha com [`CoreError::NoEventListener`]
    /// antes de tocar no ratchet.
    pub fn decrypt(&self, peer: DeviceAddress, envelope: Envelope) -> Result<(), CoreError> {
        let from = Address::try_from(&peer)?;
        let envelope = protocol::Ciphertext::from(envelope);
        // O assinante fica travado durante a decifragem: não troca entre a checagem e a entrega.
        let events = lock(&self.events);
        let deliver = events.as_ref().ok_or(CoreError::NoEventListener)?;
        let plaintext =
            self.with_sessions(|sessions| block_on(sessions.decrypt(&from, &envelope)))?;
        let event = ChatEvent::MessageReceived {
            from: peer,
            body: plaintext.to_vec(),
        };
        if deliver(event) {
            Ok(())
        } else {
            Err(CoreError::NoEventListener)
        }
    }

    /// Stream de eventos do núcleo. Assinar de novo substitui o assinante anterior (por exemplo,
    /// num hot restart do Flutter).
    pub fn events(&self, sink: StreamSink<ChatEvent>) {
        self.subscribe(Box::new(move |event| sink.add(event).is_ok()));
    }

    /// Como [`Self::events`], mas entrega a uma closure Rust: os testes de integração em `tests/`
    /// não têm como criar um `StreamSink` sem o Dart. `deliver` devolve `false` quando o
    /// assinante fechou. Só existe com a feature `test-support` e fica fora da ponte.
    #[cfg(feature = "test-support")]
    #[frb(ignore)]
    pub fn subscribe_events(&self, deliver: impl Fn(ChatEvent) -> bool + Send + 'static) {
        self.subscribe(Box::new(deliver));
    }

    fn subscribe(&self, deliver: Deliver) {
        *lock(&self.events) = Some(deliver);
    }

    fn with_sessions<T>(
        &self,
        f: impl FnOnce(&mut LibsignalSessions<SqliteStores>) -> Result<T, ProtocolError>,
    ) -> Result<T, CoreError> {
        let mut sessions = lock(&self.sessions);
        let sessions = sessions.as_mut().ok_or(CoreError::NoAccount)?;
        Ok(f(sessions)?)
    }
}

/// Os mutexes só protegem estado que segue consistente após um panic (que em release aborta).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Conduz `future` até o fim na thread atual.
///
/// `Box::pin` e não `pin!`: o `pin!` expande para `super let`, que o parser do codegen do
/// flutter_rust_bridge 2.13 não aceita.
fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        thread::park();
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::Path;
    use std::sync::mpsc::{self, Receiver};

    use super::*;
    use crate::api::types::EnvelopeKind;

    type TestResult = Result<(), Box<dyn Error>>;

    const KEY: [u8; 32] = [0x5A; 32];

    /// Assina os eventos de `core` num canal.
    fn subscribe(core: &FalaaiCore) -> Receiver<ChatEvent> {
        let (sender, events) = mpsc::channel();
        core.subscribe(Box::new(move |event| sender.send(event).is_ok()));
        events
    }

    /// Um dispositivo: núcleo sobre um banco em arquivo e o stream de eventos assinado.
    struct Device {
        address: DeviceAddress,
        keys: AccountKeys,
        core: FalaaiCore,
        events: Receiver<ChatEvent>,
    }

    impl Device {
        /// Gera as chaves, "registra" (grava o endereço local) e assina os eventos.
        fn register(dir: &Path, seed: u8) -> Result<Self, Box<dyn Error>> {
            let core = open(dir, seed)?;
            let keys = core.generate_account_keys()?;
            let address = address(seed);
            core.set_local_address(address.clone())?;
            let events = subscribe(&core);
            Ok(Self {
                address,
                keys,
                core,
                events,
            })
        }

        /// O que o servidor entregaria: uma pré-chave EC e uma Kyber descartáveis.
        fn bundle(&self) -> Result<PreKeyBundle, Box<dyn Error>> {
            Ok(PreKeyBundle {
                registration_id: self.keys.registration_id,
                identity_key: self.keys.identity_key.clone(),
                pre_key: self.keys.pre_keys.first().cloned(),
                signed_pre_key: self.keys.signed_pre_key.clone(),
                kyber_pre_key: self
                    .keys
                    .kyber_pre_keys
                    .first()
                    .cloned()
                    .ok_or("sem kyber")?,
            })
        }

        fn send(&self, to: &Device, text: &[u8]) -> Result<Envelope, CoreError> {
            self.core.encrypt(to.address.clone(), text.to_vec())
        }

        fn receive(&self, from: &Device, envelope: Envelope) -> Result<Vec<u8>, Box<dyn Error>> {
            self.core.decrypt(from.address.clone(), envelope)?;
            match self.events.try_recv()? {
                ChatEvent::MessageReceived { from: sender, body } => {
                    assert_eq!(sender, from.address);
                    Ok(body)
                }
            }
        }
    }

    fn open(dir: &Path, seed: u8) -> Result<FalaaiCore, CoreError> {
        let path = dir.join(format!("{seed:02x}.db"));
        FalaaiCore::open(path.to_string_lossy().into_owned(), KEY.to_vec())
    }

    fn address(seed: u8) -> DeviceAddress {
        DeviceAddress {
            aci: format!("{seed:02x}{seed:02x}{seed:02x}{seed:02x}-0000-4000-8000-000000000000"),
            device_id: 1,
        }
    }

    /// Alice abre sessão com o bundle de Bob.
    fn alice_and_bob(dir: &Path) -> Result<(Device, Device), Box<dyn Error>> {
        let alice = Device::register(dir, 0xA1)?;
        let bob = Device::register(dir, 0xB0)?;
        alice
            .core
            .process_prekey_bundle(bob.address.clone(), bob.bundle()?)?;
        Ok((alice, bob))
    }

    #[test]
    fn dois_nucleos_trocam_mensagens_pela_api() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (alice, bob) = alice_and_bob(dir.path())?;

        let first = alice.send(&bob, b"oi, bob")?;
        assert_eq!(first.kind, EnvelopeKind::PreKey);
        assert_eq!(bob.receive(&alice, first)?, b"oi, bob");

        let reply = bob.send(&alice, b"oi, alice")?;
        assert_eq!(reply.kind, EnvelopeKind::Message);
        assert_eq!(alice.receive(&bob, reply)?, b"oi, alice");

        let next = alice.send(&bob, b"tudo bem?")?;
        assert_eq!(next.kind, EnvelopeKind::Message);
        assert_eq!(bob.receive(&alice, next)?, b"tudo bem?");
        Ok(())
    }

    #[test]
    fn sessao_e_endereco_local_sobrevivem_a_reabrir() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (alice, mut bob) = alice_and_bob(dir.path())?;
        let first = alice.send(&bob, b"oi, bob")?;

        bob.core = open(dir.path(), 0xB0)?;
        bob.events = subscribe(&bob.core);
        assert_eq!(bob.receive(&alice, first)?, b"oi, bob");
        Ok(())
    }

    #[test]
    fn decifrar_sem_assinante_falha_sem_avancar_o_ratchet() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (alice, bob) = alice_and_bob(dir.path())?;
        let first = alice.send(&bob, b"oi, bob")?;

        let unsubscribed = open(dir.path(), 0xB0)?;
        assert_eq!(
            unsubscribed.decrypt(alice.address.clone(), first.clone()),
            Err(CoreError::NoEventListener)
        );
        assert_eq!(bob.receive(&alice, first)?, b"oi, bob");
        Ok(())
    }

    #[test]
    fn decifrar_com_stream_fechado_falha() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (alice, mut bob) = alice_and_bob(dir.path())?;
        bob.events = mpsc::channel().1;
        let first = alice.send(&bob, b"oi, bob")?;
        assert_eq!(
            bob.core.decrypt(alice.address.clone(), first),
            Err(CoreError::NoEventListener)
        );
        Ok(())
    }

    #[test]
    fn envelope_repetido_e_recusado() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (alice, bob) = alice_and_bob(dir.path())?;
        bob.receive(&alice, alice.send(&bob, b"oi")?)?;
        let reply = bob.send(&alice, b"oi")?;
        alice.receive(&bob, reply.clone())?;
        assert_eq!(
            alice.core.decrypt(bob.address.clone(), reply),
            Err(CoreError::DuplicateMessage)
        );
        Ok(())
    }

    #[test]
    fn cifrar_sem_sessao_falha() -> TestResult {
        let dir = tempfile::tempdir()?;
        let alice = Device::register(dir.path(), 0xA1)?;
        assert_eq!(
            alice.core.encrypt(address(0xB0), b"oi".to_vec()),
            Err(CoreError::SessionNotFound)
        );
        Ok(())
    }

    #[test]
    fn sessoes_exigem_conta_e_endereco_local() -> TestResult {
        let dir = tempfile::tempdir()?;
        let core = open(dir.path(), 0xA1)?;
        assert_eq!(
            core.set_local_address(address(0xA1)),
            Err(CoreError::NoAccount)
        );
        core.generate_account_keys()?;
        assert_eq!(
            core.encrypt(address(0xB0), b"oi".to_vec()),
            Err(CoreError::NoAccount)
        );
        Ok(())
    }

    #[test]
    fn chaves_da_conta_sao_geradas_uma_vez() -> TestResult {
        let dir = tempfile::tempdir()?;
        let core = open(dir.path(), 0xA1)?;
        core.generate_account_keys()?;
        assert_eq!(
            core.generate_account_keys().err(),
            Some(CoreError::AccountExists)
        );
        Ok(())
    }

    #[test]
    fn endereco_local_nao_muda_depois_de_gravado() -> TestResult {
        let dir = tempfile::tempdir()?;
        let alice = Device::register(dir.path(), 0xA1)?;
        alice.core.set_local_address(alice.address.clone())?;
        assert_eq!(
            alice.core.set_local_address(address(0xC0)),
            Err(CoreError::AccountExists)
        );
        let reopened = open(dir.path(), 0xA1)?;
        assert_eq!(
            reopened.set_local_address(address(0xC0)),
            Err(CoreError::AccountExists)
        );
        Ok(())
    }

    #[test]
    fn endereco_invalido_e_recusado() -> TestResult {
        let dir = tempfile::tempdir()?;
        let alice = Device::register(dir.path(), 0xA1)?;
        for peer in [
            DeviceAddress {
                aci: "nao-e-uuid".to_owned(),
                device_id: 1,
            },
            DeviceAddress {
                device_id: 0,
                ..address(0xB0)
            },
        ] {
            assert_eq!(
                alice.core.encrypt(peer, b"oi".to_vec()),
                Err(CoreError::InvalidAddress)
            );
        }
        Ok(())
    }

    #[test]
    fn bundle_com_chave_malformada_ou_assinatura_errada_e_recusado() -> TestResult {
        let dir = tempfile::tempdir()?;
        let alice = Device::register(dir.path(), 0xA1)?;
        let bob = Device::register(dir.path(), 0xB0)?;

        let mut malformed = bob.bundle()?;
        malformed.identity_key.truncate(10);
        let mut forged = bob.bundle()?;
        if let Some(byte) = forged.signed_pre_key.signature.first_mut() {
            *byte ^= 0x01;
        }
        let mut wrong_kyber = bob.bundle()?;
        wrong_kyber.kyber_pre_key.public_key = bob.keys.signed_pre_key.public_key.clone();

        for bundle in [malformed, forged, wrong_kyber] {
            assert_eq!(
                alice
                    .core
                    .process_prekey_bundle(bob.address.clone(), bundle),
                Err(CoreError::InvalidKey)
            );
        }
        Ok(())
    }

    #[test]
    fn banco_com_chave_errada_ou_de_tamanho_invalido_nao_abre() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("a1.db").to_string_lossy().into_owned();
        drop(FalaaiCore::open(path.clone(), KEY.to_vec())?);
        assert_eq!(
            FalaaiCore::open(path.clone(), vec![0x5A; 16]).err(),
            Some(CoreError::InvalidDatabaseKey)
        );
        assert_eq!(
            FalaaiCore::open(path, vec![0x00; 32]).err(),
            Some(CoreError::WrongDatabaseKey)
        );
        Ok(())
    }

    #[test]
    fn debug_dos_tipos_da_api_omite_aci_e_conteudo() {
        let from = address(0xA1);
        let event = ChatEvent::MessageReceived {
            from: from.clone(),
            body: b"segredo".to_vec(),
        };
        let envelope = Envelope {
            kind: EnvelopeKind::Message,
            body: b"segredo".to_vec(),
        };
        for debug in [format!("{event:?}"), format!("{envelope:?}")] {
            assert!(!debug.contains(&from.aci), "{debug}");
            assert!(!debug.contains("segredo"), "{debug}");
            assert!(!debug.contains("115, 101"), "{debug}");
        }
    }
}
