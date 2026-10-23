//! Superfície exposta ao Flutter via flutter_rust_bridge.
//!
//! Material de chave não cruza esta fronteira: as chaves privadas nascem e ficam no banco local;
//! saem só chaves públicas, envelopes selados e texto já decifrado. O único segredo que entra é
//! a chave do banco, que a plataforma guarda (Keychain/Keystore); ela é zerada depois de abrir o
//! banco e nunca volta ao Dart.
//!
//! Todo envelope sai selado (sealed sender): o servidor não vê o remetente. Para isso o app
//! entrega o trust root do servidor ao abrir o núcleo e o certificado de remetente emitido pelo
//! `accounts` com [`FalaaiCore::set_sender_certificate`].
//!
//! O transporte também é do núcleo: o app não abre socket nem HTTPS. [`FalaaiCore::connect`]
//! abre o socket autenticado, que recebe, decifra e confirma envelopes em segundo plano;
//! [`FalaaiCore::send`] envia pelo socket não autenticado sempre que tem a unidentified access
//! key do destinatário (ADR-0010).
//!
//! As funções são síncronas no Rust e o flutter_rust_bridge as roda no seu pool de threads; no
//! Dart todas devolvem `Future`. Os futuros da libsignal não são `Send` e os stores sobre SQLite
//! nunca suspendem, então são conduzidos na própria thread por [`block_on`].

pub mod error;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod types;

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use flutter_rust_bridge::frb;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::error::CoreError;
use self::types::{AccountKeys, ChatEvent, DeviceAddress, Envelope, PreKeyBundle, ServerConfig};
use crate::frb_generated::StreamSink;
use crate::protocol::access::AccessKey;
use crate::protocol::certificate::TrustRoot;
use crate::protocol::signal::LibsignalSessions;
use crate::protocol::store::{SqliteStore, SqliteStores};
use crate::protocol::{self, Address, ProtocolError, Sessions};
use crate::storage::{Database, DatabaseKey};
use crate::transport::{Credentials, Disposition, Outgoing, Server, Transport};

/// Tamanho do `client_message_id`: um UUID.
const CLIENT_MESSAGE_ID_LEN: usize = 16;

/// Núcleo aberto sobre o banco local de um dispositivo. No Dart é um handle opaco.
#[frb(opaque)]
pub struct FalaaiCore {
    db: Arc<Database>,
    store: SqliteStore,
    trust_root: TrustRoot,
    /// Vazio até o endereço local ser conhecido: a libsignal precisa dele nas sessões.
    /// Compartilhado com a thread do socket autenticado, que decifra o que chega.
    sessions: Arc<Mutex<Option<CoreSessions>>>,
    events: Arc<Mutex<Option<Deliver>>>,
    /// Conexão com o servidor, depois de [`Self::connect`].
    transport: Mutex<Option<Arc<Transport>>>,
}

type CoreSessions = LibsignalSessions<SqliteStores>;

/// Entrega um evento ao assinante; `false` se ele já fechou o stream. Closure e não trait: o
/// codegen exporta para o Dart toda trait de `api`.
type Deliver = Box<dyn Fn(ChatEvent) -> bool + Send>;

impl FalaaiCore {
    /// Abre (ou cria) o banco local em `db_path` com a chave de 32 bytes guardada pela
    /// plataforma. `trust_root` é a chave pública raiz do servidor, da configuração do app
    /// (33 bytes, formato da libsignal): só certificados de remetente que encadeiam até ela são
    /// aceitos.
    pub fn open(
        db_path: String,
        db_key: Vec<u8>,
        trust_root: Vec<u8>,
    ) -> Result<FalaaiCore, CoreError> {
        let db_key = Zeroizing::new(db_key);
        let trust_root = TrustRoot::new(&trust_root)?;
        let key = DatabaseKey::from_bytes(&db_key)?;
        let db = Arc::new(Database::open(Path::new(&db_path), &key)?);
        let store = SqliteStore::new(db.clone());
        let sessions = store.local_address()?.map(|local| {
            LibsignalSessions::new(local, trust_root.clone(), SqliteStores::new(db.clone()))
        });
        Ok(Self {
            db,
            store,
            trust_root,
            sessions: Arc::new(Mutex::new(sessions)),
            events: Arc::new(Mutex::new(None)),
            transport: Mutex::new(None),
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
        let mut sessions = lock(&self.sessions);
        // Repetir o mesmo endereço não descarta o certificado de remetente já entregue.
        if sessions.is_none() {
            *sessions = Some(LibsignalSessions::new(
                local,
                self.trust_root.clone(),
                SqliteStores::new(self.db.clone()),
            ));
        }
        Ok(())
    }

    /// Entrega o certificado de remetente que o `accounts` emitiu para este dispositivo. Ele vale
    /// pouco tempo (24h) e fica só em memória: o app o guarda, entrega de novo ao abrir o núcleo e
    /// pede outro quando [`Self::encrypt`] falhar com [`CoreError::NoSenderCertificate`]. Falha
    /// com [`CoreError::InvalidSenderCertificate`] se o certificado não encadeia até o trust
    /// root, já venceu ou é de outro dispositivo ou identidade.
    pub fn set_sender_certificate(&self, certificate: Vec<u8>) -> Result<(), CoreError> {
        self.with_sessions(|sessions| block_on(sessions.set_sender_certificate(&certificate)))
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

    /// Cifra `plaintext` para `peer` e sela com o certificado de remetente; o resultado vai em
    /// `Envelope.content`. Exige sessão aberta e certificado de remetente válido.
    pub fn encrypt(&self, peer: DeviceAddress, plaintext: Vec<u8>) -> Result<Envelope, CoreError> {
        let plaintext = Zeroizing::new(plaintext);
        let peer = Address::try_from(&peer)?;
        let envelope =
            self.with_sessions(|sessions| block_on(sessions.encrypt(&peer, &plaintext)))?;
        Ok(envelope.into())
    }

    /// Abre e decifra um envelope selado e entrega o texto, com o remetente tirado do certificado,
    /// no stream de [`Self::events`] como [`ChatEvent::MessageReceived`]. `server_timestamp` é o
    /// do `Deliver` (milissegundos desde a época Unix): o certificado de remetente tem de valer
    /// nesse instante, então uma mensagem que esperou na fila ainda abre. `Ok` quer dizer que o
    /// evento foi entregue e o envelope pode ser confirmado ao servidor. Sem assinante, falha com
    /// [`CoreError::NoEventListener`] antes de tocar no ratchet.
    pub fn decrypt(&self, envelope: Envelope, server_timestamp: u64) -> Result<(), CoreError> {
        receive(
            &self.sessions,
            &self.events,
            &protocol::Ciphertext::from(envelope),
            server_timestamp,
        )
    }

    /// Conecta ao servidor com o token que o `accounts` emitiu no registro deste dispositivo.
    /// Exige o endereço local ([`Self::set_local_address`]).
    ///
    /// Volta logo: o socket autenticado conecta em segundo plano e reconecta sozinho quando cai.
    /// Cada envelope que chega é decifrado e entregue no stream de [`Self::events`], como em
    /// [`Self::decrypt`], e só então confirmado ao servidor. Um envelope que nunca vai abrir
    /// (adulterado, duplicado, de identidade não confiável) também é confirmado e descartado; um
    /// que falhou por causa local (sem assinante, banco ocupado) fica na fila e volta na próxima
    /// conexão. Conectar de novo troca a conexão anterior.
    pub fn connect(&self, server: ServerConfig, token: String) -> Result<(), CoreError> {
        let token = Zeroizing::new(token);
        let server = Server::new(
            &server.gateway_url,
            &server.accounts_url,
            &server.root_certificates,
        )?;
        let local = self.store.local_address()?.ok_or(CoreError::NoAccount)?;
        let credentials = Credentials::new(local.aci(), local.device_id(), token);
        let (sessions, events) = (self.sessions.clone(), self.events.clone());
        let transport = Transport::connect(&server, credentials, move |content, timestamp| {
            let envelope = protocol::Ciphertext::new(content.to_vec());
            disposition(receive(&sessions, &events, &envelope, timestamp))
        })?;
        *lock(&self.transport) = Some(Arc::new(transport));
        Ok(())
    }

    /// Fecha a conexão com o servidor. Sem efeito se não houver.
    pub fn disconnect(&self) {
        *lock(&self.transport) = None;
    }

    /// Envia a `peer` um envelope de [`Self::encrypt`], identificado por `client_message_id`
    /// (16 bytes, um UUID; reenviar com o mesmo id deixa o destinatário deduplicar). `Ok` quer
    /// dizer que o servidor gravou na fila do destinatário.
    ///
    /// Com a profile key do contato, vai pelo socket não autenticado e o servidor não sabe quem
    /// envia. Sem ela (primeiro contato), ou se o servidor recusar a access key, vai pelo socket
    /// autenticado e o servidor vê o par remetente/destinatário (risco residual da ADR-0010).
    pub fn send(
        &self,
        peer: DeviceAddress,
        client_message_id: Vec<u8>,
        envelope: Envelope,
    ) -> Result<(), CoreError> {
        let peer = Address::try_from(&peer)?;
        if client_message_id.len() != CLIENT_MESSAGE_ID_LEN {
            return Err(CoreError::InvalidEnvelope);
        }
        let destination_aci = Uuid::parse_str(peer.aci())
            .map_err(|_| CoreError::InvalidAddress)?
            .into_bytes();
        let access_key = AccessKey::of(&self.store, &peer)?;
        let outgoing = Outgoing {
            destination_aci,
            destination_device_id: peer.device_id(),
            client_message_id,
            content: envelope.body,
        };
        let sent = self
            .transport()?
            .send(outgoing, access_key.as_ref().map(AccessKey::as_bytes))?;
        CoreError::from_sent(sent)
    }

    /// Pede ao `accounts` um certificado de remetente novo para este dispositivo (vale 24h) e
    /// devolve os bytes, para o app entregar com [`Self::set_sender_certificate`] e guardar.
    /// Exige [`Self::connect`], que traz o endereço do servidor e o token.
    pub fn fetch_sender_certificate(&self) -> Result<Vec<u8>, CoreError> {
        Ok(self.transport()?.sender_certificate()?)
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
        f: impl FnOnce(&mut CoreSessions) -> Result<T, ProtocolError>,
    ) -> Result<T, CoreError> {
        with_sessions(&self.sessions, f)
    }

    fn transport(&self) -> Result<Arc<Transport>, CoreError> {
        lock(&self.transport).clone().ok_or(CoreError::NotConnected)
    }
}

fn with_sessions<T>(
    sessions: &Mutex<Option<CoreSessions>>,
    f: impl FnOnce(&mut CoreSessions) -> Result<T, ProtocolError>,
) -> Result<T, CoreError> {
    let mut sessions = lock(sessions);
    let sessions = sessions.as_mut().ok_or(CoreError::NoAccount)?;
    Ok(f(sessions)?)
}

/// Abre e decifra `envelope` e entrega o texto ao assinante de eventos. Sem assinante, falha com
/// [`CoreError::NoEventListener`] antes de tocar no ratchet.
fn receive(
    sessions: &Mutex<Option<CoreSessions>>,
    events: &Mutex<Option<Deliver>>,
    envelope: &protocol::Ciphertext,
    server_timestamp: u64,
) -> Result<(), CoreError> {
    // O assinante fica travado durante a decifragem: não troca entre a checagem e a entrega.
    let events = lock(events);
    let deliver = events.as_ref().ok_or(CoreError::NoEventListener)?;
    let decrypted = with_sessions(sessions, |sessions| {
        block_on(sessions.decrypt(envelope, server_timestamp))
    })?;
    let event = ChatEvent::MessageReceived {
        from: DeviceAddress::from(&decrypted.from),
        body: decrypted.plaintext.to_vec(),
    };
    if deliver(event) {
        Ok(())
    } else {
        Err(CoreError::NoEventListener)
    }
}

/// Confirmar ou não ao servidor um envelope recebido pelo socket. Confirma o que foi entregue e
/// o que nunca vai abrir; segura o que falhou por causa local passageira.
fn disposition(received: Result<(), CoreError>) -> Disposition {
    match received {
        Err(
            CoreError::NoEventListener
            | CoreError::DatabaseBusy
            | CoreError::Storage
            | CoreError::NoAccount
            | CoreError::Internal,
        ) => Disposition::Retain,
        Ok(()) | Err(_) => Disposition::Ack,
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
    use std::sync::mpsc::{self, Receiver};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::protocol::certificate::CertificateIssuer;

    type TestResult = Result<(), Box<dyn Error>>;

    const KEY: [u8; 32] = [0x5A; 32];

    /// Um dia, a validade dos certificados de remetente.
    const DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;

    fn now_millis() -> Result<u64, Box<dyn Error>> {
        Ok(u64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        )?)
    }

    /// Assina os eventos de `core` num canal.
    fn subscribe(core: &FalaaiCore) -> Receiver<ChatEvent> {
        let (sender, events) = mpsc::channel();
        core.subscribe(Box::new(move |event| sender.send(event).is_ok()));
        events
    }

    /// O servidor: trust root, certificados de remetente e os bancos dos aparelhos em `dir`.
    struct Server {
        dir: tempfile::TempDir,
        certificates: CertificateIssuer,
    }

    impl Server {
        fn new() -> Result<Self, Box<dyn Error>> {
            Ok(Self {
                dir: tempfile::tempdir()?,
                certificates: CertificateIssuer::new()?,
            })
        }

        fn open(&self, seed: u8) -> Result<FalaaiCore, CoreError> {
            let path = self.dir.path().join(format!("{seed:02x}.db"));
            FalaaiCore::open(
                path.to_string_lossy().into_owned(),
                KEY.to_vec(),
                self.certificates.trust_root(),
            )
        }

        /// Certificado de remetente de `address` com a identidade `keys`, válido por um dia.
        fn certificate(
            &self,
            address: &DeviceAddress,
            keys: &AccountKeys,
        ) -> Result<Vec<u8>, Box<dyn Error>> {
            let address = Address::try_from(address)?;
            Ok(self
                .certificates
                .issue(&address, &keys.identity_key, now_millis()? + DAY_MILLIS)?)
        }
    }

    /// Um dispositivo: núcleo sobre um banco em arquivo e o stream de eventos assinado.
    struct Device {
        address: DeviceAddress,
        keys: AccountKeys,
        core: FalaaiCore,
        events: Receiver<ChatEvent>,
    }

    impl Device {
        /// Gera as chaves, "registra" (grava o endereço local), entrega o certificado de remetente
        /// e assina os eventos.
        fn register(server: &Server, seed: u8) -> Result<Self, Box<dyn Error>> {
            let core = server.open(seed)?;
            let keys = core.generate_account_keys()?;
            let address = address(seed);
            core.set_local_address(address.clone())?;
            core.set_sender_certificate(server.certificate(&address, &keys)?)?;
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

        fn deliver(&self, envelope: Envelope) -> Result<(), Box<dyn Error>> {
            Ok(self.core.decrypt(envelope, now_millis()?)?)
        }

        fn receive(&self, from: &Device, envelope: Envelope) -> Result<Vec<u8>, Box<dyn Error>> {
            self.deliver(envelope)?;
            match self.events.try_recv()? {
                ChatEvent::MessageReceived { from: sender, body } => {
                    assert_eq!(sender, from.address);
                    Ok(body)
                }
            }
        }
    }

    fn address(seed: u8) -> DeviceAddress {
        DeviceAddress {
            aci: format!("{seed:02x}{seed:02x}{seed:02x}{seed:02x}-0000-4000-8000-000000000000"),
            device_id: 1,
        }
    }

    /// Alice abre sessão com o bundle de Bob.
    fn alice_and_bob(server: &Server) -> Result<(Device, Device), Box<dyn Error>> {
        let alice = Device::register(server, 0xA1)?;
        let bob = Device::register(server, 0xB0)?;
        alice
            .core
            .process_prekey_bundle(bob.address.clone(), bob.bundle()?)?;
        Ok((alice, bob))
    }

    #[test]
    fn dois_nucleos_trocam_mensagens_seladas_pela_api() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;

        let first = alice.send(&bob, b"oi, bob")?;
        assert_eq!(bob.receive(&alice, first)?, b"oi, bob");

        let reply = bob.send(&alice, b"oi, alice")?;
        assert_eq!(alice.receive(&bob, reply)?, b"oi, alice");

        let next = alice.send(&bob, b"tudo bem?")?;
        assert_eq!(bob.receive(&alice, next)?, b"tudo bem?");
        Ok(())
    }

    #[test]
    fn sessao_e_endereco_local_sobrevivem_a_reabrir() -> TestResult {
        let server = Server::new()?;
        let (alice, mut bob) = alice_and_bob(&server)?;
        let first = alice.send(&bob, b"oi, bob")?;

        bob.core = server.open(0xB0)?;
        bob.events = subscribe(&bob.core);
        assert_eq!(bob.receive(&alice, first)?, b"oi, bob");
        Ok(())
    }

    #[test]
    fn certificado_de_remetente_fica_so_em_memoria() -> TestResult {
        let server = Server::new()?;
        let (mut alice, bob) = alice_and_bob(&server)?;
        alice.core = server.open(0xA1)?;
        assert_eq!(alice.send(&bob, b"oi"), Err(CoreError::NoSenderCertificate));
        alice
            .core
            .set_sender_certificate(server.certificate(&alice.address, &alice.keys)?)?;
        assert_eq!(bob.receive(&alice, alice.send(&bob, b"oi")?)?, b"oi");
        Ok(())
    }

    #[test]
    fn repetir_o_endereco_local_mantem_o_certificado() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        alice.core.set_local_address(alice.address.clone())?;
        assert_eq!(bob.receive(&alice, alice.send(&bob, b"oi")?)?, b"oi");
        Ok(())
    }

    #[test]
    fn certificado_de_outro_dispositivo_e_recusado() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        assert_eq!(
            alice
                .core
                .set_sender_certificate(server.certificate(&bob.address, &bob.keys)?),
            Err(CoreError::InvalidSenderCertificate)
        );
        Ok(())
    }

    #[test]
    fn certificado_exige_endereco_local() -> TestResult {
        let server = Server::new()?;
        let core = server.open(0xA1)?;
        let keys = core.generate_account_keys()?;
        assert_eq!(
            core.set_sender_certificate(server.certificate(&address(0xA1), &keys)?),
            Err(CoreError::NoAccount)
        );
        Ok(())
    }

    #[test]
    fn trust_root_malformado_e_recusado() -> TestResult {
        let server = Server::new()?;
        let path = server.dir.path().join("a1.db");
        let mut trust_root = server.certificates.trust_root();
        trust_root.truncate(10);
        assert_eq!(
            FalaaiCore::open(
                path.to_string_lossy().into_owned(),
                KEY.to_vec(),
                trust_root
            )
            .err(),
            Some(CoreError::InvalidKey)
        );
        Ok(())
    }

    #[test]
    fn decifrar_sem_assinante_falha_sem_avancar_o_ratchet() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        let first = alice.send(&bob, b"oi, bob")?;

        let unsubscribed = server.open(0xB0)?;
        assert_eq!(
            unsubscribed.decrypt(first.clone(), now_millis()?),
            Err(CoreError::NoEventListener)
        );
        assert_eq!(bob.receive(&alice, first)?, b"oi, bob");
        Ok(())
    }

    #[test]
    fn decifrar_com_stream_fechado_falha() -> TestResult {
        let server = Server::new()?;
        let (alice, mut bob) = alice_and_bob(&server)?;
        bob.events = mpsc::channel().1;
        let first = alice.send(&bob, b"oi, bob")?;
        assert_eq!(
            bob.core.decrypt(first, now_millis()?),
            Err(CoreError::NoEventListener)
        );
        Ok(())
    }

    #[test]
    fn envelope_repetido_e_recusado() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        bob.receive(&alice, alice.send(&bob, b"oi")?)?;
        let reply = bob.send(&alice, b"oi")?;
        alice.receive(&bob, reply.clone())?;
        assert_eq!(
            alice.core.decrypt(reply, now_millis()?),
            Err(CoreError::DuplicateMessage)
        );
        Ok(())
    }

    #[test]
    fn envelope_de_outro_destinatario_e_recusado() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        let carol = Device::register(&server, 0xC0)?;
        let first = alice.send(&bob, b"oi, bob")?;
        assert!(carol.deliver(first.clone()).is_err());
        assert!(carol.events.try_recv().is_err());
        assert_eq!(bob.receive(&alice, first)?, b"oi, bob");
        Ok(())
    }

    #[test]
    fn cifrar_sem_sessao_falha() -> TestResult {
        let server = Server::new()?;
        let alice = Device::register(&server, 0xA1)?;
        assert_eq!(
            alice.core.encrypt(address(0xB0), b"oi".to_vec()),
            Err(CoreError::SessionNotFound)
        );
        Ok(())
    }

    #[test]
    fn sessoes_exigem_conta_e_endereco_local() -> TestResult {
        let server = Server::new()?;
        let core = server.open(0xA1)?;
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
        let server = Server::new()?;
        let core = server.open(0xA1)?;
        core.generate_account_keys()?;
        assert_eq!(
            core.generate_account_keys().err(),
            Some(CoreError::AccountExists)
        );
        Ok(())
    }

    #[test]
    fn endereco_local_nao_muda_depois_de_gravado() -> TestResult {
        let server = Server::new()?;
        let alice = Device::register(&server, 0xA1)?;
        alice.core.set_local_address(alice.address.clone())?;
        assert_eq!(
            alice.core.set_local_address(address(0xC0)),
            Err(CoreError::AccountExists)
        );
        let reopened = server.open(0xA1)?;
        assert_eq!(
            reopened.set_local_address(address(0xC0)),
            Err(CoreError::AccountExists)
        );
        Ok(())
    }

    #[test]
    fn endereco_invalido_e_recusado() -> TestResult {
        let server = Server::new()?;
        let alice = Device::register(&server, 0xA1)?;
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
        let server = Server::new()?;
        let alice = Device::register(&server, 0xA1)?;
        let bob = Device::register(&server, 0xB0)?;

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
        let server = Server::new()?;
        let path = server.dir.path().join("a1.db");
        let path = path.to_string_lossy().into_owned();
        let trust_root = server.certificates.trust_root();
        drop(FalaaiCore::open(
            path.clone(),
            KEY.to_vec(),
            trust_root.clone(),
        )?);
        assert_eq!(
            FalaaiCore::open(path.clone(), vec![0x5A; 16], trust_root.clone()).err(),
            Some(CoreError::InvalidDatabaseKey)
        );
        assert_eq!(
            FalaaiCore::open(path, vec![0x00; 32], trust_root).err(),
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
            body: b"segredo".to_vec(),
        };
        for debug in [format!("{event:?}"), format!("{envelope:?}")] {
            assert!(!debug.contains(&from.aci), "{debug}");
            assert!(!debug.contains("segredo"), "{debug}");
            assert!(!debug.contains("115, 101"), "{debug}");
        }
    }
}
