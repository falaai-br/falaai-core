//! Superfície exposta ao Flutter via flutter_rust_bridge.
//!
//! Material de chave não cruza esta fronteira: as chaves privadas nascem e ficam no banco local;
//! saem só chaves públicas, envelopes selados e texto já decifrado. O único segredo que cruza é
//! a chave do banco: nasce no Rust ([`generate_db_key`]) e sai uma única vez, na instalação, para
//! a plataforma guardar (Keychain/Keystore); depois só entra, em [`FalaaiCore::open`], e é zerada
//! assim que o banco abre. O Dart apenas repassa esses bytes, sem gerar nem derivar chave.
//!
//! Todo envelope sai selado (sealed sender): o servidor não vê o remetente. Para isso o app
//! entrega o trust root do servidor ao abrir o núcleo e o certificado de remetente emitido pelo
//! `accounts` com [`FalaaiCore::set_sender_certificate`].
//!
//! O transporte também é do núcleo: o app não abre socket nem HTTPS. [`FalaaiCore::connect`]
//! abre o socket autenticado, que recebe, decifra, grava e confirma envelopes em segundo plano;
//! os envios vão pelo socket não autenticado sempre que há a unidentified access key do
//! destinatário (ADR-0010).
//!
//! Para enviar, o app põe a mensagem na outbox com [`FalaaiCore::send_message`], conectado ou
//! não. Enquanto conectado, o núcleo cifra e envia em ordem, tenta de novo com backoff
//! exponencial o que falhou por rede, reenvia logo depois de reconectar e avisa o resultado no
//! stream de eventos. Todo reenvio leva o mesmo `client_message_id`, e o receptor descarta a
//! cópia: nada se perde nem chega duas vezes.
//!
//! Toda mensagem recebida é gravada no banco local na mesma transação que avança o ratchet, por
//! quem a decifrar: o app ou a Notification Service Extension do iOS. O evento só chega ao
//! processo que decifrou; o outro lê o que foi gravado com [`FalaaiCore::received_messages`].
//!
//! Cada conversa tem um código de segurança ([`FalaaiCore::safety_number`]), o fingerprint da
//! libsignal sobre as identidades dos dois lados. A primeira chave de um contato é aceita
//! (TOFU); uma troca é aceita e avisada na mensagem em que chegou (`identity_changed`), e só
//! bloqueia o envio ([`CoreError::UntrustedIdentity`]) em conversa que o usuário marcou como
//! verificada ([`FalaaiCore::set_identity_verified`]), até ele verificar de novo ou aceitar.
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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use flutter_rust_bridge::frb;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::error::CoreError;
use self::types::{
    AccountKeys, ChatEvent, DeviceAddress, Envelope, IdentityStatus, PreKeyBundle, ReceivedMessage,
    SafetyNumber, ServerConfig,
};
use crate::frb_generated::StreamSink;
use crate::messaging::Inbox;
use crate::messaging::outbox::{
    self, Attempt, AttemptFn, BACKOFF, CLIENT_MESSAGE_ID_LEN, Courier, NotifyFn, Outbox, Outcome,
    Rejection,
};
use crate::protocol::access::AccessKey;
use crate::protocol::certificate::TrustRoot;
use crate::protocol::identity;
use crate::protocol::signal::LibsignalSessions;
use crate::protocol::store::{SqliteStore, SqliteStores};
use crate::protocol::{self, Address, Sessions};
use crate::storage::{Database, DatabaseKey};
use crate::transport::{Credentials, Disposition, Incoming, Outgoing, Server, Transport};

/// Gera a chave de 32 bytes do banco local com o CSPRNG do Rust, para a primeira abertura. Não
/// precisa de núcleo aberto. O app guarda os bytes no Keychain/Keystore, sem cópia em outro lugar,
/// e os entrega a cada [`FalaaiCore::open`]; perder a chave é perder o banco.
pub fn generate_db_key() -> Vec<u8> {
    DatabaseKey::generate().to_vec()
}

/// Núcleo aberto sobre o banco local de um dispositivo. No Dart é um handle opaco.
#[frb(opaque)]
pub struct FalaaiCore {
    db: Arc<Database>,
    store: SqliteStore,
    inbox: Inbox,
    outbox: Outbox,
    trust_root: TrustRoot,
    /// Vazio até o endereço local ser conhecido: a libsignal precisa dele nas sessões.
    /// Compartilhado com a thread do socket autenticado, que decifra o que chega.
    sessions: Arc<Mutex<Option<CoreSessions>>>,
    events: Arc<Mutex<Option<Deliver>>>,
    /// Conexão com o servidor, depois de [`Self::connect`].
    transport: Mutex<Option<Arc<Transport>>>,
    /// Thread que esvazia a outbox, enquanto há conexão.
    courier: Mutex<Option<Courier>>,
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
        let inbox = Inbox::new(db.clone());
        let outbox = Outbox::new(db.clone());
        let sessions = store.local_address()?.map(|local| {
            LibsignalSessions::new(local, trust_root.clone(), SqliteStores::new(db.clone()))
        });
        Ok(Self {
            db,
            store,
            inbox,
            outbox,
            trust_root,
            sessions: Arc::new(Mutex::new(sessions)),
            events: Arc::new(Mutex::new(None)),
            transport: Mutex::new(None),
            courier: Mutex::new(None),
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
    /// pede outro quando [`Self::encrypt`] falhar com [`CoreError::NoSenderCertificate`]. Sem
    /// certificado válido a outbox fica parada; o novo a destrava na hora. Falha com
    /// [`CoreError::InvalidSenderCertificate`] se o certificado não encadeia até o trust root, já
    /// venceu ou é de outro dispositivo ou identidade.
    pub fn set_sender_certificate(&self, certificate: Vec<u8>) -> Result<(), CoreError> {
        self.with_sessions(|sessions| block_on(sessions.set_sender_certificate(&certificate)))?;
        self.wake_courier();
        Ok(())
    }

    /// Abre sessão com `peer` a partir do bundle de pré-chaves que ele publicou (PQXDH).
    /// Devolve `true` se a chave de identidade do bundle é outra que não a conhecida para a
    /// conta de `peer`: a troca foi aceita e o app mostra o aviso de código de segurança novo.
    ///
    /// Em conversa verificada ([`Self::set_identity_verified`]), uma chave diferente da
    /// verificada falha com [`CoreError::UntrustedIdentity`] sem abrir sessão; a chave nova fica
    /// registrada, então [`Self::safety_number`] já mostra o código novo e
    /// [`Self::identity_status`] fica [`IdentityStatus::Changed`] até o usuário agir.
    pub fn process_prekey_bundle(
        &self,
        peer: DeviceAddress,
        bundle: PreKeyBundle,
    ) -> Result<bool, CoreError> {
        let peer = Address::try_from(&peer)?;
        let bundle = bundle.to_protocol(&peer)?;
        self.with_sessions(|sessions| block_on(sessions.start_session(&peer, &bundle)))
    }

    /// Código de segurança da conversa com a conta de `peer`, com a chave de identidade
    /// conhecida para ela (a última vista num bundle ou numa mensagem). Os dois aparelhos
    /// mostram os mesmos 60 dígitos; cada um mostra seu QR para o outro ler. Exige a conta
    /// ([`CoreError::NoAccount`]) e alguma chave do contato ([`CoreError::UnknownIdentity`]).
    pub fn safety_number(&self, peer: DeviceAddress) -> Result<SafetyNumber, CoreError> {
        let peer = Address::try_from(&peer)?;
        let local = self.store.local_address()?.ok_or(CoreError::NoAccount)?;
        Ok(identity::safety_number(&self.store, &local, &peer)?.into())
    }

    /// `true` se `scanned_qr`, lido do QR que o aparelho de `peer` mostra, é o código de
    /// segurança desta conversa: as identidades dos dois lados batem. Falha com
    /// [`CoreError::InvalidSafetyNumber`] se o QR não for um código de segurança. Conferir não
    /// marca a conversa como verificada: isso é [`Self::set_identity_verified`].
    pub fn safety_number_matches(
        &self,
        peer: DeviceAddress,
        scanned_qr: Vec<u8>,
    ) -> Result<bool, CoreError> {
        let peer = Address::try_from(&peer)?;
        let local = self.store.local_address()?.ok_or(CoreError::NoAccount)?;
        Ok(identity::safety_number_matches(
            &self.store,
            &local,
            &peer,
            &scanned_qr,
        )?)
    }

    /// Situação da identidade da conta de `peer` frente ao que o usuário verificou.
    pub fn identity_status(&self, peer: DeviceAddress) -> Result<IdentityStatus, CoreError> {
        let peer = Address::try_from(&peer)?;
        Ok(self.store.identity_status(&peer)?.into())
    }

    /// Marca a chave de identidade atual da conta de `peer` como verificada pelo usuário
    /// (`true`), depois de ele conferir o código de segurança; ou desfaz a verificação
    /// (`false`). A verificação vale para aquela chave: se ela mudar, a conversa passa a
    /// [`IdentityStatus::Changed`] e o envio é bloqueado até chamar de novo com `true` (a chave
    /// nova foi conferida) ou `false` (a troca foi aceita sem conferir). Verificar exige alguma
    /// chave do contato ([`CoreError::UnknownIdentity`]).
    pub fn set_identity_verified(
        &self,
        peer: DeviceAddress,
        verified: bool,
    ) -> Result<(), CoreError> {
        let peer = Address::try_from(&peer)?;
        Ok(self.store.set_identity_verified(&peer, verified)?)
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

    /// Abre e decifra um envelope selado, grava a mensagem no banco local e entrega o texto, com o
    /// remetente tirado do certificado, no stream de [`Self::events`] como
    /// [`ChatEvent::MessageReceived`]. `client_message_id` e `server_timestamp` vêm do `Deliver`
    /// (milissegundos desde a época Unix): o certificado de remetente tem de valer nesse instante,
    /// então uma mensagem que esperou na fila ainda abre. `Ok` quer dizer que a mensagem foi
    /// gravada e o evento entregue, e o envelope pode ser confirmado ao servidor.
    ///
    /// Um reenvio de mensagem já gravada (mesmo remetente e mesmo `client_message_id`, que não
    /// pode ser vazio para isso) avança o ratchet, mas não grava nem emite evento: falha com
    /// [`CoreError::DuplicateMessage`], como o mesmo envelope decifrado duas vezes.
    ///
    /// Decifrar, gravar e entregar são atômicos: sem assinante, ou com o stream fechado na
    /// entrega, falha com [`CoreError::NoEventListener`], nada é gravado e o ratchet não avança,
    /// então o mesmo envelope decifra de novo. Enquanto o app ou a extensão de notificação
    /// decifra, o outro processo espera; passado o timeout, falha com [`CoreError::DatabaseBusy`]
    /// e o envelope fica para depois.
    pub fn decrypt(
        &self,
        envelope: Envelope,
        client_message_id: Vec<u8>,
        server_timestamp: u64,
    ) -> Result<(), CoreError> {
        let content = protocol::Ciphertext::from(envelope);
        let incoming = Incoming {
            content: content.body(),
            client_message_id: &client_message_id,
            server_timestamp,
        };
        receive(&self.sessions, &self.inbox, &self.events, incoming)
    }

    /// `true` se outro processo gravou no banco desde a última chamada ou, na primeira, desde a
    /// abertura: a extensão de notificação do iOS decifrou mensagens ou abriu sessões (ou o app,
    /// visto da extensão). O app chama ao voltar ao primeiro plano e ao receber o aviso da
    /// extensão, para recarregar o que mostra (as mensagens com [`Self::received_messages`]); o
    /// aviso entre processos é da plataforma.
    pub fn changed_by_other_process(&self) -> Result<bool, CoreError> {
        Ok(self.db.changed_elsewhere()?)
    }

    /// Até `limit` mensagens recebidas com id maior que `after`, em ordem de id: as que este
    /// processo entregou em [`ChatEvent::MessageReceived`] e as que o outro (a extensão de
    /// notificação) decifrou e gravou. Comece com `after = 0` e passe o id da última lida.
    ///
    /// O id cresce na ordem em que as mensagens foram gravadas por qualquer dos processos, então
    /// o id de um evento não serve de cursor: a extensão pode ter gravado ids menores ainda não
    /// lidos. Mensagens já recebidas por evento voltam aqui; o app deduplica pelo id.
    pub fn received_messages(
        &self,
        after: i64,
        limit: u32,
    ) -> Result<Vec<ReceivedMessage>, CoreError> {
        let messages = self.inbox.after(after, limit)?;
        Ok(messages.into_iter().map(ReceivedMessage::from).collect())
    }

    /// Conecta ao servidor com o token que o `accounts` emitiu no registro deste dispositivo.
    /// Exige o endereço local ([`Self::set_local_address`]).
    ///
    /// Volta logo: o socket autenticado conecta em segundo plano e reconecta sozinho quando cai.
    /// Cada envelope que chega é decifrado, gravado e entregue no stream de [`Self::events`], como
    /// em [`Self::decrypt`], e só então confirmado ao servidor. Um envelope que nunca vai abrir
    /// (adulterado, duplicado, de identidade não confiável) também é confirmado e descartado; um
    /// que falhou por causa local (sem assinante, banco ocupado) fica na fila e volta na próxima
    /// conexão. Conectar de novo troca a conexão anterior.
    ///
    /// Conectado, o núcleo também esvazia a outbox ([`Self::send_message`]) em segundo plano, e
    /// volta a esvaziá-la a cada reconexão.
    pub fn connect(&self, server: ServerConfig, token: String) -> Result<(), CoreError> {
        let token = Zeroizing::new(token);
        let server = Server::new(
            &server.gateway_url,
            &server.accounts_url,
            &server.root_certificates,
        )?;
        let local = self.store.local_address()?.ok_or(CoreError::NoAccount)?;
        let credentials = Credentials::new(local.aci(), local.device_id(), token);
        let (sessions, inbox, events) = (
            self.sessions.clone(),
            self.inbox.clone(),
            self.events.clone(),
        );
        let (wake, signals) = outbox::channel();
        let reconnected = wake.clone();
        let transport = Arc::new(Transport::connect(
            &server,
            credentials,
            move |incoming| disposition(receive(&sessions, &inbox, &events, incoming)),
            move || reconnected.retry(),
        )?);
        let courier = Courier::start(
            self.outbox.clone(),
            (wake, signals),
            BACKOFF,
            attempt(
                self.sessions.clone(),
                self.store.clone(),
                Arc::downgrade(&transport),
            ),
            notify(self.events.clone()),
        )
        .map_err(|_| CoreError::Internal)?;
        // O courier anterior para ao sair de escopo; o transporte anterior fecha depois dele.
        *lock(&self.courier) = Some(courier);
        *lock(&self.transport) = Some(transport);
        Ok(())
    }

    /// Fecha a conexão com o servidor e para a outbox, que guarda o que não foi enviado. Sem
    /// efeito se não houver conexão.
    pub fn disconnect(&self) {
        *lock(&self.courier) = None;
        *lock(&self.transport) = None;
    }

    /// Põe `body` na outbox para `peer` e devolve o `client_message_id` (16 bytes, um UUID) que
    /// a identifica. Funciona sem conexão: a mensagem fica no banco local, sobrevive a fechar o
    /// app e sai quando houver [`Self::connect`].
    ///
    /// Conectado, o núcleo envia as mensagens na ordem em que entraram, cifrando cada tentativa
    /// de novo, como [`Self::encrypt`] e [`Self::send`] fariam. Falha passageira (rede, limite de
    /// taxa, banco ocupado, certificado de remetente vencido) para a fila e tenta de novo com
    /// backoff exponencial, de 1s até 5min; reconectar ou entregar um certificado novo tenta na
    /// hora. O resultado chega no stream de [`Self::events`]: [`ChatEvent::MessageSent`] quando o
    /// servidor gravou na fila do destinatário, [`ChatEvent::MessageFailed`] quando reenviar não
    /// adianta (sem sessão, identidade não confiável, destinatário inexistente, envelope
    /// recusado). Sem assinante, o evento fica guardado e sai quando houver um.
    pub fn send_message(&self, peer: DeviceAddress, body: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let body = Zeroizing::new(body);
        let peer = Address::try_from(&peer)?;
        let client_message_id = self.outbox.push(&peer, &body)?;
        if let Some(courier) = lock(&self.courier).as_ref() {
            courier.wake().pushed();
        }
        Ok(client_message_id.to_vec())
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
        transmit(
            &self.store,
            &*self.transport()?,
            &peer,
            client_message_id,
            envelope.body,
        )
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
        // Resultados da outbox que ficaram sem assinante.
        self.wake_courier();
    }

    /// Faz a outbox tentar já, se há conexão.
    fn wake_courier(&self) {
        if let Some(courier) = lock(&self.courier).as_ref() {
            courier.wake().retry();
        }
    }

    fn with_sessions<T, E>(
        &self,
        f: impl FnOnce(&mut CoreSessions) -> Result<T, E>,
    ) -> Result<T, CoreError>
    where
        CoreError: From<E>,
    {
        with_sessions(&self.sessions, f)
    }

    fn transport(&self) -> Result<Arc<Transport>, CoreError> {
        lock(&self.transport).clone().ok_or(CoreError::NotConnected)
    }
}

/// Uma tentativa da outbox: cifra a mensagem e envia por `transport`, se ele ainda existe.
fn attempt(
    sessions: Arc<Mutex<Option<CoreSessions>>>,
    store: SqliteStore,
    transport: Weak<Transport>,
) -> AttemptFn {
    Box::new(move |pending| {
        let Some(transport) = transport.upgrade() else {
            return Attempt::Retry;
        };
        let sent = with_sessions(&sessions, |sessions| {
            block_on(sessions.encrypt(&pending.to, &pending.body))
        })
        .and_then(|envelope| {
            transmit(
                &store,
                &transport,
                &pending.to,
                pending.client_message_id.to_vec(),
                envelope.body().to_vec(),
            )
        });
        classify(sent)
    })
}

/// Entrega um resultado da outbox no stream de eventos; `false` sem assinante.
fn notify(events: Arc<Mutex<Option<Deliver>>>) -> NotifyFn {
    Box::new(move |client_message_id, outcome| {
        let client_message_id = client_message_id.to_vec();
        let event = match outcome {
            Outcome::Sent => ChatEvent::MessageSent { client_message_id },
            Outcome::Rejected(rejection) => ChatEvent::MessageFailed {
                client_message_id,
                error: CoreError::from(rejection),
            },
        };
        lock(&events).as_ref().is_some_and(|deliver| deliver(event))
    })
}

/// Envia o envelope selado `content` a `peer`: pelo socket não autenticado se há a access key do
/// contato, senão pelo autenticado.
fn transmit(
    store: &SqliteStore,
    transport: &Transport,
    peer: &Address,
    client_message_id: Vec<u8>,
    content: Vec<u8>,
) -> Result<(), CoreError> {
    let destination_aci = Uuid::parse_str(peer.aci())
        .map_err(|_| CoreError::InvalidAddress)?
        .into_bytes();
    let access_key = AccessKey::of(store, peer)?;
    let outgoing = Outgoing {
        destination_aci,
        destination_device_id: peer.device_id(),
        client_message_id,
        content,
    };
    let sent = transport.send(outgoing, access_key.as_ref().map(AccessKey::as_bytes))?;
    CoreError::from_sent(sent)
}

/// Resultado de uma tentativa da outbox. Sai da fila o que foi aceito e o que reenviar igual não
/// resolve; o resto (rede, limite de taxa, certificado vencido, banco ocupado) tenta de novo.
fn classify(sent: Result<(), CoreError>) -> Attempt {
    let rejection = match sent {
        Ok(()) => return Attempt::Done(Outcome::Sent),
        Err(CoreError::InvalidEnvelope | CoreError::InvalidAddress) => Rejection::InvalidEnvelope,
        Err(CoreError::UnknownDestination) => Rejection::UnknownDestination,
        Err(CoreError::SessionNotFound) => Rejection::SessionNotFound,
        Err(CoreError::UntrustedIdentity) => Rejection::UntrustedIdentity,
        Err(_) => return Attempt::Retry,
    };
    Attempt::Done(Outcome::Rejected(rejection))
}

fn with_sessions<T, E>(
    sessions: &Mutex<Option<CoreSessions>>,
    f: impl FnOnce(&mut CoreSessions) -> Result<T, E>,
) -> Result<T, CoreError>
where
    CoreError: From<E>,
{
    let mut sessions = lock(sessions);
    let sessions = sessions.as_mut().ok_or(CoreError::NoAccount)?;
    Ok(f(sessions)?)
}

/// Abre e decifra o envelope, grava a mensagem em `inbox` e entrega o texto ao assinante de
/// eventos, numa transação só: sem assinante, ou com o stream fechado na entrega, falha com
/// [`CoreError::NoEventListener`], nada fica gravado e o ratchet não avança, então o mesmo
/// envelope decifra de novo quando o servidor o reentregar. Um reenvio de mensagem já gravada
/// avança o ratchet sem gravar nem entregar e falha com [`CoreError::DuplicateMessage`].
fn receive(
    sessions: &Mutex<Option<CoreSessions>>,
    inbox: &Inbox,
    events: &Mutex<Option<Deliver>>,
    incoming: Incoming<'_>,
) -> Result<(), CoreError> {
    let envelope = protocol::Ciphertext::new(incoming.content.to_vec());
    let timestamp = incoming.server_timestamp;
    // O assinante fica travado durante a decifragem: não troca entre a checagem e a entrega.
    let events = lock(events);
    let deliver = events.as_ref().ok_or(CoreError::NoEventListener)?;
    let fresh = with_sessions(sessions, |sessions| {
        block_on(sessions.decrypt(&envelope, timestamp, |decrypted| {
            // Roda na thread dona da transação do decrypt: grava junto com o ratchet.
            let Some(id) = inbox.record(
                &decrypted.from,
                incoming.client_message_id,
                timestamp,
                &decrypted.plaintext,
                decrypted.identity_changed,
            )?
            else {
                return Ok(false);
            };
            let event = ChatEvent::MessageReceived {
                id,
                from: DeviceAddress::from(&decrypted.from),
                body: decrypted.plaintext.to_vec(),
                identity_changed: decrypted.identity_changed,
            };
            if deliver(event) {
                Ok(true)
            } else {
                Err(CoreError::NoEventListener)
            }
        }))
    })?;
    if fresh {
        Ok(())
    } else {
        Err(CoreError::DuplicateMessage)
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
            self.open_file(&format!("{seed:02x}.db"))
        }

        fn open_file(&self, file: &str) -> Result<FalaaiCore, CoreError> {
            let path = self.dir.path().join(file);
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
            Self::register_file(server, seed, &format!("{seed:02x}.db"))
        }

        fn register_file(server: &Server, seed: u8, file: &str) -> Result<Self, Box<dyn Error>> {
            let core = server.open_file(file)?;
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

        /// O mesmo aparelho reinstalado sem backup: a mesma conta (mesmo endereço), banco novo
        /// e, portanto, identidade nova. Os contatos veem o código de segurança mudar.
        fn reinstall(&self, server: &Server, seed: u8) -> Result<Self, Box<dyn Error>> {
            Self::register_file(server, seed, &format!("{seed:02x}-reinstalado.db"))
        }

        fn status(&self, peer: &Device) -> Result<IdentityStatus, CoreError> {
            self.core.identity_status(peer.address.clone())
        }

        fn safety_number(&self, peer: &Device) -> Result<SafetyNumber, CoreError> {
            self.core.safety_number(peer.address.clone())
        }

        fn verify(&self, peer: &Device, verified: bool) -> Result<(), CoreError> {
            self.core
                .set_identity_verified(peer.address.clone(), verified)
        }

        /// O mesmo aparelho aberto por outro processo, como a extensão de notificação: outro
        /// núcleo sobre o banco de `seed`, com os eventos assinados.
        fn other_process(&self, server: &Server, seed: u8) -> Result<Self, Box<dyn Error>> {
            let core = server.open(seed)?;
            let events = subscribe(&core);
            Ok(Self {
                address: self.address.clone(),
                keys: self.keys.clone(),
                core,
                events,
            })
        }

        /// O que o servidor entregaria: uma pré-chave EC e uma Kyber descartáveis.
        fn bundle(&self) -> Result<PreKeyBundle, Box<dyn Error>> {
            self.bundle_nth(0)
        }

        /// Bundle com a `index`-ésima pré-chave descartável de cada tipo: as anteriores podem já
        /// ter sido consumidas por um PQXDH recebido.
        fn bundle_nth(&self, index: usize) -> Result<PreKeyBundle, Box<dyn Error>> {
            Ok(PreKeyBundle {
                registration_id: self.keys.registration_id,
                identity_key: self.keys.identity_key.clone(),
                pre_key: self.keys.pre_keys.get(index).cloned(),
                signed_pre_key: self.keys.signed_pre_key.clone(),
                kyber_pre_key: self
                    .keys
                    .kyber_pre_keys
                    .get(index)
                    .cloned()
                    .ok_or("sem kyber")?,
            })
        }

        fn send(&self, to: &Device, text: &[u8]) -> Result<Envelope, CoreError> {
            self.core.encrypt(to.address.clone(), text.to_vec())
        }

        fn deliver(&self, envelope: Envelope) -> Result<(), Box<dyn Error>> {
            Ok(self.core.decrypt(envelope, Vec::new(), now_millis()?)?)
        }

        /// Decifra, confere o remetente e que a mensagem do evento ficou gravada, e devolve o
        /// texto.
        fn receive(&self, from: &Device, envelope: Envelope) -> Result<Vec<u8>, Box<dyn Error>> {
            let (body, identity_changed) = self.receive_noting_identity(from, envelope)?;
            assert!(!identity_changed, "identidade mudou sem o teste esperar");
            Ok(body)
        }

        /// Como [`Self::receive`], devolvendo também se a identidade de `from` mudou nesta
        /// mensagem, no evento e na mensagem gravada.
        fn receive_noting_identity(
            &self,
            from: &Device,
            envelope: Envelope,
        ) -> Result<(Vec<u8>, bool), Box<dyn Error>> {
            self.deliver(envelope)?;
            match self.events.try_recv()? {
                ChatEvent::MessageReceived {
                    id,
                    from: sender,
                    body,
                    identity_changed,
                } => {
                    assert_eq!(sender, from.address);
                    let stored = self.core.received_messages(id - 1, 1)?;
                    let stored = stored.first().ok_or("mensagem não gravada")?;
                    assert_eq!(
                        (stored.id, &stored.body, stored.identity_changed),
                        (id, &body, identity_changed)
                    );
                    Ok((body, identity_changed))
                }
                other => Err(format!("esperava mensagem, veio {other:?}").into()),
            }
        }

        /// Textos gravados no banco, em ordem.
        fn stored(&self) -> Result<Vec<Vec<u8>>, CoreError> {
            let messages = self.core.received_messages(0, u32::MAX)?;
            Ok(messages.into_iter().map(|m| m.body).collect())
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
            unsubscribed.decrypt(first.clone(), Vec::new(), now_millis()?),
            Err(CoreError::NoEventListener)
        );
        assert!(bob.stored()?.is_empty());
        assert_eq!(bob.receive(&alice, first)?, b"oi, bob");
        Ok(())
    }

    #[test]
    fn decifrar_com_stream_fechado_falha_sem_avancar_o_ratchet() -> TestResult {
        let server = Server::new()?;
        let (alice, mut bob) = alice_and_bob(&server)?;
        bob.events = mpsc::channel().1;
        let first = alice.send(&bob, b"oi, bob")?;
        assert_eq!(
            bob.core.decrypt(first.clone(), Vec::new(), now_millis()?),
            Err(CoreError::NoEventListener)
        );
        assert!(bob.stored()?.is_empty(), "gravada sem entrega");
        // O servidor reentrega o envelope não confirmado.
        bob.events = subscribe(&bob.core);
        assert_eq!(bob.receive(&alice, first)?, b"oi, bob");
        assert_eq!(bob.stored()?, [b"oi, bob"]);
        Ok(())
    }

    #[test]
    fn mensagem_decifrada_pela_extensao_fica_gravada_para_o_app() -> TestResult {
        let server = Server::new()?;
        let (alice, app) = alice_and_bob(&server)?;
        let extension = app.other_process(&server, 0xB0)?;
        let first = alice.send(&app, b"oi, bob")?;
        let second = alice.send(&app, b"tudo bem?")?;

        // A extensão decifra com o app em segundo plano: o evento fica nela.
        let sent_at = now_millis()?;
        extension.core.decrypt(first, Vec::new(), sent_at)?;
        assert!(app.events.try_recv().is_err());

        assert!(app.core.changed_by_other_process()?);
        let unread = app.core.received_messages(0, 10)?;
        let [from_extension] = unread.as_slice() else {
            return Err("esperava uma mensagem".into());
        };
        assert_eq!(from_extension.from, alice.address);
        assert_eq!(from_extension.server_timestamp, sent_at);
        assert_eq!(from_extension.body, b"oi, bob");

        assert_eq!(app.receive(&alice, second)?, b"tudo bem?");
        let after = app.core.received_messages(from_extension.id, 10)?;
        assert_eq!(
            after.iter().map(|m| &m.body[..]).collect::<Vec<_>>(),
            [b"tudo bem?"]
        );
        Ok(())
    }

    #[test]
    fn mensagem_que_nao_abre_nao_fica_gravada() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        let first = alice.send(&bob, b"oi, bob")?;
        let mut tampered = first.clone();
        if let Some(last) = tampered.body.last_mut() {
            *last ^= 0x01;
        }
        assert_eq!(
            bob.core.decrypt(tampered, Vec::new(), now_millis()?),
            Err(CoreError::InvalidMessage)
        );
        bob.receive(&alice, first.clone())?;
        assert_eq!(
            bob.core.decrypt(first, Vec::new(), now_millis()?),
            Err(CoreError::DuplicateMessage)
        );
        assert_eq!(bob.stored()?, [b"oi, bob"]);
        Ok(())
    }

    #[test]
    fn app_e_extensao_decifram_sobre_o_mesmo_banco() -> TestResult {
        let server = Server::new()?;
        let (alice, app) = alice_and_bob(&server)?;
        let extension = app.other_process(&server, 0xB0)?;
        let first = alice.send(&app, b"oi, bob")?;
        let second = alice.send(&app, b"tudo bem?")?;
        assert!(!app.core.changed_by_other_process()?);

        // A extensão decifra a notificação; o app decifra a seguinte e recusa a repetida.
        assert_eq!(extension.receive(&alice, first.clone())?, b"oi, bob");
        assert!(app.core.changed_by_other_process()?);
        assert_eq!(app.receive(&alice, second)?, b"tudo bem?");
        assert_eq!(
            app.core.decrypt(first, Vec::new(), now_millis()?),
            Err(CoreError::DuplicateMessage)
        );
        assert!(!app.core.changed_by_other_process()?);
        assert!(extension.core.changed_by_other_process()?);
        Ok(())
    }

    #[test]
    fn reenvio_com_o_mesmo_client_message_id_avanca_o_ratchet_sem_duplicar() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        let id = vec![0x11; 16];
        // A primeira tentativa chegou, mas o SendAck se perdeu: a outbox cifra de novo.
        let first = alice.send(&bob, b"oi, bob")?;
        let resent = alice.send(&bob, b"oi, bob")?;
        assert_ne!(first, resent);

        bob.core.decrypt(first, id.clone(), now_millis()?)?;
        assert!(matches!(
            bob.events.try_recv()?,
            ChatEvent::MessageReceived { .. }
        ));
        assert_eq!(
            bob.core.decrypt(resent.clone(), id.clone(), now_millis()?),
            Err(CoreError::DuplicateMessage)
        );
        assert!(bob.events.try_recv().is_err());
        assert_eq!(bob.stored()?, [b"oi, bob"]);
        // O ratchet avançou com o reenvio: ele não abre de novo, e a conversa segue.
        assert_eq!(
            bob.core.decrypt(resent, Vec::new(), now_millis()?),
            Err(CoreError::DuplicateMessage)
        );
        assert_eq!(
            bob.receive(&alice, alice.send(&bob, b"tudo bem?")?)?,
            b"tudo bem?"
        );
        Ok(())
    }

    #[test]
    fn mesmo_client_message_id_de_outro_remetente_nao_e_reenvio() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        let carol = Device::register(&server, 0xC0)?;
        // As pré-chaves descartáveis do bundle já foram para Alice: só sobra a de último recurso.
        let bundle = PreKeyBundle {
            pre_key: None,
            kyber_pre_key: bob.keys.kyber_last_resort_pre_key.clone(),
            ..bob.bundle()?
        };
        carol
            .core
            .process_prekey_bundle(bob.address.clone(), bundle)?;
        let id = vec![0x11; 16];
        bob.core
            .decrypt(alice.send(&bob, b"de alice")?, id.clone(), now_millis()?)?;
        bob.core
            .decrypt(carol.send(&bob, b"de carol")?, id, now_millis()?)?;
        assert_eq!(bob.stored()?, [&b"de alice"[..], b"de carol"]);
        Ok(())
    }

    #[test]
    fn mensagem_vai_para_a_outbox_sem_conexao_e_sobrevive_a_reabrir() -> TestResult {
        let server = Server::new()?;
        let (mut alice, bob) = alice_and_bob(&server)?;
        let first = alice
            .core
            .send_message(bob.address.clone(), b"um".to_vec())?;
        let second = alice
            .core
            .send_message(bob.address.clone(), b"dois".to_vec())?;
        assert_eq!(first.len(), CLIENT_MESSAGE_ID_LEN);
        assert_ne!(first, second);

        alice.core = server.open(0xA1)?;
        let pending = alice.core.outbox.next()?.ok_or("outbox vazia")?;
        assert_eq!(pending.client_message_id.to_vec(), first);
        assert_eq!(pending.to, Address::try_from(&bob.address)?);
        assert_eq!(pending.body.as_slice(), b"um");
        assert!(alice.events.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn mensagem_para_endereco_invalido_nao_entra_na_outbox() -> TestResult {
        let server = Server::new()?;
        let alice = Device::register(&server, 0xA1)?;
        let peer = DeviceAddress {
            aci: "nao-e-uuid".to_owned(),
            device_id: 1,
        };
        assert_eq!(
            alice.core.send_message(peer, b"oi".to_vec()),
            Err(CoreError::InvalidAddress)
        );
        assert!(alice.core.outbox.next()?.is_none());
        Ok(())
    }

    #[test]
    fn so_recusa_definitiva_tira_a_mensagem_da_outbox() {
        let done = |sent| match classify(sent) {
            Attempt::Done(outcome) => Some(outcome),
            Attempt::Retry => None,
        };
        assert_eq!(done(Ok(())), Some(Outcome::Sent));
        for (error, rejection) in [
            (CoreError::InvalidEnvelope, Rejection::InvalidEnvelope),
            (CoreError::UnknownDestination, Rejection::UnknownDestination),
            (CoreError::SessionNotFound, Rejection::SessionNotFound),
            (CoreError::UntrustedIdentity, Rejection::UntrustedIdentity),
        ] {
            assert_eq!(done(Err(error)), Some(Outcome::Rejected(rejection)));
            assert_eq!(CoreError::from(rejection), error);
        }
        for passing in [
            CoreError::Network,
            CoreError::NotConnected,
            CoreError::RateLimited,
            CoreError::Unauthorized,
            CoreError::NoSenderCertificate,
            CoreError::DatabaseBusy,
            CoreError::Storage,
            CoreError::Internal,
        ] {
            assert_eq!(done(Err(passing)), None, "{passing:?}");
        }
    }

    #[test]
    fn envelope_repetido_e_recusado() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        bob.receive(&alice, alice.send(&bob, b"oi")?)?;
        let reply = bob.send(&alice, b"oi")?;
        alice.receive(&bob, reply.clone())?;
        assert_eq!(
            alice.core.decrypt(reply, Vec::new(), now_millis()?),
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
    fn chave_gerada_tem_32_bytes_e_muda_a_cada_chamada() {
        let (first, second) = (generate_db_key(), generate_db_key());
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 32);
        assert_ne!(first, second);
    }

    #[test]
    fn chave_gerada_abre_e_reabre_o_banco() -> TestResult {
        let server = Server::new()?;
        let path = server.dir.path().join("a1.db");
        let path = path.to_string_lossy().into_owned();
        let trust_root = server.certificates.trust_root();
        let key = generate_db_key();

        FalaaiCore::open(path.clone(), key.clone(), trust_root.clone())?.generate_account_keys()?;

        // A conta gravada na primeira abertura continua lá.
        let reopened = FalaaiCore::open(path.clone(), key, trust_root.clone())?;
        assert_eq!(
            reopened.generate_account_keys().err(),
            Some(CoreError::AccountExists)
        );
        assert_eq!(
            FalaaiCore::open(path, generate_db_key(), trust_root).err(),
            Some(CoreError::WrongDatabaseKey)
        );
        Ok(())
    }

    #[test]
    fn debug_dos_tipos_da_api_omite_aci_e_conteudo() {
        let from = address(0xA1);
        let event = ChatEvent::MessageReceived {
            id: 7,
            from: from.clone(),
            body: b"segredo".to_vec(),
            identity_changed: false,
        };
        let envelope = Envelope {
            body: b"segredo".to_vec(),
        };
        let message = ReceivedMessage {
            id: 7,
            from: from.clone(),
            server_timestamp: 1,
            body: b"segredo".to_vec(),
            identity_changed: true,
        };
        let safety_number = SafetyNumber {
            digits: "segredo".to_owned(),
            qr: b"segredo".to_vec(),
        };
        let sent = ChatEvent::MessageSent {
            client_message_id: vec![0xEE; 16],
        };
        let failed = ChatEvent::MessageFailed {
            client_message_id: vec![0xEE; 16],
            error: CoreError::SessionNotFound,
        };
        for debug in [&sent, &failed].map(|event| format!("{event:?}")) {
            assert!(!debug.contains("238"), "{debug}");
        }
        for debug in [
            format!("{event:?}"),
            format!("{envelope:?}"),
            format!("{message:?}"),
            format!("{safety_number:?}"),
        ] {
            assert!(!debug.contains(&from.aci), "{debug}");
            assert!(!debug.contains("segredo"), "{debug}");
            assert!(!debug.contains("115, 101"), "{debug}");
        }
    }

    #[test]
    fn os_dois_lados_mostram_o_mesmo_codigo_de_seguranca_e_conferem_o_qr() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        // Bob só conhece a identidade de Alice quando a primeira mensagem dela chega.
        assert_eq!(bob.status(&alice)?, IdentityStatus::Unknown);
        assert_eq!(
            bob.safety_number(&alice).err(),
            Some(CoreError::UnknownIdentity)
        );
        assert_eq!(bob.verify(&alice, true), Err(CoreError::UnknownIdentity));
        bob.receive(&alice, alice.send(&bob, b"oi")?)?;

        let (from_alice, from_bob) = (alice.safety_number(&bob)?, bob.safety_number(&alice)?);
        assert_eq!(from_alice.digits, from_bob.digits);
        assert_eq!(from_alice.digits.len(), 60);
        assert!(
            alice
                .core
                .safety_number_matches(bob.address.clone(), from_bob.qr.clone())?
        );
        assert!(
            bob.core
                .safety_number_matches(alice.address.clone(), from_alice.qr.clone())?
        );
        assert!(
            !alice
                .core
                .safety_number_matches(bob.address.clone(), from_alice.qr)?
        );
        assert_eq!(
            alice
                .core
                .safety_number_matches(bob.address.clone(), b"lixo".to_vec()),
            Err(CoreError::InvalidSafetyNumber)
        );
        assert_eq!(alice.status(&bob)?, IdentityStatus::Default);
        Ok(())
    }

    #[test]
    fn codigo_de_seguranca_exige_conta() -> TestResult {
        let server = Server::new()?;
        let core = server.open(0xA1)?;
        assert_eq!(core.safety_number(address(0xB0)), Err(CoreError::NoAccount));
        assert_eq!(
            core.safety_number_matches(address(0xB0), Vec::new()),
            Err(CoreError::NoAccount)
        );
        Ok(())
    }

    #[test]
    fn troca_de_identidade_sem_verificacao_e_aceita_e_avisada_na_mensagem() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        bob.receive(&alice, alice.send(&bob, b"oi")?)?;
        let before = alice.safety_number(&bob)?;

        // Bob reinstala sem backup e escreve para Alice com a identidade nova.
        let bob = bob.reinstall(&server, 0xB0)?;
        assert!(
            !bob.core
                .process_prekey_bundle(alice.address.clone(), alice.bundle()?)?
        );
        let (body, identity_changed) =
            alice.receive_noting_identity(&bob, bob.send(&alice, b"voltei")?)?;
        assert_eq!(body, b"voltei");
        assert!(identity_changed);
        assert_eq!(alice.status(&bob)?, IdentityStatus::Default);
        let after = alice.safety_number(&bob)?;
        assert_ne!(after.digits, before.digits);
        assert_eq!(after.digits, bob.safety_number(&alice)?.digits);

        // Só a mensagem da troca leva o aviso; e Alice responde sem bloqueio.
        assert_eq!(
            alice.receive(&bob, bob.send(&alice, b"tudo bem?")?)?,
            b"tudo bem?"
        );
        assert_eq!(
            bob.receive(&alice, alice.send(&bob, b"oi de novo")?)?,
            b"oi de novo"
        );
        let flags: Vec<bool> = alice
            .core
            .received_messages(0, 10)?
            .iter()
            .map(|m| m.identity_changed)
            .collect();
        assert_eq!(flags, [true, false]);
        Ok(())
    }

    #[test]
    fn conversa_verificada_recebe_a_troca_mas_bloqueia_o_envio_ate_o_usuario_agir() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        bob.receive(&alice, alice.send(&bob, b"oi")?)?;
        alice.verify(&bob, true)?;
        assert_eq!(alice.status(&bob)?, IdentityStatus::Verified);
        assert_eq!(
            bob.receive(&alice, alice.send(&bob, b"verificado")?)?,
            b"verificado"
        );

        let bob = bob.reinstall(&server, 0xB0)?;
        bob.core
            .process_prekey_bundle(alice.address.clone(), alice.bundle()?)?;
        let (_, identity_changed) =
            alice.receive_noting_identity(&bob, bob.send(&alice, b"voltei")?)?;
        assert!(identity_changed);
        assert_eq!(alice.status(&bob)?, IdentityStatus::Changed);
        assert_eq!(
            alice.send(&bob, b"bloqueada"),
            Err(CoreError::UntrustedIdentity)
        );
        // Receber segue aberto enquanto o envio está bloqueado.
        assert_eq!(
            alice.receive(&bob, bob.send(&alice, b"ainda aqui")?)?,
            b"ainda aqui"
        );

        // Aceitar a troca sem conferir volta ao padrão e libera o envio.
        alice.verify(&bob, false)?;
        assert_eq!(alice.status(&bob)?, IdentityStatus::Default);
        assert_eq!(
            bob.receive(&alice, alice.send(&bob, b"liberada")?)?,
            b"liberada"
        );

        // Conferir o código novo e verificar de novo também libera, e volta a proteger.
        alice.verify(&bob, true)?;
        assert_eq!(alice.status(&bob)?, IdentityStatus::Verified);
        assert_eq!(
            bob.receive(&alice, alice.send(&bob, b"verificada")?)?,
            b"verificada"
        );
        Ok(())
    }

    #[test]
    fn bundle_com_identidade_nova_em_conversa_verificada_nao_abre_sessao_e_mostra_o_codigo_novo()
    -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        bob.receive(&alice, alice.send(&bob, b"oi")?)?;
        alice.verify(&bob, true)?;

        // O Bob reinstalado conhece a identidade de Alice pelo bundle dela, sem lhe escrever.
        let bob = bob.reinstall(&server, 0xB0)?;
        assert!(
            !bob.core
                .process_prekey_bundle(alice.address.clone(), alice.bundle()?)?
        );
        assert_eq!(
            alice
                .core
                .process_prekey_bundle(bob.address.clone(), bob.bundle()?),
            Err(CoreError::UntrustedIdentity)
        );
        assert_eq!(alice.status(&bob)?, IdentityStatus::Changed);
        // A identidade nova ficou registrada, sem confiança: o código já é o novo, e Bob ainda
        // não tem sessão com Alice.
        assert_eq!(
            alice.safety_number(&bob)?.digits,
            bob.safety_number(&alice)?.digits
        );
        assert_eq!(alice.send(&bob, b"oi"), Err(CoreError::UntrustedIdentity));

        // Conferido o código, a sessão abre com a chave já conhecida (sem nova troca).
        alice.verify(&bob, true)?;
        assert!(
            !alice
                .core
                .process_prekey_bundle(bob.address.clone(), bob.bundle()?)?
        );
        assert_eq!(
            bob.receive(&alice, alice.send(&bob, b"agora sim")?)?,
            b"agora sim"
        );
        Ok(())
    }

    #[test]
    fn bundle_com_identidade_nova_sem_verificacao_abre_sessao_e_avisa() -> TestResult {
        let server = Server::new()?;
        let (alice, bob) = alice_and_bob(&server)?;
        bob.receive(&alice, alice.send(&bob, b"oi")?)?;
        assert_eq!(alice.status(&bob)?, IdentityStatus::Default);

        let bob = bob.reinstall(&server, 0xB0)?;
        assert!(
            alice
                .core
                .process_prekey_bundle(bob.address.clone(), bob.bundle()?)?
        );
        assert_eq!(alice.status(&bob)?, IdentityStatus::Default);
        assert_eq!(
            bob.receive(&alice, alice.send(&bob, b"oi de novo")?)?,
            b"oi de novo"
        );
        Ok(())
    }

    #[test]
    fn aviso_de_troca_decifrado_pela_extensao_fica_gravado_para_o_app() -> TestResult {
        let server = Server::new()?;
        let (alice, app) = alice_and_bob(&server)?;
        app.receive(&alice, alice.send(&app, b"oi")?)?;
        let extension = app.other_process(&server, 0xB0)?;

        let alice = alice.reinstall(&server, 0xA1)?;
        alice
            .core
            .process_prekey_bundle(app.address.clone(), app.bundle_nth(1)?)?;
        let (_, identity_changed) =
            extension.receive_noting_identity(&alice, alice.send(&app, b"voltei")?)?;
        assert!(identity_changed);

        assert!(app.core.changed_by_other_process()?);
        let stored = app.core.received_messages(0, 10)?;
        let [first, from_extension] = stored.as_slice() else {
            return Err("esperava duas mensagens".into());
        };
        assert!(!first.identity_changed);
        assert!(from_extension.identity_changed);
        assert_eq!(from_extension.body, b"voltei");
        assert_eq!(app.status(&alice)?, IdentityStatus::Default);
        Ok(())
    }
}
