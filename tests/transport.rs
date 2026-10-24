//! Transporte de ponta a ponta: dois cores falando com um gateway e um `accounts` de teste no
//! loopback, só pela API pública.
//!
//! O gateway de teste segue o contrato do falaai-proto@4ade11f: `/v1/ws` autenticado por
//! `Authorization: Basic aci.device:token`, `/v1/ws/unidentified` sem credencial, `Send` aceito
//! no não autenticado só com a unidentified access key que o destinatário registrou. Ele guarda
//! cada frame `Send` como chegou, para o teste exigido pelo fla-0wu: nenhum carrega o ACI do
//! remetente fora do conteúdo selado.

mod common;

use std::error::Error;
use std::time::Duration;

use common::{Device, TestResult, accounts, now_millis};
use falaai_core::api::error::CoreError;
use falaai_core::api::test_support::unidentified_access_key;
use falaai_core::api::types::{ChatEvent, DeviceAddress, ServerConfig};
use uuid::Uuid;

use self::fake::{Fault, Gateway, Socket};

/// Quanto o teste espera por algo que acontece em segundo plano.
const WAIT: Duration = Duration::from_secs(10);

const ALICE: u8 = 0xA1;
const BOB: u8 = 0xB0;

const BOB_PROFILE_KEY: [u8; 32] = [0x42; 32];

/// Alice e Bob registrados no servidor de teste, conectados, com sessão aberta de Alice para
/// Bob. Bob registrou a access key da profile key dele.
struct World {
    _dir: tempfile::TempDir,
    server: Gateway,
    alice: Device,
    bob: Device,
}

impl World {
    fn new() -> Result<Self, Box<dyn Error>> {
        let dir = tempfile::tempdir()?;
        let server = Gateway::start()?;
        let alice = Device::register(dir.path(), ALICE)?;
        let mut bob = Device::register(dir.path(), BOB)?;
        for device in [&alice, &bob] {
            server.register(device, token(device))?;
            device.core().connect(server.config(), token(device))?;
        }
        server.register_access_key(&bob, unidentified_access_key(&BOB_PROFILE_KEY))?;
        server.wait_connected(&alice)?;
        server.wait_connected(&bob)?;
        alice.start_session(&mut bob)?;
        Ok(Self {
            _dir: dir,
            server,
            alice,
            bob,
        })
    }

    /// Alice cifra e envia `text` a Bob; devolve o `client_message_id`.
    fn alice_sends(&self, text: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let envelope = self.alice.send(&self.bob, text)?;
        let id = rand::random::<[u8; 16]>().to_vec();
        self.alice
            .core()
            .send(self.bob.address.clone(), id.clone(), envelope)?;
        Ok(id)
    }

    /// Bob recebe `text` de Alice pelo socket autenticado.
    fn bob_receives(&self, text: &[u8]) -> TestResult {
        let (from, body) = self.bob.next_message(WAIT)?;
        assert_eq!(from, self.alice.address);
        assert_eq!(body, text);
        Ok(())
    }

    /// Alice põe `text` para Bob na outbox; devolve o `client_message_id`.
    fn alice_posts(&self, text: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.alice
            .core()
            .send_message(self.bob.address.clone(), text.to_vec())
    }

    /// O próximo evento de Alice diz que o servidor aceitou a mensagem `id`.
    fn alice_hears_sent(&self, id: &[u8]) -> TestResult {
        match self.alice.next_event(WAIT)? {
            ChatEvent::MessageSent { client_message_id } => {
                assert_eq!(client_message_id, id);
                Ok(())
            }
            other => Err(format!("esperava MessageSent, veio {other:?}").into()),
        }
    }

    /// Bob não recebe mais nada por um tempo.
    fn bob_hears_nothing_more(&self) -> TestResult {
        std::thread::sleep(Duration::from_millis(500));
        assert!(self.bob.no_events(), "Bob recebeu uma cópia");
        Ok(())
    }
}

fn token(device: &Device) -> String {
    format!("token-{}", device.address.aci)
}

fn aci_bytes(device: &Device) -> Result<[u8; 16], Box<dyn Error>> {
    Ok(Uuid::parse_str(&device.address.aci)?.into_bytes())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// `frame` sem a primeira ocorrência de `part`.
fn without(frame: &[u8], part: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let start = frame
        .windows(part.len())
        .position(|window| window == part)
        .ok_or("conteúdo fora do frame")?;
    Ok([&frame[..start], &frame[start + part.len()..]].concat())
}

/// Nenhum `Send` carrega o ACI do remetente (binário ou texto) fora do conteúdo selado, nem
/// dentro dele: o selo esconde o remetente.
fn assert_no_sender(server: &Gateway, sender: &Device) -> TestResult {
    let sender_aci = aci_bytes(sender)?;
    let sends = server.sends();
    assert!(!sends.is_empty());
    for send in sends {
        let outside_seal = without(&send.frame, &send.content)?;
        for frame in [&outside_seal, &send.frame] {
            assert!(!contains(frame, &sender_aci), "{:?}", send.socket);
            assert!(
                !contains(frame, sender.address.aci.as_bytes()),
                "{:?}",
                send.socket
            );
        }
    }
    Ok(())
}

#[test]
fn com_profile_key_envia_pelo_socket_nao_autenticado_sem_o_remetente() -> TestResult {
    let world = World::new()?;
    world
        .alice
        .core()
        .set_peer_profile_key(&world.bob.address, &BOB_PROFILE_KEY)?;

    let id = world.alice_sends(b"oi, bob")?;
    world.bob_receives(b"oi, bob")?;

    let sends = world.server.sends();
    assert_eq!(sends.len(), 1);
    let send = sends.first().ok_or("sem send")?;
    assert_eq!(send.socket, Socket::Unidentified);
    assert_eq!(send.client_message_id, id);
    assert_eq!(send.destination_aci, aci_bytes(&world.bob)?);
    assert_eq!(send.access_key, unidentified_access_key(&BOB_PROFILE_KEY));
    assert_no_sender(&world.server, &world.alice)?;

    // O handshake do socket não autenticado não leva credencial nem nada da conta.
    let handshakes = world.server.unidentified_handshakes();
    assert!(!handshakes.is_empty());
    for headers in handshakes {
        for (name, value) in headers {
            assert!(!name.eq_ignore_ascii_case("authorization"), "{name}");
            assert!(!value.contains(&world.alice.address.aci), "{name}");
        }
    }

    world.server.wait_acked(1)?;
    Ok(())
}

#[test]
fn sem_profile_key_cai_para_o_socket_autenticado() -> TestResult {
    let world = World::new()?;

    world.alice_sends(b"primeiro contato")?;
    world.bob_receives(b"primeiro contato")?;

    let sends = world.server.sends();
    assert_eq!(sends.len(), 1);
    let send = sends.first().ok_or("sem send")?;
    assert_eq!(send.socket, Socket::Authenticated);
    assert!(send.access_key.is_empty());
    assert_no_sender(&world.server, &world.alice)?;
    Ok(())
}

#[test]
fn access_key_recusada_cai_para_o_socket_autenticado() -> TestResult {
    let world = World::new()?;
    world
        .alice
        .core()
        .set_peer_profile_key(&world.bob.address, &[0x07; 32])?;

    world.alice_sends(b"profile key velha")?;
    world.bob_receives(b"profile key velha")?;

    let sockets = world
        .server
        .sends()
        .iter()
        .map(|send| (send.socket, send.access_key.is_empty()))
        .collect::<Vec<_>>();
    assert_eq!(
        sockets,
        [(Socket::Unidentified, false), (Socket::Authenticated, true)]
    );
    assert_no_sender(&world.server, &world.alice)?;
    Ok(())
}

#[test]
fn conversa_nos_dois_sentidos_confirma_cada_entrega() -> TestResult {
    let world = World::new()?;
    world
        .alice
        .core()
        .set_peer_profile_key(&world.bob.address, &BOB_PROFILE_KEY)?;

    world.alice_sends(b"oi, bob")?;
    world.bob_receives(b"oi, bob")?;

    // Bob responde sem a profile key de Alice: vai pelo autenticado.
    let reply = world.bob.send(&world.alice, b"oi, alice")?;
    world.bob.core().send(
        world.alice.address.clone(),
        rand::random::<[u8; 16]>().to_vec(),
        reply,
    )?;
    let (from, body) = world.alice.next_message(WAIT)?;
    assert_eq!(from, world.bob.address);
    assert_eq!(body, b"oi, alice");

    world.server.wait_acked(2)?;
    Ok(())
}

#[test]
fn entrega_sem_assinante_nao_e_confirmada_e_volta_na_proxima_conexao() -> TestResult {
    let mut world = World::new()?;
    // O app reabriu o núcleo e conectou antes de assinar os eventos.
    world.bob.reopen_without_events()?;
    world
        .bob
        .core()
        .connect(world.server.config(), token(&world.bob))?;
    world.server.wait_connected(&world.bob)?;

    world.alice_sends(b"segura")?;
    world.server.wait_delivered(1)?;
    std::thread::sleep(Duration::from_millis(500));
    assert!(world.server.acked().is_empty());

    // Assina e conecta de novo: o servidor entrega o que ficou sem Ack.
    world.bob.subscribe();
    world
        .bob
        .core()
        .connect(world.server.config(), token(&world.bob))?;
    world.bob_receives(b"segura")?;
    world.server.wait_acked(1)?;
    Ok(())
}

#[test]
fn entrega_com_stream_fechado_nao_avanca_o_ratchet_e_a_reentrega_abre() -> TestResult {
    let mut world = World::new()?;
    world.bob.close_events();

    world.alice_sends(b"segura")?;
    world.server.wait_delivered(1)?;
    std::thread::sleep(Duration::from_millis(500));
    assert!(world.server.acked().is_empty());

    // Com o ratchet avançado, a reentrega daria DuplicateMessage e seria confirmada e perdida.
    world.bob.subscribe();
    world
        .bob
        .core()
        .connect(world.server.config(), token(&world.bob))?;
    world.bob_receives(b"segura")?;
    world.server.wait_acked(1)?;
    Ok(())
}

#[test]
fn outbox_envia_e_avisa_que_o_servidor_aceitou() -> TestResult {
    let world = World::new()?;
    world
        .alice
        .core()
        .set_peer_profile_key(&world.bob.address, &BOB_PROFILE_KEY)?;

    let id = world.alice_posts(b"oi, bob")?;
    assert_eq!(id.len(), 16);
    world.bob_receives(b"oi, bob")?;
    world.alice_hears_sent(&id)?;

    let sends = world.server.sends();
    let [send] = sends.as_slice() else {
        return Err(format!("{} sends", sends.len()).into());
    };
    assert_eq!(send.socket, Socket::Unidentified);
    assert_eq!(send.client_message_id, id);
    assert_no_sender(&world.server, &world.alice)?;
    Ok(())
}

#[test]
fn outbox_envia_na_ordem_em_que_as_mensagens_entraram() -> TestResult {
    let world = World::new()?;
    let texts: [&[u8]; 3] = [b"um", b"dois", b"tres"];
    let ids = texts
        .iter()
        .map(|text| world.alice_posts(text))
        .collect::<Result<Vec<_>, _>>()?;
    for text in texts {
        world.bob_receives(text)?;
    }
    for id in &ids {
        world.alice_hears_sent(id)?;
    }
    let sent: Vec<Vec<u8>> = world
        .server
        .sends()
        .into_iter()
        .map(|send| send.client_message_id)
        .collect();
    assert_eq!(sent, ids);
    Ok(())
}

#[test]
fn sendack_perdido_reenvia_com_o_mesmo_id_e_o_receptor_descarta_a_copia() -> TestResult {
    let world = World::new()?;
    world
        .alice
        .core()
        .set_peer_profile_key(&world.bob.address, &BOB_PROFILE_KEY)?;
    // O servidor grava na fila de Bob, mas Alice não vê o aceite e tenta de novo.
    world.server.inject(Fault::AcceptButRateLimit);

    let id = world.alice_posts(b"so uma vez")?;
    world.bob_receives(b"so uma vez")?;
    world.alice_hears_sent(&id)?;

    let sends = world.server.sends();
    assert_eq!(sends.len(), 2);
    assert!(sends.iter().all(|send| send.client_message_id == id));
    // Cada tentativa cifra de novo: o ratchet sozinho não reconheceria a cópia.
    assert_ne!(sends[0].content, sends[1].content);
    // As duas entregas são confirmadas, e a cópia não vira mensagem.
    world.server.wait_acked(2)?;
    world.bob_hears_nothing_more()?;
    assert_eq!(world.bob.core().received_messages(0, 10)?.len(), 1);

    // A conversa segue.
    let next = world.alice_posts(b"e a proxima")?;
    world.bob_receives(b"e a proxima")?;
    world.alice_hears_sent(&next)?;
    Ok(())
}

#[test]
fn conexao_caida_no_envio_reenvia_depois_de_reconectar() -> TestResult {
    let world = World::new()?;
    // Sem a profile key de Bob, o envio vai pelo socket autenticado, que cai no `Send`.
    world.server.inject(Fault::Drop);

    let id = world.alice_posts(b"depois da queda")?;
    world.bob_receives(b"depois da queda")?;
    world.alice_hears_sent(&id)?;

    let sends = world.server.sends();
    assert_eq!(sends.len(), 2);
    assert!(
        sends
            .iter()
            .all(|send| send.socket == Socket::Authenticated)
    );
    assert!(sends.iter().all(|send| send.client_message_id == id));
    world.bob_hears_nothing_more()?;
    Ok(())
}

#[test]
fn mensagem_posta_sem_conexao_sai_ao_conectar_mesmo_depois_de_reabrir() -> TestResult {
    let mut world = World::new()?;
    world.alice.core().disconnect();
    let first = world.alice_posts(b"offline 1")?;
    let second = world.alice_posts(b"offline 2")?;
    std::thread::sleep(Duration::from_millis(200));
    assert!(world.server.sends().is_empty());

    // O app foi fechado e aberto de novo.
    world.alice.reopen()?;
    world
        .alice
        .core()
        .connect(world.server.config(), token(&world.alice))?;
    world.bob_receives(b"offline 1")?;
    world.bob_receives(b"offline 2")?;
    world.alice_hears_sent(&first)?;
    world.alice_hears_sent(&second)?;
    Ok(())
}

#[test]
fn sem_sessao_a_mensagem_falha_e_sai_da_outbox() -> TestResult {
    let world = World::new()?;
    let stranger = DeviceAddress {
        aci: common::aci(0xC0),
        device_id: 1,
    };
    let id = world
        .alice
        .core()
        .send_message(stranger, b"para quem?".to_vec())?;
    match world.alice.next_event(WAIT)? {
        ChatEvent::MessageFailed {
            client_message_id,
            error,
        } => {
            assert_eq!(client_message_id, id);
            assert_eq!(error, CoreError::SessionNotFound);
        }
        other => return Err(format!("esperava MessageFailed, veio {other:?}").into()),
    }
    assert!(world.server.sends().is_empty());

    // A recusa não para a fila: a próxima mensagem sai.
    let next = world.alice_posts(b"oi, bob")?;
    world.bob_receives(b"oi, bob")?;
    world.alice_hears_sent(&next)?;
    Ok(())
}

#[test]
fn resultado_sem_assinante_chega_quando_alguem_assina() -> TestResult {
    let mut world = World::new()?;
    world.alice.close_events();

    let id = world.alice_posts(b"oi, bob")?;
    world.bob_receives(b"oi, bob")?;
    std::thread::sleep(Duration::from_millis(200));

    world.alice.subscribe();
    world.alice_hears_sent(&id)?;
    assert_eq!(world.server.sends().len(), 1);
    Ok(())
}

#[test]
fn certificado_de_remetente_vem_do_accounts() -> TestResult {
    let world = World::new()?;
    let certificate = world.alice.core().fetch_sender_certificate()?;
    assert_eq!(certificate, world.server.certificate_of(&world.alice)?);
    world.alice.core().set_sender_certificate(certificate)?;
    Ok(())
}

#[test]
fn token_recusado_pelo_accounts() -> TestResult {
    let world = World::new()?;
    world
        .alice
        .core()
        .connect(world.server.config(), "token-errado".to_owned())?;
    assert_eq!(
        world.alice.core().fetch_sender_certificate(),
        Err(CoreError::Unauthorized)
    );
    Ok(())
}

#[test]
fn sem_connect_nao_envia_nem_busca_certificado() -> TestResult {
    let dir = tempfile::tempdir()?;
    let alice = Device::register(dir.path(), ALICE)?;
    let mut bob = Device::register(dir.path(), BOB)?;
    alice.start_session(&mut bob)?;
    let envelope = alice.send(&bob, b"oi")?;
    assert_eq!(
        alice
            .core()
            .send(bob.address.clone(), vec![0; 16], envelope),
        Err(CoreError::NotConnected)
    );
    assert_eq!(
        alice.core().fetch_sender_certificate(),
        Err(CoreError::NotConnected)
    );
    Ok(())
}

#[test]
fn client_message_id_precisa_de_16_bytes() -> TestResult {
    let world = World::new()?;
    let envelope = world.alice.send(&world.bob, b"oi")?;
    assert_eq!(
        world
            .alice
            .core()
            .send(world.bob.address.clone(), vec![0; 15], envelope),
        Err(CoreError::InvalidEnvelope)
    );
    Ok(())
}

#[test]
fn configuracao_sem_tls_fora_do_loopback_e_recusada() -> TestResult {
    let dir = tempfile::tempdir()?;
    let alice = Device::register(dir.path(), ALICE)?;
    let config = ServerConfig {
        gateway_url: "ws://gw.falaai.com.br".to_owned(),
        accounts_url: "https://api.falaai.com.br".to_owned(),
        root_certificates: Vec::new(),
    };
    assert_eq!(
        alice.core().connect(config, "t".to_owned()),
        Err(CoreError::InvalidServerConfig)
    );
    Ok(())
}

/// Gateway e `accounts` de teste.
mod fake {
    use std::collections::{HashMap, VecDeque};
    use std::error::Error;
    use std::io::{ErrorKind, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{self, Sender};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::thread;
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use falaai_core::api::types::ServerConfig;
    use prost::Message as _;
    use tungstenite::handshake::server::{ErrorResponse, Request, Response};
    use tungstenite::http::{StatusCode, header};
    use tungstenite::{Message, WebSocket};
    use uuid::Uuid;

    use super::{Device, WAIT, accounts, now_millis};

    /// Espelho de `websocket.proto`, escrito à parte do core para conferir o formato.
    mod proto {
        #[derive(Clone, PartialEq, prost::Message)]
        pub struct Envelope {
            #[prost(int32, tag = "1")]
            pub r#type: i32,
            #[prost(bytes = "vec", tag = "2")]
            pub client_message_id: Vec<u8>,
            #[prost(bytes = "vec", tag = "3")]
            pub content: Vec<u8>,
        }

        #[derive(Clone, PartialEq, prost::Message)]
        pub struct Frame {
            #[prost(oneof = "Payload", tags = "1, 2, 3, 4, 5, 6")]
            pub payload: Option<Payload>,
        }

        #[derive(Clone, PartialEq, prost::Oneof)]
        pub enum Payload {
            #[prost(message, tag = "1")]
            Send(Send),
            #[prost(message, tag = "2")]
            SendAck(SendAck),
            #[prost(message, tag = "3")]
            Deliver(Deliver),
            #[prost(message, tag = "4")]
            Ack(Ack),
            #[prost(message, tag = "5")]
            Ping(Ping),
            #[prost(message, tag = "6")]
            Pong(Ping),
        }

        #[derive(Clone, PartialEq, prost::Message)]
        pub struct Send {
            #[prost(bytes = "vec", tag = "1")]
            pub destination_aci: Vec<u8>,
            #[prost(uint32, tag = "2")]
            pub destination_device_id: u32,
            #[prost(message, optional, tag = "3")]
            pub envelope: Option<Envelope>,
            #[prost(bytes = "vec", tag = "4")]
            pub unidentified_access_key: Vec<u8>,
        }

        #[derive(Clone, PartialEq, prost::Message)]
        pub struct SendAck {
            #[prost(bytes = "vec", tag = "1")]
            pub client_message_id: Vec<u8>,
            #[prost(int32, tag = "2")]
            pub status: i32,
        }

        pub const ACCEPTED: i32 = 1;
        pub const RATE_LIMITED: i32 = 4;
        pub const UNAUTHORIZED: i32 = 5;

        #[derive(Clone, PartialEq, prost::Message)]
        pub struct Deliver {
            #[prost(uint64, tag = "1")]
            pub seq: u64,
            #[prost(uint64, tag = "2")]
            pub server_timestamp: u64,
            #[prost(message, optional, tag = "3")]
            pub envelope: Option<Envelope>,
        }

        #[derive(Clone, PartialEq, prost::Message)]
        pub struct Ack {
            #[prost(uint64, tag = "1")]
            pub seq: u64,
        }

        #[derive(Clone, PartialEq, prost::Message)]
        pub struct Ping {
            #[prost(uint64, tag = "1")]
            pub id: u64,
        }
    }

    /// Falha que o servidor aplica ao próximo `Send`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Fault {
        /// Grava na fila do destinatário, mas responde `RATE_LIMITED`: para quem envia, é como
        /// se o `SendAck` se perdesse.
        AcceptButRateLimit,
        /// Derruba a conexão sem gravar nada.
        Drop,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Socket {
        Authenticated,
        Unidentified,
    }

    /// Um frame `Send` como chegou, e os campos dele.
    #[derive(Clone)]
    pub struct CapturedSend {
        pub socket: Socket,
        pub frame: Vec<u8>,
        pub destination_aci: [u8; 16],
        pub access_key: Vec<u8>,
        pub client_message_id: Vec<u8>,
        pub content: Vec<u8>,
    }

    /// Dispositivo: ACI em 16 bytes e device id.
    type DeviceKey = ([u8; 16], u32);

    #[derive(Default)]
    struct State {
        /// `aci.device` → token.
        tokens: HashMap<String, String>,
        /// `aci.device` → certificado de remetente que o `accounts` entrega.
        certificates: HashMap<String, Vec<u8>>,
        access_keys: HashMap<[u8; 16], Vec<u8>>,
        /// Conexão autenticada atual de cada dispositivo, com um id para a anterior, ao cair, não
        /// remover a nova.
        connected: HashMap<DeviceKey, (u64, Sender<Vec<u8>>)>,
        next_connection: u64,
        /// `Deliver` sem `Ack` de cada dispositivo, por `seq`; vão de novo a cada conexão.
        unacked: HashMap<DeviceKey, Vec<(u64, Vec<u8>)>>,
        delivered: usize,
        next_seq: u64,
        sends: Vec<CapturedSend>,
        acked: Vec<u64>,
        unidentified_handshakes: Vec<Vec<(String, String)>>,
        faults: VecDeque<Fault>,
    }

    pub struct Gateway {
        gateway_url: String,
        accounts_url: String,
        state: Arc<Mutex<State>>,
    }

    fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
        state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn username(device: &Device) -> String {
        format!("{}.{}", device.address.aci, device.address.device_id)
    }

    fn device_key(device: &Device) -> Result<DeviceKey, Box<dyn Error>> {
        Ok((
            Uuid::parse_str(&device.address.aci)?.into_bytes(),
            device.address.device_id.into(),
        ))
    }

    impl Gateway {
        pub fn start() -> Result<Self, Box<dyn Error>> {
            let state = Arc::new(Mutex::new(State::default()));
            let gateway = TcpListener::bind("127.0.0.1:0")?;
            let accounts = TcpListener::bind("127.0.0.1:0")?;
            let gateway_url = format!("ws://{}", gateway.local_addr()?);
            let accounts_url = format!("http://{}", accounts.local_addr()?);
            let shared = state.clone();
            thread::spawn(move || {
                for stream in gateway.incoming().flatten() {
                    let state = shared.clone();
                    thread::spawn(move || {
                        let _ = websocket(stream, &state);
                    });
                }
            });
            let shared = state.clone();
            thread::spawn(move || {
                for stream in accounts.incoming().flatten() {
                    let _ = http(stream, &shared);
                }
            });
            Ok(Self {
                gateway_url,
                accounts_url,
                state,
            })
        }

        pub fn config(&self) -> ServerConfig {
            ServerConfig {
                gateway_url: self.gateway_url.clone(),
                accounts_url: self.accounts_url.clone(),
                root_certificates: Vec::new(),
            }
        }

        /// O registro no `accounts`: token e certificado de remetente do dispositivo.
        pub fn register(&self, device: &Device, token: String) -> Result<(), Box<dyn Error>> {
            let certificate = accounts()?.issue_sender_certificate(
                &device.address,
                device.identity_key(),
                now_millis()? + super::common::CERTIFICATE_VALIDITY_MILLIS,
            )?;
            let mut state = lock(&self.state);
            state.tokens.insert(username(device), token);
            state.certificates.insert(username(device), certificate);
            Ok(())
        }

        pub fn certificate_of(&self, device: &Device) -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(lock(&self.state)
                .certificates
                .get(&username(device))
                .cloned()
                .ok_or("sem certificado")?)
        }

        /// A `UnidentifiedAccess` que a conta registrou.
        pub fn register_access_key(
            &self,
            device: &Device,
            access_key: Vec<u8>,
        ) -> Result<(), Box<dyn Error>> {
            let (aci, _) = device_key(device)?;
            lock(&self.state).access_keys.insert(aci, access_key);
            Ok(())
        }

        pub fn wait_connected(&self, device: &Device) -> Result<(), Box<dyn Error>> {
            let key = device_key(device)?;
            wait(|| lock(&self.state).connected.contains_key(&key))
        }

        pub fn wait_acked(&self, count: usize) -> Result<(), Box<dyn Error>> {
            wait(|| lock(&self.state).acked.len() >= count)
        }

        pub fn wait_delivered(&self, count: usize) -> Result<(), Box<dyn Error>> {
            wait(|| lock(&self.state).delivered >= count)
        }

        pub fn acked(&self) -> Vec<u64> {
            lock(&self.state).acked.clone()
        }

        /// Aplica `fault` ao próximo `Send`, de qualquer socket.
        pub fn inject(&self, fault: Fault) {
            lock(&self.state).faults.push_back(fault);
        }

        pub fn sends(&self) -> Vec<CapturedSend> {
            lock(&self.state).sends.clone()
        }

        pub fn unidentified_handshakes(&self) -> Vec<Vec<(String, String)>> {
            lock(&self.state).unidentified_handshakes.clone()
        }
    }

    fn wait(mut done: impl FnMut() -> bool) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + WAIT;
        while !done() {
            if Instant::now() > deadline {
                return Err("tempo esgotado".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    /// `aci.device` de um `Authorization: Basic` válido.
    fn authenticate(state: &State, authorization: Option<&str>) -> Option<String> {
        let encoded = authorization?.strip_prefix("Basic ")?;
        let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
        let (user, token) = decoded.split_once(':')?;
        (state.tokens.get(user)? == token).then(|| user.to_owned())
    }

    fn parse_user(user: &str) -> Option<DeviceKey> {
        let (aci, device) = user.split_once('.')?;
        Some((
            Uuid::parse_str(aci).ok()?.into_bytes(),
            device.parse().ok()?,
        ))
    }

    // O callback do handshake devolve o `ErrorResponse` do tungstenite, que é grande.
    #[allow(clippy::result_large_err)]
    fn websocket(stream: TcpStream, state: &Arc<Mutex<State>>) -> Result<(), Box<dyn Error>> {
        let mut socket = Socket::Unidentified;
        let mut user = None;
        let mut ws = tungstenite::accept_hdr(stream, |request: &Request, response: Response| {
            let authorization = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());
            let mut state = lock(state);
            match request.uri().path() {
                "/v1/ws" => {
                    socket = Socket::Authenticated;
                    user = authenticate(&state, authorization);
                    if user.is_none() {
                        let mut refused = ErrorResponse::new(None);
                        *refused.status_mut() = StatusCode::UNAUTHORIZED;
                        return Err(refused);
                    }
                }
                "/v1/ws/unidentified" => {
                    let headers = request
                        .headers()
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.as_str().to_owned(),
                                String::from_utf8_lossy(value.as_bytes()).into_owned(),
                            )
                        })
                        .collect();
                    state.unidentified_handshakes.push(headers);
                }
                _ => {
                    let mut missing = ErrorResponse::new(None);
                    *missing.status_mut() = StatusCode::NOT_FOUND;
                    return Err(missing);
                }
            }
            Ok(response)
        })
        .map_err(|_| "handshake recusado")?;
        ws.get_ref()
            .set_read_timeout(Some(Duration::from_millis(20)))?;

        let (outgoing, deliveries) = mpsc::channel::<Vec<u8>>();
        let me = match &user {
            Some(user) => {
                let key = parse_user(user).ok_or("usuário malformado")?;
                let mut state = lock(state);
                for (_, frame) in state.unacked.get(&key).into_iter().flatten() {
                    outgoing.send(frame.clone())?;
                }
                state.next_connection += 1;
                let id = state.next_connection;
                state.connected.insert(key, (id, outgoing));
                Some((key, id))
            }
            None => None,
        };

        let result = serve(&mut ws, socket, me.map(|(key, _)| key), state, &deliveries);
        if let Some((key, id)) = me {
            let mut state = lock(state);
            if state
                .connected
                .get(&key)
                .is_some_and(|(current, _)| *current == id)
            {
                state.connected.remove(&key);
            }
        }
        result
    }

    fn serve(
        ws: &mut WebSocket<TcpStream>,
        socket: Socket,
        me: Option<DeviceKey>,
        state: &Arc<Mutex<State>>,
        deliveries: &mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        loop {
            while let Ok(frame) = deliveries.try_recv() {
                ws.send(Message::binary(frame))?;
                lock(state).delivered += 1;
            }
            let bytes = match ws.read() {
                Ok(Message::Binary(bytes)) => bytes,
                Ok(Message::Close(_)) => return Ok(()),
                Ok(_) => continue,
                Err(tungstenite::Error::Io(e))
                    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let frame = proto::Frame::decode(bytes.as_ref())?;
            let answer = match frame.payload.ok_or("frame vazio")? {
                proto::Payload::Send(send) => {
                    let fault = lock(state).faults.pop_front();
                    if fault == Some(Fault::Drop) {
                        capture(state, socket, &bytes, &send)?;
                        return Ok(());
                    }
                    let mut ack = accept(state, socket, &bytes, send)?;
                    if fault == Some(Fault::AcceptButRateLimit) {
                        ack.status = proto::RATE_LIMITED;
                    }
                    Some(proto::Payload::SendAck(ack))
                }
                proto::Payload::Ack(ack) => {
                    let mut state = lock(state);
                    state.acked.push(ack.seq);
                    if let Some(unacked) = me.and_then(|key| state.unacked.get_mut(&key)) {
                        unacked.retain(|(seq, _)| *seq != ack.seq);
                    }
                    None
                }
                proto::Payload::Ping(ping) => Some(proto::Payload::Pong(ping)),
                _ => None,
            };
            if let Some(payload) = answer {
                let frame = proto::Frame {
                    payload: Some(payload),
                };
                ws.send(Message::binary(frame.encode_to_vec()))?;
            }
        }
    }

    /// Grava o `Send` como chegou; devolve o envelope e o destinatário.
    fn capture(
        state: &Arc<Mutex<State>>,
        socket: Socket,
        frame: &[u8],
        send: &proto::Send,
    ) -> Result<(proto::Envelope, [u8; 16]), Box<dyn Error>> {
        let envelope = send.envelope.clone().ok_or("send sem envelope")?;
        let destination_aci: [u8; 16] = send
            .destination_aci
            .as_slice()
            .try_into()
            .map_err(|_| "aci com tamanho errado")?;
        lock(state).sends.push(CapturedSend {
            socket,
            frame: frame.to_vec(),
            destination_aci,
            access_key: send.unidentified_access_key.clone(),
            client_message_id: envelope.client_message_id.clone(),
            content: envelope.content.clone(),
        });
        Ok((envelope, destination_aci))
    }

    /// Grava o `Send` e enfileira o envelope para o destinatário, se autorizado.
    fn accept(
        state: &Arc<Mutex<State>>,
        socket: Socket,
        frame: &[u8],
        send: proto::Send,
    ) -> Result<proto::SendAck, Box<dyn Error>> {
        let (envelope, destination_aci) = capture(state, socket, frame, &send)?;
        let mut state = lock(state);
        let authorized = socket == Socket::Authenticated
            || state.access_keys.get(&destination_aci) == Some(&send.unidentified_access_key);
        if !authorized {
            return Ok(proto::SendAck {
                client_message_id: envelope.client_message_id,
                status: proto::UNAUTHORIZED,
            });
        }
        state.next_seq += 1;
        let deliver = proto::Frame {
            payload: Some(proto::Payload::Deliver(proto::Deliver {
                seq: state.next_seq,
                server_timestamp: now_millis()?,
                envelope: Some(envelope.clone()),
            })),
        }
        .encode_to_vec();
        let key = (destination_aci, send.destination_device_id);
        let seq = state.next_seq;
        state
            .unacked
            .entry(key)
            .or_default()
            .push((seq, deliver.clone()));
        if let Some((_, connection)) = state.connected.get(&key) {
            connection.send(deliver)?;
        }
        Ok(proto::SendAck {
            client_message_id: envelope.client_message_id,
            status: proto::ACCEPTED,
        })
    }

    /// `GET /v1/certificate/sender` do `accounts`, uma requisição por conexão.
    fn http(mut stream: TcpStream, state: &Arc<Mutex<State>>) -> Result<(), Box<dyn Error>> {
        stream.set_read_timeout(Some(WAIT))?;
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                return Ok(());
            }
            request.extend_from_slice(&buffer[..read]);
        }
        let request = String::from_utf8(request)?;
        let authorization = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_owned())
        });
        let state = lock(state);
        let certificate = request
            .starts_with("GET /v1/certificate/sender HTTP/1.1\r\n")
            .then(|| authenticate(&state, authorization.as_deref()))
            .flatten()
            .and_then(|user| state.certificates.get(&user));
        let response = match certificate {
            Some(certificate) => {
                let body = format!(r#"{{"certificate":"{}"}}"#, STANDARD.encode(certificate));
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }
            None => "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_owned(),
        };
        stream.write_all(response.as_bytes())?;
        Ok(())
    }
}
