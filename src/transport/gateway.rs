//! Socket autenticado (`/v1/ws`), numa thread própria.
//!
//! A thread é a única dona do socket: lê `Deliver`, entrega ao núcleo e devolve `Ack` só do que
//! o núcleo persistiu; responde `Ping`; escreve os `Send` de fallback que chegam por canal e
//! devolve o `SendAck` a quem esperava. Caiu, reconecta com backoff exponencial e avisa a cada
//! conexão aberta, para a outbox reenviar o que ficou. A entrega é at-least-once: um `Deliver`
//! sem `Ack` volta na próxima conexão.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use super::socket::Socket;
use super::{Credentials, Disposition, Incoming, Sent, TransportError, proto};

/// Espera antes da primeira reconexão; dobra a cada falha até [`MAX_BACKOFF`].
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Sem nada chegar por esse tempo, manda um `Ping`.
const PING_AFTER: Duration = Duration::from_secs(30);

/// Sem resposta ao `Ping` nesse tempo, dá a conexão por morta e reconecta.
const PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// Quanto um `Send` espera pelo `SendAck`.
pub(super) const SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// Entrega um envelope recebido ao núcleo.
pub(super) type DeliverFn = Box<dyn FnMut(Incoming<'_>) -> Disposition + Send>;

/// Avisa que o socket autenticado (re)conectou.
pub(super) type ConnectedFn = Box<dyn FnMut() + Send>;

type Reply = Sender<Result<Sent, TransportError>>;

enum Command {
    Send(proto::Send, Reply),
    Stop,
}

/// Handle da thread do socket autenticado; ao sair de escopo, a thread fecha o socket e
/// termina.
pub(super) struct Gateway {
    commands: Sender<Command>,
}

impl Gateway {
    /// Sobe a thread, que conecta em `url` com `credentials`, chama `connected` a cada conexão
    /// aberta e passa cada envelope recebido a `deliver`.
    pub(super) fn start(
        url: String,
        tls: Arc<rustls::ClientConfig>,
        credentials: Arc<Credentials>,
        deliver: DeliverFn,
        connected: ConnectedFn,
    ) -> Result<Self, TransportError> {
        let (commands, receiver) = mpsc::channel();
        let worker = Worker {
            url,
            tls,
            credentials,
            deliver,
            connected,
            commands: receiver,
            next_ping: 0,
        };
        thread::Builder::new()
            .name("falaai-gateway".to_owned())
            .spawn(move || worker.run())
            .map_err(|_| TransportError::Network)?;
        Ok(Self { commands })
    }

    /// Envia `send` pelo socket autenticado e espera o `SendAck`. Sem conexão no momento, falha
    /// com [`TransportError::NotConnected`].
    pub(super) fn send(&self, send: proto::Send) -> Result<Sent, TransportError> {
        let (reply, response) = mpsc::channel();
        self.commands
            .send(Command::Send(send, reply))
            .map_err(|_| TransportError::NotConnected)?;
        match response.recv_timeout(SEND_TIMEOUT) {
            Ok(result) => result,
            Err(_) => Err(TransportError::Network),
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
    }
}

#[derive(PartialEq, Eq)]
enum Flow {
    Reconnect,
    Stop,
}

struct Worker {
    url: String,
    tls: Arc<rustls::ClientConfig>,
    credentials: Arc<Credentials>,
    deliver: DeliverFn,
    connected: ConnectedFn,
    commands: Receiver<Command>,
    next_ping: u64,
}

impl Worker {
    fn run(mut self) {
        let mut backoff = MIN_BACKOFF;
        loop {
            let authorization = self.credentials.authorization();
            if let Ok(socket) = Socket::connect(&self.url, &self.tls, Some(&authorization)) {
                backoff = MIN_BACKOFF;
                (self.connected)();
                if self.serve(socket) == Flow::Stop {
                    return;
                }
            }
            if self.wait(backoff) == Flow::Stop {
                return;
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// Espera `duration` sem conexão: `Send` falha na hora, `Stop` encerra.
    fn wait(&mut self, duration: Duration) -> Flow {
        let deadline = Instant::now() + duration;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.commands.recv_timeout(left) {
                Ok(Command::Send(_, reply)) => {
                    let _ = reply.send(Err(TransportError::NotConnected));
                }
                Ok(Command::Stop) | Err(RecvTimeoutError::Disconnected) => return Flow::Stop,
                Err(RecvTimeoutError::Timeout) => return Flow::Reconnect,
            }
        }
    }

    /// Atende uma conexão até ela cair ou chegar `Stop`. Quem esperava `SendAck` dela recebe
    /// erro de rede quando `pending` sai de escopo.
    fn serve(&mut self, mut socket: Socket) -> Flow {
        let mut pending: HashMap<Vec<u8>, Reply> = HashMap::new();
        let mut last_heard = Instant::now();
        let mut ping_sent: Option<Instant> = None;
        loop {
            loop {
                match self.commands.try_recv() {
                    Ok(Command::Send(send, reply)) => {
                        let id = client_message_id(&send);
                        if socket.send(proto::Payload::Send(send)).is_err() {
                            let _ = reply.send(Err(TransportError::Network));
                            return Flow::Reconnect;
                        }
                        pending.insert(id, reply);
                    }
                    Ok(Command::Stop) | Err(TryRecvError::Disconnected) => {
                        socket.close();
                        return Flow::Stop;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }

            let payload = match socket.recv() {
                Ok(Some(payload)) => payload,
                Ok(None) => {
                    match ping_sent {
                        Some(sent) if sent.elapsed() > PONG_TIMEOUT => return Flow::Reconnect,
                        None if last_heard.elapsed() > PING_AFTER => {
                            self.next_ping = self.next_ping.wrapping_add(1);
                            let ping = proto::Ping { id: self.next_ping };
                            if socket.send(proto::Payload::Ping(ping)).is_err() {
                                return Flow::Reconnect;
                            }
                            ping_sent = Some(Instant::now());
                        }
                        _ => {}
                    }
                    continue;
                }
                Err(_) => return Flow::Reconnect,
            };
            last_heard = Instant::now();
            ping_sent = None;

            let answer = match payload {
                proto::Payload::Deliver(deliver) => {
                    let envelope = deliver.envelope.unwrap_or_default();
                    let incoming = Incoming {
                        content: &envelope.content,
                        client_message_id: &envelope.client_message_id,
                        server_timestamp: deliver.server_timestamp,
                    };
                    match (self.deliver)(incoming) {
                        Disposition::Ack => {
                            Some(proto::Payload::Ack(proto::Ack { seq: deliver.seq }))
                        }
                        Disposition::Retain => None,
                    }
                }
                proto::Payload::SendAck(ack) => {
                    if let Some(reply) = pending.remove(&ack.client_message_id) {
                        let _ = reply.send(Ok(Sent::from_status(ack.status)));
                    }
                    None
                }
                proto::Payload::Ping(ping) => {
                    Some(proto::Payload::Pong(proto::Pong { id: ping.id }))
                }
                proto::Payload::Pong(_) | proto::Payload::Send(_) | proto::Payload::Ack(_) => None,
            };
            if let Some(answer) = answer
                && socket.send(answer).is_err()
            {
                return Flow::Reconnect;
            }
        }
    }
}

fn client_message_id(send: &proto::Send) -> Vec<u8> {
    send.envelope
        .as_ref()
        .map(|e| e.client_message_id.clone())
        .unwrap_or_default()
}
