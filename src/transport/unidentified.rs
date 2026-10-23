//! Socket não autenticado (`/v1/ws/unidentified`), por onde sai o envelope selado.
//!
//! Sem credencial nenhuma: o handshake não leva header de autorização e o `Send` só leva o
//! destinatário, a unidentified access key dele e o envelope selado. A conexão é aberta no
//! primeiro envio e reaproveitada; caiu, abre outra.

use std::sync::Arc;
use std::time::Instant;

use super::gateway::SEND_TIMEOUT;
use super::socket::Socket;
use super::{Sent, TransportError, proto};

pub(super) struct Unidentified {
    url: String,
    tls: Arc<rustls::ClientConfig>,
    socket: Option<Socket>,
}

impl Unidentified {
    pub(super) fn new(url: String, tls: Arc<rustls::ClientConfig>) -> Self {
        Self {
            url,
            tls,
            socket: None,
        }
    }

    /// Envia `send` e espera o `SendAck`. Uma conexão reaproveitada pode ter caído em silêncio;
    /// se falhar, tenta uma vez numa nova. O destinatário deduplica um envelope que chegue duas
    /// vezes.
    pub(super) fn send(&mut self, send: &proto::Send) -> Result<Sent, TransportError> {
        let reused = self.socket.is_some();
        match self.try_send(send) {
            Err(TransportError::Network) if reused => self.try_send(send),
            result => result,
        }
    }

    fn try_send(&mut self, send: &proto::Send) -> Result<Sent, TransportError> {
        let socket = match &mut self.socket {
            Some(socket) => socket,
            None => self
                .socket
                .insert(Socket::connect(&self.url, &self.tls, None)?),
        };
        let result = exchange(socket, send);
        if result.is_err()
            && let Some(socket) = self.socket.take()
        {
            socket.close();
        }
        result
    }
}

fn exchange(socket: &mut Socket, send: &proto::Send) -> Result<Sent, TransportError> {
    let id = send
        .envelope
        .as_ref()
        .map(|e| e.client_message_id.as_slice())
        .unwrap_or_default();
    socket.send(proto::Payload::Send(send.clone()))?;
    let deadline = Instant::now() + SEND_TIMEOUT;
    while Instant::now() < deadline {
        match socket.recv()? {
            Some(proto::Payload::SendAck(ack)) if ack.client_message_id == id => {
                return Ok(Sent::from_status(ack.status));
            }
            Some(proto::Payload::Ping(ping)) => {
                socket.send(proto::Payload::Pong(proto::Pong { id: ping.id }))?;
            }
            _ => {}
        }
    }
    Err(TransportError::Network)
}
