//! Um WebSocket do gateway: conexão TCP + TLS + handshake e troca de [`Frame`]s.
//!
//! Síncrono. A leitura volta a cada [`POLL`] mesmo sem nada chegar, para quem é dono do socket
//! poder escrever entre uma leitura e outra; o tungstenite guarda o frame lido pela metade.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::HandshakeError;
use tungstenite::http::{HeaderValue, StatusCode, header};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Connector, Message, WebSocket};

use super::TransportError;
use super::proto::{Frame, Payload};

/// Limite para abrir a conexão TCP com cada endereço do host.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Limite para o handshake TLS e WebSocket e para cada escrita.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Intervalo máximo de uma leitura sem nada chegar.
pub(super) const POLL: Duration = Duration::from_millis(500);

/// WebSocket aberto com o gateway.
pub(super) struct Socket(WebSocket<MaybeTlsStream<TcpStream>>);

impl Socket {
    /// Conecta em `url`. `authorization` vai no header `Authorization` do handshake; o socket
    /// não autenticado não manda header nenhum que identifique o dispositivo. Credencial recusada
    /// falha com [`TransportError::Unauthorized`].
    pub(super) fn connect(
        url: &str,
        tls: &Arc<rustls::ClientConfig>,
        authorization: Option<&str>,
    ) -> Result<Self, TransportError> {
        let mut request = url
            .into_client_request()
            .map_err(|_| TransportError::InvalidEndpoint)?;
        if let Some(authorization) = authorization {
            let mut value =
                HeaderValue::from_str(authorization).map_err(|_| TransportError::Unauthorized)?;
            value.set_sensitive(true);
            request.headers_mut().insert(header::AUTHORIZATION, value);
        }
        let uri = request.uri();
        let host = uri.host().ok_or(TransportError::InvalidEndpoint)?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("wss") {
                443
            } else {
                80
            });
        let stream = tcp((host, port)
            .to_socket_addrs()
            .map_err(|_| TransportError::Network)?)?;
        let connector = Connector::Rustls(tls.clone());
        let (socket, _) =
            tungstenite::client_tls_with_config(request, stream, None, Some(connector)).map_err(
                |error| match error {
                    HandshakeError::Failure(tungstenite::Error::Http(response))
                        if response.status() == StatusCode::UNAUTHORIZED =>
                    {
                        TransportError::Unauthorized
                    }
                    _ => TransportError::Network,
                },
            )?;
        tcp_stream(&socket)
            .ok_or(TransportError::Network)?
            .set_read_timeout(Some(POLL))
            .map_err(|_| TransportError::Network)?;
        Ok(Self(socket))
    }

    /// Escreve `payload` num frame binário.
    pub(super) fn send(&mut self, payload: Payload) -> Result<(), TransportError> {
        let frame = Frame {
            payload: Some(payload),
        };
        self.0
            .send(Message::binary(frame.encode_to_vec()))
            .map_err(|_| TransportError::Network)
    }

    /// Próximo frame, ou `None` se nada chegou em [`POLL`] (ou chegou só controle do WebSocket
    /// ou um frame de tipo que este cliente não conhece).
    pub(super) fn recv(&mut self) -> Result<Option<Payload>, TransportError> {
        match self.0.read() {
            Ok(Message::Binary(bytes)) => Frame::decode(bytes)
                .map(|frame| frame.payload)
                .map_err(|_| TransportError::Protocol),
            Ok(Message::Text(_)) => Err(TransportError::Protocol),
            Ok(Message::Close(_)) => Err(TransportError::Network),
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => Ok(None),
            Err(tungstenite::Error::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                Ok(None)
            }
            Err(_) => Err(TransportError::Network),
        }
    }

    /// Fecha a conexão sem esperar resposta.
    pub(super) fn close(mut self) {
        let _ = self.0.close(None);
        let _ = self.0.flush();
    }
}

/// Abre TCP com o primeiro endereço que responder.
fn tcp(addresses: impl Iterator<Item = SocketAddr>) -> Result<TcpStream, TransportError> {
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            let configured = stream.set_nodelay(true).is_ok()
                && stream.set_read_timeout(Some(IO_TIMEOUT)).is_ok()
                && stream.set_write_timeout(Some(IO_TIMEOUT)).is_ok();
            if configured {
                return Ok(stream);
            }
        }
    }
    Err(TransportError::Network)
}

/// TCP por baixo do TLS. `MaybeTlsStream` é `non_exhaustive`; só plain e rustls estão ligados.
fn tcp_stream(socket: &WebSocket<MaybeTlsStream<TcpStream>>) -> Option<&TcpStream> {
    match socket.get_ref() {
        MaybeTlsStream::Rustls(stream) => Some(stream.get_ref()),
        MaybeTlsStream::Plain(stream) => Some(stream),
        _ => None,
    }
}
