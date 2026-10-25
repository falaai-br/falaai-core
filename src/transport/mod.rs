//! Transporte do cliente até o servidor: WebSocket e HTTPS sobre rustls (ADR-0002, ADR-0010).
//!
//! Dois WebSockets do gateway, em conexões TLS separadas (falaai-proto `websocket.proto`):
//!
//! - `/v1/ws`, autenticado pelo token do dispositivo: recebe `Deliver`, devolve `Ack` e, só
//!   como fallback, envia `Send`. Fica aberto numa thread com reconexão ([`gateway`]).
//! - `/v1/ws/unidentified`, sem credencial: envia o envelope selado provando o direito de
//!   enviar com a unidentified access key do destinatário ([`unidentified`]). O servidor vê o
//!   destinatário, nunca quem envia.
//!
//! E HTTPS para o `accounts`, que emite o certificado de remetente ([`accounts`]).
//!
//! Não conhece a libsignal: recebe envelopes já selados e chaves já derivadas. Nada daqui vai
//! para log.

mod accounts;
mod endpoint;
mod gateway;
pub(crate) mod proto;
mod socket;
mod unidentified;

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use self::accounts::Accounts;
use self::endpoint::{Endpoint, Roots};
use self::gateway::Gateway;
use self::unidentified::Unidentified;

/// Caminho do socket autenticado.
const AUTHENTICATED_PATH: &str = "/v1/ws";

/// Caminho do socket não autenticado.
const UNIDENTIFIED_PATH: &str = "/v1/ws/unidentified";

/// Erro do transporte. Não carrega URL, credencial nem conteúdo.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TransportError {
    /// URL malformada, com caminho, ou sem TLS fora do loopback.
    #[error("endereço do servidor inválido")]
    InvalidEndpoint,
    /// Certificado raiz da configuração malformado.
    #[error("certificado raiz inválido")]
    InvalidRootCertificate,
    /// Conexão, TLS ou tempo esgotado; a conexão caiu.
    #[error("falha de rede")]
    Network,
    /// O socket autenticado ainda não conectou ou está reconectando.
    #[error("sem conexão com o servidor")]
    NotConnected,
    /// O servidor recusou a credencial do dispositivo.
    #[error("credencial recusada")]
    Unauthorized,
    /// Resposta que não segue o contrato.
    #[error("resposta inválida do servidor")]
    Protocol,
}

/// Envelope recebido pelo socket autenticado.
pub(crate) struct Incoming<'a> {
    /// Mensagem selada.
    pub(crate) content: &'a [u8],
    /// Id que o remetente deu à mensagem, o mesmo em todo reenvio dela.
    pub(crate) client_message_id: &'a [u8],
    /// Instante em que o servidor recebeu o envelope, em milissegundos desde a época Unix.
    pub(crate) server_timestamp: u64,
}

/// O que fazer com um envelope recebido depois de entregue ao núcleo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Persistido, ou impossível de abrir: confirma e o servidor apaga da fila.
    Ack,
    /// Falha local passageira: não confirma, e o servidor entrega de novo na próxima conexão.
    Retain,
}

/// Resultado de um envio, do `SendAck`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sent {
    /// Gravado na fila do destinatário.
    Accepted,
    /// Envelope malformado; reenviar igual não adianta.
    Invalid,
    /// Destinatário ou dispositivo inexistente.
    UnknownDestination,
    /// Limite de taxa; reenviar com backoff.
    RateLimited,
    /// Unidentified access key ausente ou errada (ou destinatário inexistente).
    Unauthorized,
}

impl Sent {
    fn from_status(status: i32) -> Self {
        match proto::SendStatus::try_from(status) {
            Ok(proto::SendStatus::Accepted) => Self::Accepted,
            Ok(proto::SendStatus::UnknownDestination) => Self::UnknownDestination,
            Ok(proto::SendStatus::RateLimited) => Self::RateLimited,
            Ok(proto::SendStatus::Unauthorized) => Self::Unauthorized,
            Ok(proto::SendStatus::Invalid | proto::SendStatus::Unspecified) | Err(_) => {
                Self::Invalid
            }
        }
    }
}

/// Endereços do servidor e raízes TLS.
pub(crate) struct Server {
    gateway: Endpoint,
    accounts: Endpoint,
    roots: Roots,
}

impl Server {
    /// `gateway` é a base `wss://` do gateway; `accounts`, a base `https://` do `accounts`; sem
    /// caminho. Texto claro (`ws://`, `http://`) só no loopback. `root_certificates` (DER), se
    /// não vazio, substitui as raízes da Mozilla.
    pub(crate) fn new(
        gateway: &str,
        accounts: &str,
        root_certificates: &[Vec<u8>],
    ) -> Result<Self, TransportError> {
        Ok(Self {
            gateway: Endpoint::websocket(gateway)?,
            accounts: Endpoint::https(accounts)?,
            roots: Roots::new(root_certificates)?,
        })
    }
}

/// Credencial do dispositivo: `aci.device_id` e o token que o `accounts` emitiu no registro.
/// Vai em `Authorization: Basic` no socket autenticado e no `accounts`; nunca no socket não
/// autenticado.
pub(crate) struct Credentials {
    username: String,
    token: Zeroizing<String>,
}

impl Credentials {
    pub(crate) fn new(aci: &str, device_id: u8, token: Zeroizing<String>) -> Self {
        Self {
            username: format!("{aci}.{device_id}"),
            token,
        }
    }

    /// Valor do header `Authorization`.
    fn authorization(&self) -> Zeroizing<String> {
        let mut pair = Zeroizing::new(String::with_capacity(
            self.username.len() + 1 + self.token.len(),
        ));
        pair.push_str(&self.username);
        pair.push(':');
        pair.push_str(&self.token);
        let mut header = Zeroizing::new(String::from("Basic "));
        STANDARD.encode_string(pair.as_bytes(), &mut header);
        header
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(<omitidas>)")
    }
}

/// Envelope a enviar: destinatário e o envelope do falaai-proto já montado.
pub(crate) struct Outgoing {
    /// ACI do destinatário, 16 bytes.
    pub(crate) destination_aci: [u8; 16],
    pub(crate) destination_device_id: u8,
    pub(crate) client_message_id: Vec<u8>,
    /// Tipo do envelope, em claro para o servidor decidir o push; nunca `Unspecified`.
    pub(crate) envelope_type: proto::EnvelopeType,
    /// Mensagem selada.
    pub(crate) content: Vec<u8>,
}

/// Conexão com o servidor de um dispositivo: socket autenticado em segundo plano, socket não
/// autenticado sob demanda e cliente do `accounts`. Ao sair de escopo, o socket autenticado
/// fecha.
pub(crate) struct Transport {
    credentials: Arc<Credentials>,
    gateway: Gateway,
    unidentified: Mutex<Unidentified>,
    accounts: Accounts,
}

impl Transport {
    /// Conecta o socket autenticado em segundo plano, chama `connected` a cada vez que ele
    /// (re)conecta e passa a `deliver` cada envelope recebido.
    pub(crate) fn connect(
        server: &Server,
        credentials: Credentials,
        deliver: impl FnMut(Incoming<'_>) -> Disposition + Send + 'static,
        connected: impl FnMut() + Send + 'static,
    ) -> Result<Self, TransportError> {
        let tls = server.roots.rustls()?;
        let credentials = Arc::new(credentials);
        let gateway = Gateway::start(
            server.gateway.join(AUTHENTICATED_PATH),
            tls.clone(),
            credentials.clone(),
            Box::new(deliver),
            Box::new(connected),
        )?;
        Ok(Self {
            credentials,
            gateway,
            unidentified: Mutex::new(Unidentified::new(
                server.gateway.join(UNIDENTIFIED_PATH),
                tls,
            )),
            accounts: Accounts::new(
                server.accounts.join(accounts::SENDER_CERTIFICATE_PATH),
                server.roots.ureq(),
            ),
        })
    }

    /// Envia `outgoing`. Com a unidentified access key do destinatário, vai pelo socket não
    /// autenticado e o servidor não sabe quem envia. Sem ela, ou se o servidor a recusar, vai
    /// pelo socket autenticado e o servidor vê o par remetente/destinatário (primeiro contato,
    /// risco residual da ADR-0010). Falha de rede no socket não autenticado não cai para o
    /// autenticado: expor o par não resolveria a rede.
    pub(crate) fn send(
        &self,
        outgoing: Outgoing,
        access_key: Option<&[u8]>,
    ) -> Result<Sent, TransportError> {
        let mut send = proto::Send {
            destination_aci: outgoing.destination_aci.to_vec(),
            destination_device_id: outgoing.destination_device_id.into(),
            envelope: Some(proto::WireEnvelope {
                r#type: outgoing.envelope_type.into(),
                client_message_id: outgoing.client_message_id,
                content: outgoing.content,
            }),
            unidentified_access_key: Vec::new(),
        };
        if let Some(access_key) = access_key {
            send.unidentified_access_key = access_key.to_vec();
            let sent = self
                .unidentified
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .send(&send)?;
            if sent != Sent::Unauthorized {
                return Ok(sent);
            }
            send.unidentified_access_key.clear();
        }
        self.gateway.send(send)
    }

    /// Certificado de remetente novo do `accounts`, como veio.
    pub(crate) fn sender_certificate(&self) -> Result<Vec<u8>, TransportError> {
        self.accounts.sender_certificate(&self.credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credencial_vai_em_basic_com_aci_ponto_device() {
        let credentials = Credentials::new(
            "9d0652a3-dcc3-4d11-975f-74d61598733f",
            3,
            Zeroizing::new("tok".to_owned()),
        );
        let expected = format!(
            "Basic {}",
            STANDARD.encode("9d0652a3-dcc3-4d11-975f-74d61598733f.3:tok")
        );
        assert_eq!(credentials.authorization().as_str(), expected);
    }

    #[test]
    fn debug_da_credencial_omite_aci_e_token() {
        let credentials = Credentials::new(
            "9d0652a3-dcc3-4d11-975f-74d61598733f",
            3,
            Zeroizing::new("segredo".to_owned()),
        );
        assert_eq!(format!("{credentials:?}"), "Credentials(<omitidas>)");
    }

    #[test]
    fn status_desconhecido_vira_invalido() {
        assert_eq!(Sent::from_status(1), Sent::Accepted);
        assert_eq!(Sent::from_status(5), Sent::Unauthorized);
        assert_eq!(Sent::from_status(0), Sent::Invalid);
        assert_eq!(Sent::from_status(99), Sent::Invalid);
    }
}
