//! HTTPS do `accounts`: certificado de remetente do sealed sender.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use super::{Credentials, TransportError};

/// Caminho do certificado de remetente no `accounts` (contrato proposto ao fls-5nv).
pub(super) const SENDER_CERTIFICATE_PATH: &str = "/v1/certificate/sender";

/// Limite de uma requisição inteira.
const TIMEOUT: Duration = Duration::from_secs(15);

/// Maior corpo aceito; o certificado tem algumas centenas de bytes.
const MAX_BODY: u64 = 16 * 1024;

/// Corpo da resposta: `{"certificate": "<base64>"}`.
#[derive(Deserialize)]
struct SenderCertificateResponse {
    certificate: String,
}

/// Cliente HTTPS do `accounts`.
pub(super) struct Accounts {
    agent: ureq::Agent,
    url: String,
}

impl Accounts {
    pub(super) fn new(url: String, tls: ureq::tls::TlsConfig) -> Self {
        let agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .new_agent();
        Self { agent, url }
    }

    /// Pede um certificado de remetente novo para o dispositivo de `credentials`. Devolve os
    /// bytes como vieram; quem valida é o protocolo, ao recebê-los.
    pub(super) fn sender_certificate(
        &self,
        credentials: &Credentials,
    ) -> Result<Vec<u8>, TransportError> {
        let mut response = self
            .agent
            .get(&self.url)
            .header("Authorization", credentials.authorization().as_str())
            .call()
            .map_err(|_| TransportError::Network)?;
        match response.status().as_u16() {
            200 => {}
            401 | 403 => return Err(TransportError::Unauthorized),
            _ => return Err(TransportError::Network),
        }
        let body: SenderCertificateResponse = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_json()
            .map_err(|_| TransportError::Protocol)?;
        STANDARD
            .decode(body.certificate)
            .map_err(|_| TransportError::Protocol)
    }
}
