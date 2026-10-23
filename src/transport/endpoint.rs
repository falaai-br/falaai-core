//! Endereços do servidor e raízes TLS.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use tungstenite::http::Uri;

use super::TransportError;

/// Base de um serviço (`esquema://host[:porta]`), sem caminho. Só aceita TLS, exceto no
/// loopback, onde rodam o servidor de desenvolvimento e os testes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Endpoint(String);

impl Endpoint {
    /// Base do gateway: `wss://`, ou `ws://` no loopback.
    pub(super) fn websocket(url: &str) -> Result<Self, TransportError> {
        Self::parse(url, "wss", "ws")
    }

    /// Base de um serviço HTTP: `https://`, ou `http://` no loopback.
    pub(super) fn https(url: &str) -> Result<Self, TransportError> {
        Self::parse(url, "https", "http")
    }

    fn parse(url: &str, secure: &str, plain: &str) -> Result<Self, TransportError> {
        let uri: Uri = url.parse().map_err(|_| TransportError::InvalidEndpoint)?;
        let scheme = uri.scheme_str().ok_or(TransportError::InvalidEndpoint)?;
        let host = uri.host().ok_or(TransportError::InvalidEndpoint)?;
        let bare_path = matches!(uri.path(), "" | "/") && uri.query().is_none();
        let allowed = scheme == secure || (scheme == plain && is_loopback(host));
        if !allowed || !bare_path || host.is_empty() {
            return Err(TransportError::InvalidEndpoint);
        }
        let authority = uri.authority().ok_or(TransportError::InvalidEndpoint)?;
        if authority.as_str().contains('@') {
            return Err(TransportError::InvalidEndpoint);
        }
        Ok(Self(format!("{scheme}://{authority}")))
    }

    /// URL de `path` (começando com `/`) neste serviço.
    pub(super) fn join(&self, path: &str) -> String {
        format!("{}{path}", self.0)
    }
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

/// Raízes em que o TLS confia: as da Mozilla (webpki-roots) ou, se a configuração trouxer
/// certificados, só eles (pinning pela CA do servidor).
#[derive(Clone)]
pub(super) enum Roots {
    WebPki,
    Pinned(Arc<Vec<CertificateDer<'static>>>),
}

impl Roots {
    /// `certificates` em DER; vazio usa as raízes da Mozilla.
    pub(super) fn new(certificates: &[Vec<u8>]) -> Result<Self, TransportError> {
        if certificates.is_empty() {
            return Ok(Self::WebPki);
        }
        let pinned = certificates
            .iter()
            .map(|der| CertificateDer::from(der.clone()))
            .collect::<Vec<_>>();
        // Valida já, para um certificado ruim falhar na configuração e não em cada conexão.
        let mut store = rustls::RootCertStore::empty();
        for certificate in &pinned {
            store
                .add(certificate.clone())
                .map_err(|_| TransportError::InvalidRootCertificate)?;
        }
        Ok(Self::Pinned(Arc::new(pinned)))
    }

    /// Configuração do rustls para o WebSocket.
    pub(super) fn rustls(&self) -> Result<Arc<rustls::ClientConfig>, TransportError> {
        let mut store = rustls::RootCertStore::empty();
        match self {
            Self::WebPki => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            Self::Pinned(certificates) => {
                for certificate in certificates.iter() {
                    store
                        .add(certificate.clone())
                        .map_err(|_| TransportError::InvalidRootCertificate)?;
                }
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| TransportError::InvalidRootCertificate)?
            .with_root_certificates(store)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// Configuração de TLS do cliente HTTPS.
    pub(super) fn ureq(&self) -> ureq::tls::TlsConfig {
        let roots = match self {
            Self::WebPki => ureq::tls::RootCerts::WebPki,
            Self::Pinned(certificates) => ureq::tls::RootCerts::new_with_certs(
                &certificates
                    .iter()
                    .map(|der| ureq::tls::Certificate::from_der(der.as_ref()).to_owned())
                    .collect::<Vec<_>>(),
            ),
        };
        ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(roots)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exige_tls_fora_do_loopback() {
        assert_eq!(
            Endpoint::websocket("wss://gw.falaai.com.br").map(|e| e.join("/v1/ws")),
            Ok("wss://gw.falaai.com.br/v1/ws".to_owned())
        );
        assert_eq!(
            Endpoint::https("https://api.falaai.com.br:8443/").map(|e| e.join("/v1/x")),
            Ok("https://api.falaai.com.br:8443/v1/x".to_owned())
        );
        for url in [
            "ws://gw.falaai.com.br",
            "http://api.falaai.com.br",
            "https://gw.falaai.com.br",
            "wss://gw.falaai.com.br/v1/ws",
            "wss://gw.falaai.com.br?x=1",
            "wss://usuario:senha@gw.falaai.com.br",
            "gw.falaai.com.br",
            "",
        ] {
            assert_eq!(
                Endpoint::websocket(url),
                Err(TransportError::InvalidEndpoint),
                "{url}"
            );
        }
        assert_eq!(
            Endpoint::https("http://api.falaai.com.br"),
            Err(TransportError::InvalidEndpoint)
        );
    }

    #[test]
    fn aceita_texto_claro_so_no_loopback() {
        for url in ["ws://127.0.0.1:8080", "ws://localhost:1", "ws://[::1]:9"] {
            assert!(Endpoint::websocket(url).is_ok(), "{url}");
        }
        assert!(Endpoint::https("http://127.0.0.1:8080").is_ok());
        assert_eq!(
            Endpoint::websocket("ws://10.0.0.1"),
            Err(TransportError::InvalidEndpoint)
        );
    }

    #[test]
    fn raiz_malformada_falha_na_configuracao() {
        assert_eq!(
            Roots::new(&[vec![0x30, 0x00]]).err(),
            Some(TransportError::InvalidRootCertificate)
        );
        assert!(Roots::new(&[]).is_ok_and(|roots| roots.rustls().is_ok()));
    }
}
