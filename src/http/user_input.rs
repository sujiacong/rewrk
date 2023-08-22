use std::convert::TryFrom;
use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, Result};
use http::header::HeaderValue;
use http::uri::Uri;
use http::{HeaderMap, Method};
use hyper::body::Bytes;
use tokio::task::spawn_blocking;
use tokio_rustls::TlsConnector;

use super::BenchType;

#[derive(Clone)]
pub(crate) enum Scheme {
    Http,
    Https(TlsConnector),
}

impl Scheme {
    fn default_port(&self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https(_) => 443,
        }
    }
}

struct NoCertificateVerification {}
impl tokio_rustls::rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::Certificate,
        _intermediates: &[tokio_rustls::rustls::Certificate],
        _server_name: &tokio_rustls::rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<tokio_rustls::rustls::client::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::ServerCertVerified::assertion())
    }
}

#[derive(Clone)]
pub(crate) struct UserInput {
    pub(crate) addr: SocketAddr,
    pub(crate) scheme: Scheme,
    pub(crate) host: String,
    pub(crate) host_header: HeaderValue,
    pub(crate) uri: Uri,
    pub(crate) method: Method,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

impl UserInput {
    pub(crate) async fn new(
        protocol: BenchType,
        string: String,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<Self> {
        spawn_blocking(move || {
            Self::blocking_new(protocol, string, method, headers, body)
        })
        .await
        .unwrap()
    }

    fn blocking_new(
        protocol: BenchType,
        string: String,
        method: Method,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<Self> {
        let uri = Uri::try_from(string)?;
        let scheme = uri
            .scheme()
            .ok_or_else(|| anyhow!("scheme is not present on uri"))?
            .as_str();
        let scheme = match scheme {
            "http" => Scheme::Http,
            "https" => {
                let root_certs = tokio_rustls::rustls::RootCertStore::empty();
                let mut cfg = tokio_rustls::rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_certs)
                .with_no_client_auth();
                match protocol
                {
                    BenchType::HTTP1 => cfg.alpn_protocols.push(b"http/1.1".to_vec()),
                    BenchType::HTTP2 => cfg.alpn_protocols.push(b"h2".to_vec()),
                };
                let mut dangerous_config = tokio_rustls::rustls::ClientConfig::dangerous(&mut cfg);
                dangerous_config.set_certificate_verifier(std::sync::Arc::new(NoCertificateVerification {}));
                Scheme::Https(TlsConnector::from(std::sync::Arc::new(cfg)))
            },
            _ => return Err(anyhow::Error::msg("invalid scheme")),
        };
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow!("host not present on uri"))?;
        let host = authority.host().to_owned();
        let port = authority
            .port_u16()
            .unwrap_or_else(|| scheme.default_port());
        let host_header = HeaderValue::from_str(&host)?;

        // Prefer ipv4.
        let addr_iter = (host.as_str(), port).to_socket_addrs()?;
        let mut last_addr = None;
        for addr in addr_iter {
            last_addr = Some(addr);
            if addr.is_ipv4() {
                break;
            }
        }
        let addr = last_addr.ok_or_else(|| anyhow!("hostname lookup failed"))?;

        Ok(Self {
            addr,
            scheme,
            host,
            host_header,
            uri,
            method,
            headers,
            body,
        })
    }
}
