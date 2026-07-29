use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;

const MAX_BODY_BYTES: usize = 1024 * 1024;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: u32 = 5;

pub struct HttpRequest<'a> {
    pub url: &'a str,
    pub pinned_certificate_pem: Option<&'a str>,
    pub skip_verification: bool,
}

#[derive(Debug)]
pub enum HttpError {
    NotHttps,
    BadUrl,
    BadRedirect,
    HttpStatus(u16),
    BodyTooLarge,
    Tls,
    Transport(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::NotHttps => write!(f, "URL must use the https scheme"),
            HttpError::BadUrl => write!(f, "URL could not be parsed"),
            HttpError::BadRedirect => {
                write!(f, "redirected to a non-https or too deep target")
            }
            HttpError::HttpStatus(401) => {
                write!(f, "server rejected the embedded credentials (401)")
            }
            HttpError::HttpStatus(403) => write!(f, "disabled on the server (403)"),
            HttpError::HttpStatus(404) => write!(f, "document not found on the server (404)"),
            HttpError::HttpStatus(code) => write!(f, "server answered HTTP status {code}"),
            HttpError::BodyTooLarge => write!(f, "response exceeded 1 MiB"),
            HttpError::Tls => write!(f, "server certificate verification failed"),
            HttpError::Transport(message) => write!(f, "request failed: {message}"),
        }
    }
}

impl std::error::Error for HttpError {}

pub trait HttpTransport {
    fn get(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpError>;
}

struct PreparedRequest {
    url: String,
    authorization: Option<String>,
}

fn validate_url(url: &str) -> Result<url::Url, HttpError> {
    let parsed = url::Url::parse(url).map_err(|_| HttpError::BadUrl)?;
    if parsed.scheme() != "https" {
        return Err(HttpError::NotHttps);
    }
    Ok(parsed)
}

fn prepare_request(url: &str) -> Result<PreparedRequest, HttpError> {
    let mut parsed = validate_url(url)?;
    let authorization = if parsed.username().is_empty() {
        None
    } else {
        let decode = |raw: &str| {
            percent_encoding::percent_decode_str(raw)
                .decode_utf8()
                .map(|cow| cow.into_owned())
                .map_err(|_| HttpError::BadUrl)
        };
        let username = decode(parsed.username())?;
        let password = decode(parsed.password().unwrap_or_default())?;
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        parsed.set_username("").map_err(|_| HttpError::BadUrl)?;
        parsed.set_password(None).map_err(|_| HttpError::BadUrl)?;
        Some(format!("Basic {credentials}"))
    };
    Ok(PreparedRequest {
        url: parsed.into(),
        authorization,
    })
}

fn redirect_target(current: &str, location: &str) -> Result<String, HttpError> {
    let base = url::Url::parse(current).map_err(|_| HttpError::BadUrl)?;
    let target = base.join(location).map_err(|_| HttpError::BadRedirect)?;
    if target.scheme() != "https" {
        return Err(HttpError::BadRedirect);
    }
    Ok(target.into())
}

// Credentials are only ever sent to the original host.
fn apply_redirect(prepared: &mut PreparedRequest, location: &str) -> Result<(), HttpError> {
    let target = redirect_target(&prepared.url, location)?;
    let same_host = url::Url::parse(&prepared.url)
        .ok()
        .zip(url::Url::parse(&target).ok())
        .map(|(current, next)| {
            current.host_str() == next.host_str()
                && current.port_or_known_default() == next.port_or_known_default()
        })
        .unwrap_or(false);
    if !same_host {
        prepared.authorization = None;
    }
    prepared.url = target;
    Ok(())
}

fn read_bounded(reader: &mut impl Read) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    let mut limited = reader.take((MAX_BODY_BYTES + 1) as u64);
    limited
        .read_to_end(&mut body)
        .map_err(|e| HttpError::Transport(e.to_string()))?;
    if body.len() > MAX_BODY_BYTES {
        return Err(HttpError::BodyTooLarge);
    }
    Ok(body)
}

fn status_error(code: u16) -> HttpError {
    HttpError::HttpStatus(code)
}

fn parse_pem_certificates(pem: &str) -> Vec<rustls::Certificate> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .map(|certs| certs.into_iter().map(rustls::Certificate).collect())
        .unwrap_or_default()
}

pub struct UreqTransport;

impl UreqTransport {
    fn build_tls_config(request: &HttpRequest) -> rustls::ClientConfig {
        if request.skip_verification {
            return rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(NoVerification))
                .with_no_client_auth();
        }
        let mut roots = rustls::RootCertStore::empty();
        roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        if let Some(pem) = request.pinned_certificate_pem {
            roots.add_parsable_certificates(&parse_pem_certificates(pem));
        }
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn fetch_once(
        agent: &ureq::Agent,
        prepared: &PreparedRequest,
    ) -> Result<ureq::Response, HttpError> {
        let mut call = agent.get(&prepared.url);
        if let Some(header) = &prepared.authorization {
            call = call.set("Authorization", header);
        }
        match call.call() {
            Ok(response) => Ok(response),
            Err(ureq::Error::Status(code, _)) => Err(status_error(code)),
            Err(ureq::Error::Transport(transport)) => {
                let message = transport.to_string();
                if message.contains("certificate") || message.contains("tls") {
                    return Err(HttpError::Tls);
                }
                // ureq's raw message can embed the host or address.
                Err(HttpError::Transport(match transport.kind() {
                    ureq::ErrorKind::Dns => "DNS resolution failed".to_string(),
                    ureq::ErrorKind::ConnectionFailed => "connection failed".to_string(),
                    _ => "transport error".to_string(),
                }))
            }
        }
    }
}

impl HttpTransport for UreqTransport {
    fn get(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(OPERATION_TIMEOUT)
            .redirects(0)
            .tls_config(Arc::new(Self::build_tls_config(request)))
            .build();
        let mut prepared = prepare_request(request.url)?;
        for _ in 0..=MAX_REDIRECTS {
            let response = Self::fetch_once(&agent, &prepared)?;
            if response.status() < 300 || response.status() >= 400 {
                return read_bounded(&mut response.into_reader());
            }
            let location = response
                .header("location")
                .ok_or(HttpError::BadRedirect)?
                .to_string();
            apply_redirect(&mut prepared, &location)?;
        }
        Err(HttpError::BadRedirect)
    }
}

struct NoVerification;

impl rustls::client::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_scheme() {
        let err = validate_url("http://example.com/subscription").unwrap_err();
        assert!(err.to_string().contains("https"), "unexpected: {err}");
    }

    #[test]
    fn extracts_percent_decoded_basic_auth() {
        let prepared = prepare_request("https://user%40corp:p%40ss@example.com/s").unwrap();
        assert_eq!(
            prepared.authorization.as_deref(),
            Some("Basic dXNlckBjb3JwOnBAc3M=") // base64("user@corp:p@ss")
        );
        assert_eq!(prepared.url, "https://example.com/s");
    }

    #[test]
    fn leaves_url_without_userinfo_untouched() {
        let prepared = prepare_request("https://example.com/s").unwrap();
        assert!(prepared.authorization.is_none());
        assert_eq!(prepared.url, "https://example.com/s");
    }

    #[test]
    fn redirect_to_http_is_rejected() {
        let target = redirect_target("https://example.com/a", "http://example.com/b").unwrap_err();
        assert!(target.to_string().contains("https"), "unexpected: {target}");
    }

    #[test]
    fn relative_redirect_resolves_against_origin() {
        let target = redirect_target("https://example.com/a/b", "../c").unwrap();
        assert_eq!(target, "https://example.com/c");
    }

    #[test]
    fn same_host_redirect_keeps_credentials() {
        let mut prepared = prepare_request("https://user:pass@example.com/s").unwrap();
        apply_redirect(&mut prepared, "/moved").unwrap();
        assert_eq!(prepared.url, "https://example.com/moved");
        assert!(prepared.authorization.is_some());
    }

    #[test]
    fn cross_host_redirect_drops_credentials() {
        let mut prepared = prepare_request("https://user:pass@example.com/s").unwrap();
        apply_redirect(&mut prepared, "https://other.example.net/s").unwrap();
        assert_eq!(prepared.url, "https://other.example.net/s");
        assert!(prepared.authorization.is_none());
    }

    #[test]
    fn body_limit_rejects_oversized_content() {
        let data = vec![0u8; MAX_BODY_BYTES + 1];
        let mut cursor = std::io::Cursor::new(data);
        assert!(read_bounded(&mut cursor).is_err());
    }

    #[test]
    fn body_limit_accepts_exact_boundary() {
        let data = vec![0u8; MAX_BODY_BYTES];
        let mut cursor = std::io::Cursor::new(data);
        assert_eq!(read_bounded(&mut cursor).unwrap().len(), MAX_BODY_BYTES);
    }

    #[test]
    fn maps_distinct_http_statuses() {
        assert!(matches!(status_error(401), HttpError::HttpStatus(401)));
        assert!(matches!(status_error(403), HttpError::HttpStatus(403)));
        assert!(matches!(status_error(404), HttpError::HttpStatus(404)));
        assert!(matches!(status_error(503), HttpError::HttpStatus(503)));
    }

    #[test]
    fn pinned_certificate_parses_as_der() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let certs = parse_pem_certificates(pem);
        assert_eq!(certs.len(), 1);
    }
}
