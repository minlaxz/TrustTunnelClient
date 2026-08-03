pub use trusttunnel_settings::{Endpoint, Listener, Settings, SocksListener, TunListener};

use crate::user_interaction::{
    ask_for_agreement, ask_for_agreement_with_default, ask_for_input, ask_for_input_raw_line,
    ask_for_password, select_variant,
};
use crate::Mode;
use serde::Deserialize;
use std::fmt;
use std::fs;
use std::ops::Not;
use x509_parser::extensions::GeneralName;

macro_rules! opt_field {
    ($x:expr, $field:ident) => {
        $x.map(|x| &x.$field)
    };
}

pub fn build(template: Option<&Settings>) -> Settings {
    Settings {
        loglevel: opt_field!(template, loglevel)
            .cloned()
            .unwrap_or_else(Settings::default_loglevel),
        vpn_mode: select_variant(
            format!("{}\n", Settings::doc_vpn_mode()),
            Settings::available_vpn_modes(),
            Settings::available_vpn_modes().iter().position(|x| {
                *x == opt_field!(template, vpn_mode)
                    .cloned()
                    .unwrap_or_else(Settings::default_vpn_mode)
                    .as_str()
            }),
        )
        .into(),
        killswitch_enabled: opt_field!(template, killswitch_enabled)
            .cloned()
            .unwrap_or_else(Settings::default_killswitch_enabled),
        killswitch_allow_ports: opt_field!(template, killswitch_allow_ports)
            .cloned()
            .unwrap_or_else(Settings::default_killswitch_allow_ports),
        post_quantum_group_enabled: opt_field!(template, post_quantum_group_enabled)
            .cloned()
            .unwrap_or_else(Settings::default_post_quantum_group_enabled),
        exclusions_tcp_early_ack_enabled: opt_field!(template, exclusions_tcp_early_ack_enabled)
            .cloned()
            .unwrap_or_else(Settings::default_exclusions_tcp_early_ack_enabled),
        exclusions_preresolve_enabled: opt_field!(template, exclusions_preresolve_enabled)
            .cloned()
            .unwrap_or_else(Settings::default_exclusions_preresolve_enabled),
        exclusions_preresolve_max_queries: opt_field!(template, exclusions_preresolve_max_queries)
            .cloned()
            .unwrap_or_else(Settings::default_exclusions_preresolve_max_queries),
        exclusions_scannable_ports: opt_field!(template, exclusions_scannable_ports)
            .cloned()
            .unwrap_or_else(Settings::default_exclusions_scannable_ports),
        exclusions: opt_field!(template, exclusions)
            .cloned()
            .unwrap_or_default(),
        endpoint: build_endpoint(opt_field!(template, endpoint)),
        listener: build_listener(opt_field!(template, listener)),
    }
}

fn build_endpoint(template: Option<&Endpoint>) -> Endpoint {
    let predefined_params = crate::get_predefined_params().clone();

    // Deep-link import: if provided via CLI, decode and return immediately
    if let Some(ref deeplink_uri) = predefined_params.deeplink {
        return endpoint_from_deeplink(deeplink_uri);
    }

    // In interactive mode, offer a choice between config file and deep-link
    let endpoint_config: Option<EndpointConfig> =
        if crate::get_mode() == Mode::Interactive && predefined_params.endpoint_config.is_none() {
            let selection = crate::user_interaction::select_index(
                "How would you like to provide endpoint configuration?",
                &["Endpoint config file", "Deep-link URI (tt://...)"],
                Some(0),
            );
            match selection {
                0 => {
                    // Endpoint config file path
                    empty_to_none(ask_for_input(
                        "Path to endpoint config, empty if no",
                        Some("".to_string()),
                    ))
                    .and_then(|x| {
                        fs::read_to_string(&x)
                            .map_err(|e| panic!("Failed to read endpoint config file:\n{}", e))
                            .ok()
                    })
                    .and_then(|x| {
                        toml::de::from_str(x.as_str())
                            .map_err(|e| panic!("Failed to parse endpoint config:\n{}", e))
                            .ok()
                    })
                }
                1 => {
                    // Deep-link URI
                    let uri = ask_for_input_raw_line("Paste deep-link URI");
                    return endpoint_from_deeplink(&uri);
                }
                _ => unreachable!(),
            }
        } else {
            empty_to_none(ask_for_input(
                "Path to endpoint config, empty if no",
                predefined_params.endpoint_config.or(Some("".to_string())),
            ))
            .and_then(|x| {
                fs::read_to_string(&x)
                    .map_err(|e| panic!("Failed to read endpoint config file:\n{}", e))
                    .ok()
            })
            .and_then(|x| {
                toml::de::from_str(x.as_str())
                    .map_err(|e| panic!("Failed to parse endpoint config:\n{}", e))
                    .ok()
            })
        };
    let mut x = Endpoint {
        addresses: endpoint_config
            .as_ref()
            .and_then(|x| x.addresses.clone().into())
            .or_else(|| {
                ask_for_input::<String>(
                    &format!(
                        "{}\nMust be delimited by whitespace.\n",
                        Endpoint::doc_addresses()
                    ),
                    predefined_params
                        .endpoint_addresses
                        .or(opt_field!(template, addresses).cloned())
                        .map(|x| x.join(" ")),
                )
                .split_whitespace()
                .map(String::from)
                .collect::<Vec<String>>()
                .into()
            })
            .unwrap(),
        has_ipv6: endpoint_config
            .as_ref()
            .and_then(|x| x.has_ipv6.into())
            .or(opt_field!(template, has_ipv6).cloned())
            .unwrap_or_else(Endpoint::default_has_ipv6),
        username: endpoint_config
            .as_ref()
            .and_then(|x| x.username.clone().into())
            .or_else(|| {
                ask_for_input(
                    Endpoint::doc_username(),
                    predefined_params
                        .credentials
                        .clone()
                        .unzip()
                        .0
                        .or(opt_field!(template, username).cloned()),
                )
                .into()
            })
            .unwrap(),
        password: endpoint_config
            .as_ref()
            .and_then(|x| x.password.clone().into())
            .or_else(|| {
                predefined_params
                    .credentials
                    .unzip()
                    .1
                    .unwrap_or_else(|| {
                        opt_field!(template, password)
                            .cloned()
                            .and_then(empty_to_none)
                            .and_then(|x| {
                                ask_for_agreement("Overwrite password?").not().then_some(x)
                            })
                            .unwrap_or_else(|| ask_for_password(Endpoint::doc_password()))
                    })
                    .into()
            })
            .unwrap(),
        client_random: endpoint_config
            .as_ref()
            .and_then(|x| x.client_random.clone().into())
            .or(opt_field!(template, client_random).cloned())
            .unwrap_or_default(),
        skip_verification: endpoint_config
            .as_ref()
            .and_then(|x| x.skip_verification.into())
            .or(opt_field!(template, skip_verification).cloned())
            .unwrap_or_else(Endpoint::default_skip_verification),
        upstream_protocol: endpoint_config
            .as_ref()
            .and_then(|x| x.upstream_protocol.clone().into())
            .or(opt_field!(template, upstream_protocol).cloned())
            .unwrap_or_else(Endpoint::default_upstream_protocol),
        anti_dpi: endpoint_config
            .as_ref()
            .and_then(|x| x.anti_dpi.into())
            .or(opt_field!(template, anti_dpi).cloned())
            .unwrap_or_else(Endpoint::default_anti_dpi),
        custom_sni: endpoint_config
            .as_ref()
            .and_then(|x| empty_to_none(x.custom_sni.clone()))
            .unwrap_or_default(),
        dns_upstreams: endpoint_config
            .as_ref()
            .map(|x| x.dns_upstreams.clone())
            .or_else(|| {
                ask_for_input::<String>(
                    &format!(
                        "{}\nDelimit by whitespace, leave empty for default.",
                        Endpoint::doc_dns_upstreams()
                    ),
                    opt_field!(template, dns_upstreams)
                        .map(|v| v.join(" "))
                        .or(Some("".to_string())),
                )
                .split_whitespace()
                .map(String::from)
                .collect::<Vec<String>>()
                .into()
            })
            .unwrap_or_default(),
        ..Default::default()
    };

    if let Some(config) = &endpoint_config {
        x.hostname = config.hostname.clone();
        x.certificate = empty_to_none(config.certificate.clone());
    } else {
        let (hostname, certificate) = if crate::get_mode() == Mode::NonInteractive {
            (
                predefined_params.hostname.clone(),
                predefined_params.certificate.and_then(|x| {
                    fs::read_to_string(&x)
                        .expect("Failed to read certificate")
                        .into()
                }),
            )
        } else if let Some(cert) = opt_field!(template, certificate)
            .cloned()
            .flatten()
            .and_then(parse_cert)
            .and_then(|x| {
                ask_for_agreement(&format!("Use an existent certificate? {:?}", x)).then_some(x)
            })
        {
            (
                Some(cert.common_name),
                opt_field!(template, certificate).cloned().flatten(),
            )
        } else if let Some(cert) = empty_to_none(ask_for_input::<String>(
            &format!(
                "{}\nEnter a path to certificate:",
                Endpoint::doc_certificate()
            ),
            Some("".into()),
        )) {
            let contents = fs::read_to_string(&cert).expect("Failed to read certificate");
            match parse_cert(contents.clone()) {
                Some(parsed) => (Some(parsed.common_name), Some(contents)),
                None => {
                    panic!("Couldn't parse provided certificate");
                }
            }
        } else {
            (None, None)
        };

        x.hostname = ask_for_input(
            Endpoint::doc_hostname(),
            predefined_params
                .hostname
                .or(opt_field!(template, hostname).cloned())
                .or(hostname),
        );
        x.custom_sni = empty_to_none(ask_for_input(
            &format!("{}\nLeave empty if not needed.", Endpoint::doc_custom_sni()),
            predefined_params
                .custom_sni
                .or(opt_field!(template, custom_sni).cloned())
                .or(Some("".to_string())),
        ))
        .unwrap_or_default();
        x.certificate = certificate;
    }

    if x.certificate.is_some() {
        parse_cert(x.certificate.clone().unwrap()).expect("Couldn't parse provided certificate");
    }

    if endpoint_config.is_none() {
        x.skip_verification = x.certificate.is_none()
            && ask_for_agreement_with_default(
                &format!("{}\n", Endpoint::doc_skip_verification()),
                opt_field!(template, skip_verification)
                    .cloned()
                    .unwrap_or_default(),
            );
    }

    x
}

fn build_listener(template: Option<&Listener>) -> Listener {
    match select_variant(
        r#"Listener type:
    * socks: SOCKS5 proxy with UDP support,
    * tun: TUN device.
"#,
        Listener::available_kinds(),
        Listener::available_kinds().iter().position(|x| {
            *x == template
                .map(Listener::to_kind_string)
                .unwrap_or_else(Listener::default_kind)
                .as_str()
        }),
    ) {
        "socks" => {
            let template = template.and_then(|x| match x {
                Listener::Socks(x) => Some(x),
                _ => None,
            });
            Listener::Socks(SocksListener {
                address: ask_for_input(
                    SocksListener::doc_address(),
                    Some(
                        opt_field!(template, address)
                            .cloned()
                            .unwrap_or_else(SocksListener::default_address),
                    ),
                ),
                username: empty_to_none(ask_for_input(
                    SocksListener::doc_username(),
                    Some(
                        opt_field!(template, username)
                            .cloned()
                            .flatten()
                            .unwrap_or_default(),
                    ),
                )),
                password: empty_to_none(ask_for_input(
                    SocksListener::doc_password(),
                    Some(
                        opt_field!(template, password)
                            .cloned()
                            .flatten()
                            .unwrap_or_default(),
                    ),
                )),
            })
        }
        "tun" => {
            let template = template.and_then(|x| match x {
                Listener::Tun(x) => Some(x),
                _ => None,
            });
            Listener::Tun(TunListener {
                bound_if: if cfg!(target_os = "windows") {
                    Default::default()
                } else {
                    ask_for_input(
                        TunListener::doc_bound_if(),
                        Some(
                            opt_field!(template, bound_if)
                                .cloned()
                                .unwrap_or_else(TunListener::default_bound_if),
                        ),
                    )
                },
                included_routes: opt_field!(template, included_routes)
                    .cloned()
                    .unwrap_or_else(TunListener::default_included_routes),
                excluded_routes: opt_field!(template, excluded_routes)
                    .cloned()
                    .unwrap_or_else(TunListener::default_excluded_routes),
                mtu_size: opt_field!(template, mtu_size)
                    .cloned()
                    .unwrap_or_else(TunListener::default_mtu_size),
                tcp_recv_buf_size: opt_field!(template, tcp_recv_buf_size)
                    .cloned()
                    .unwrap_or_else(TunListener::default_tcp_recv_buf_size),
                tcp_send_buf_size: opt_field!(template, tcp_send_buf_size)
                    .cloned()
                    .unwrap_or_else(TunListener::default_tcp_send_buf_size),
                change_system_dns: ask_for_agreement_with_default(
                    &format!("{}\n", TunListener::doc_change_system_dns()),
                    opt_field!(template, change_system_dns)
                        .cloned()
                        .unwrap_or_else(TunListener::default_change_system_dns),
                ),
                device_name: opt_field!(template, device_name)
                    .cloned()
                    .unwrap_or_else(TunListener::default_device_name),
                use_existing: opt_field!(template, use_existing)
                    .cloned()
                    .unwrap_or_else(TunListener::default_use_existing),
            })
        }
        _ => unreachable!(),
    }
}

fn empty_to_none(str: String) -> Option<String> {
    str.is_empty().not().then_some(str)
}

#[derive(Deserialize, Debug)]
pub struct EndpointConfig {
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    has_ipv6: bool,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default, alias = "client_random_prefix")]
    client_random: String,
    #[serde(default)]
    skip_verification: bool,
    #[serde(default)]
    certificate: String,
    #[serde(default)]
    upstream_protocol: String,
    #[serde(default)]
    anti_dpi: bool,
    #[serde(default)]
    custom_sni: String,
    #[serde(default)]
    dns_upstreams: Vec<String>,
}

#[derive(Debug)]
struct Cert {
    common_name: String,
    #[allow(dead_code)] // needed only for logging
    alt_names: Vec<String>,
    #[allow(dead_code)] // needed only for logging
    expiration_date: String,
}

fn parse_cert(contents: String) -> Option<Cert> {
    let cert = rustls_pemfile::certs(&mut contents.as_bytes())
        .ok()?
        .into_iter()
        .map(rustls::Certificate)
        .next()?;
    let cert = x509_parser::parse_x509_certificate(&cert.0).ok()?.1;
    Some(Cert {
        common_name: cert.validity.is_valid().then(|| {
            let x = cert.subject.to_string();
            x.as_str()
                .strip_prefix("CN=")
                .map(String::from)
                .unwrap_or(x)
        })?,
        alt_names: cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|x| {
                x.value
                    .general_names
                    .iter()
                    .map(GeneralName::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        expiration_date: cert.validity.not_after.to_string(),
    })
}

#[derive(Debug)]
pub struct CertInfo {
    pub common_name: String,
    pub expiration_date: String,
}

/// Helper struct for pretty-printing Endpoint
pub struct EndpointSummary<'a> {
    endpoint: &'a Endpoint,
    cert_infos: &'a [CertInfo],
}

impl<'a> EndpointSummary<'a> {
    pub fn new(endpoint: &'a Endpoint, cert_infos: &'a [CertInfo]) -> Self {
        Self {
            endpoint,
            cert_infos,
        }
    }
}

impl fmt::Display for EndpointSummary<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ep = self.endpoint;

        let addresses = ep.addresses.join(", ");
        let custom_sni = if ep.custom_sni.is_empty() {
            "(none)"
        } else {
            &ep.custom_sni
        };
        let client_random = if ep.client_random.is_empty() {
            "(none)"
        } else {
            &ep.client_random
        };

        let cert_display = if self.cert_infos.is_empty() {
            if ep.certificate.is_some() {
                "(present)".to_string()
            } else {
                "(none)".to_string()
            }
        } else {
            self.cert_infos
                .iter()
                .map(|c| format!("CN={} (expires {})", c.common_name, c.expiration_date))
                .collect::<Vec<_>>()
                .join("\n                     ")
        };

        let dns_upstreams = if ep.dns_upstreams.is_empty() {
            "(default: AdGuard DNS unfiltered)".to_string()
        } else {
            ep.dns_upstreams.join(", ")
        };

        write!(
            f,
            "
  Hostname:          {}
  Addresses:         {}
  Custom SNI:        {}
  IPv6:              {}
  Username:          {}
  Password:          ******
  Client random:     {}
  Skip verification: {}
  Certificate:       {}
  Protocol:          {}
  Anti-DPI:          {}
  DNS upstreams:       {}",
            ep.hostname,
            addresses,
            custom_sni,
            if ep.has_ipv6 { "yes" } else { "no" },
            ep.username,
            client_random,
            if ep.skip_verification { "yes" } else { "no" },
            cert_display,
            ep.upstream_protocol,
            if ep.anti_dpi { "yes" } else { "no" },
            dns_upstreams,
        )
    }
}

fn verify_deeplink_certificates(der_bytes: &[u8]) -> Vec<CertInfo> {
    let pem = trusttunnel_deeplink::cert::der_to_pem(der_bytes)
        .expect("Failed to convert deep-link certificate from DER to PEM");

    let certs = rustls_pemfile::certs(&mut pem.as_bytes())
        .expect("Failed to parse PEM certificates from deep-link");

    if certs.is_empty() {
        panic!("Deep-link certificate field contains no valid certificates");
    }

    let mut cert_infos = Vec::new();
    for (i, cert_der) in certs.iter().enumerate() {
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref())
            .unwrap_or_else(|e| panic!("Failed to parse certificate #{}: {}", i + 1, e));

        if !cert.validity.is_valid() {
            panic!(
                "Certificate #{} (CN={}) is not valid: not_before={}, not_after={}",
                i + 1,
                cert.subject,
                cert.validity.not_before,
                cert.validity.not_after
            );
        }

        let cn = {
            let subj = cert.subject.to_string();
            subj.strip_prefix("CN=").map(String::from).unwrap_or(subj)
        };

        cert_infos.push(CertInfo {
            common_name: cn,
            expiration_date: cert.validity.not_after.to_string(),
        });
    }

    cert_infos
}

fn display_and_confirm_endpoint(endpoint: &Endpoint, cert_infos: &[CertInfo]) {
    println!("{}\n", EndpointSummary::new(endpoint, cert_infos));

    if crate::get_mode() == Mode::Interactive
        && !ask_for_agreement_with_default("Accept this configuration?", false)
    {
        eprintln!("Deep-link configuration declined by user.");
        std::process::exit(1);
    }
}

pub fn endpoint_from_deeplink(uri: &str) -> Endpoint {
    let config = trusttunnel_deeplink::decode(uri)
        .unwrap_or_else(|e| panic!("Failed to decode deep-link URI: {}", e));

    let cert_infos = config
        .certificate
        .as_ref()
        .map(|der| verify_deeplink_certificates(der))
        .unwrap_or_default();

    let endpoint = trusttunnel_settings::endpoint_from_deeplink_config(config)
        .unwrap_or_else(|e| panic!("Failed to convert deep-link config: {}", e));

    display_and_confirm_endpoint(&endpoint, &cert_infos);

    endpoint
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusttunnel_deeplink::{DeepLinkConfig, Protocol};

    #[test]
    fn test_deeplink_field_mapping() {
        // Encode a config, then decode it and verify the field mapping
        let config = DeepLinkConfig {
            hostname: Some("test.host".to_string()),
            addresses: vec![
                "10.0.0.1:443".parse().unwrap(),
                "[::1]:8443".parse().unwrap(),
            ],
            username: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            client_random_prefix: Some("aabb".to_string()),
            custom_sni: Some("sni.host".to_string()),
            has_ipv6: false,
            skip_verification: true,
            certificate: None,
            upstream_protocol: Protocol::Http3,
            anti_dpi: true,
            dns_upstreams: vec!["tls://dns.adguard-dns.com".to_string()],
            name: Some("Example VPN".to_string()),
            subscription_url: None,
        };

        let uri = trusttunnel_deeplink::encode(&config).unwrap();
        let decoded = trusttunnel_deeplink::decode(&uri).unwrap();

        assert_eq!(decoded.hostname.as_deref(), Some("test.host"));
        assert_eq!(decoded.addresses.len(), 2);
        assert_eq!(decoded.username.as_deref(), Some("user1"));
        assert_eq!(decoded.password.as_deref(), Some("pass1"));
        assert_eq!(decoded.client_random_prefix, Some("aabb".to_string()));
        assert_eq!(decoded.custom_sni, Some("sni.host".to_string()));
        assert!(!decoded.has_ipv6);
        assert!(decoded.skip_verification);
        assert!(decoded.certificate.is_none());
        assert_eq!(decoded.upstream_protocol, Protocol::Http3);
        assert!(decoded.anti_dpi);
    }

    #[test]
    fn test_verify_deeplink_certificates_empty() {
        let result = std::panic::catch_unwind(|| verify_deeplink_certificates(&[]));
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_deeplink_certificates_invalid_der() {
        let result = std::panic::catch_unwind(|| verify_deeplink_certificates(&[0xFF, 0x00, 0x01]));
        assert!(result.is_err());
    }

    #[test]
    fn endpoint_config_reads_client_random_prefix() {
        let toml_str = r#"
hostname = "vpn.example.com"
addresses = ["1.2.3.4:443"]
username = "alice"
password = "s3cr3t"
client_random_prefix = "aabb/16"
"#;
        let config: EndpointConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.client_random, "aabb/16");
    }

    #[test]
    fn endpoint_config_still_reads_client_random() {
        let toml_str = "client_random = \"ccdd\"\n";
        let config: EndpointConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.client_random, "ccdd");
    }
}
