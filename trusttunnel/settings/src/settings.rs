use serde::{Deserialize, Serialize};

pub use crate::Endpoint;

macro_rules! docgen {
    (
        $(#{doc($($args1:tt)*)})?
        $(#[$meta1:meta])*
        $vis1:vis struct $Struct:ident {
            $(
                $(#{doc($($args2:tt)*)})?
                $(#[$meta2:meta])*
                $vis2:vis $field:ident: $ty:ty,
            )*
        }
    ) => {
        $(#[doc = $($args1)*])?
        $(#[$meta1])*
        $vis1 struct $Struct {
            $(
                $(#[doc = $($args2)*])?
                $(#[$meta2])*
                $vis2 $field: $ty,
            )*
        }

        impl $Struct {
            $(
                pub fn doc() -> &'static str {
                    std::concat!($($args1)*).into()
                }
            )?

            paste::paste! {
                $(
                    $(
                        pub fn [<doc_ $field>]() -> &'static str {
                            std::concat!($($args2)*).into()
                        }
                    )?
                )*
            }
        }
    };
}

docgen! {
    #[derive(Deserialize, Serialize)]
    pub struct Settings {
        #{doc("Logging level [info, debug, trace]")}
        #[serde(default = "Settings::default_loglevel")]
        pub loglevel: String,
        #{doc(r#"VPN mode.
Defines client connections routing policy:
* general: route through a VPN endpoint all connections except ones which destinations are in exclusions,
* selective: route through a VPN endpoint only the connections which destinations are in exclusions."#)}
        #[serde(default = "Settings::default_vpn_mode")]
        pub vpn_mode: String,
        #{doc(r#"When disabled, all connection requests are routed directly to target hosts
in case connection to VPN endpoint is lost. This helps not to break an
Internet connection if user has poor connectivity to an endpoint.
When enabled, incoming connection requests which should be routed through
an endpoint will not be routed directly in that case."#)}
        #[serde(default = "Settings::default_killswitch_enabled")]
        pub killswitch_enabled: bool,
        #{doc(r#"When the kill switch is enabled, on platforms where inbound connections are blocked by the
kill switch, allow inbound connections to these local ports. An array of integers."#)}
        #[serde(default = "Settings::default_killswitch_allow_ports")]
        pub killswitch_allow_ports: Vec<u16>,
        #{doc(r#"When enabled, a post-quantum group may be used for key exchange
in TLS handshakes initiated by the VPN client."#)}
        #[serde(default = "Settings::default_post_quantum_group_enabled")]
        pub post_quantum_group_enabled: bool,
        #{doc(r#"When enabled, all TCP connections to scannable ports are initially
routed through a fake upstream to read the TLS SNI before making any real connection.
This ensures site exclusions work correctly when a secure DNS resolver is configured
outside of AdGuard VPN, or when the exclusion list contains wildcard entries (e.g. *.example.com)."#)}
        #[serde(default = "Settings::default_exclusions_tcp_early_ack_enabled")]
        pub exclusions_tcp_early_ack_enabled: bool,
        #{doc(r#"When enabled, DNS-resolvable exclusions are pre-resolved in the background after the
exclusion list is updated. This populates the suspects cache so that connections to
excluded hosts are routed correctly without waiting for the first DNS response."#)}
        #[serde(default = "Settings::default_exclusions_preresolve_enabled")]
        pub exclusions_preresolve_enabled: bool,
        #{doc(r#"Maximum number of exclusion domains to pre-resolve per cycle."#)}
        #[serde(default = "Settings::default_exclusions_preresolve_max_queries")]
        pub exclusions_preresolve_max_queries: u32,
        #{doc(r#"Comma-separated list of ports considered "scannable" for domain extraction and exclusion matching.
Supports individual ports and ranges, e.g. `443,80,8080:8090,853`.
If empty, the default list is used."#)}
        #[serde(default = "Settings::default_exclusions_scannable_ports")]
        pub exclusions_scannable_ports: String,
        #{doc(r#"Domains and addresses which should be routed in a special manner.
Supported syntax:
  * domain name
    * if starts with "*.", any subdomain of the domain will be matched including
      www-subdomain, but not the domain itself (e.g., `*.example.com` will match
      `sub.example.com`, `sub.sub.example.com`, `www.example.com`, but not `example.com`)
    * if starts with "www." or it's just a domain name, the domain itself and its
      www-subdomain will be matched (e.g. `example.com` and `www.example.com` will
      match `example.com` `www.example.com`, but not `sub.example.com`)
  * ip address
    * recognized formats are:
      * [IPv6Address]:port
      * [IPv6Address]
      * IPv6Address
      * IPv4Address:port
      * IPv4Address
    * if port is not specified, any port will be matched
  * CIDR range
    * recognized formats are:
      * IPv4Address/mask
      * IPv6Address/mask"#)}
        #[serde(default)]
        pub exclusions: Vec<String>,
        pub endpoint: Endpoint,
        #[serde(default)]
        pub listener: Listener,
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Listener {
    Socks(SocksListener),
    Tun(TunListener),
}

impl Default for Listener {
    fn default() -> Self {
        Self::Socks(Default::default())
    }
}

docgen! {
    #[derive(Default, Deserialize, Serialize)]
    pub struct SocksListener {
        #{doc("IP address to bind the listener to")}
        #[serde(default = "SocksListener::default_address")]
        pub address: String,
        #{doc("Username for authentication if desired")}
        pub username: Option<String>,
        #{doc("Password for authentication if desired")}
        pub password: Option<String>,
    }
}

docgen! {
    #[derive(Deserialize, Serialize)]
    pub struct TunListener {
        #{doc(r#"Name of the interface used for connections made by the VPN client.
On Linux, Windows and macOS, it is detected automatically if not specified.
On Windows, an interface index as shown by `route print`, written as a string, may be used instead of a name."#)}
        #[serde(default = "TunListener::default_bound_if")]
        pub bound_if: String,
        #{doc("Routes in CIDR notation to set to the virtual interface")}
        #[serde(default = "TunListener::default_included_routes")]
        pub included_routes: Vec<String>,
        #{doc("Routes in CIDR notation to exclude from routing through the virtual interface")}
        #[serde(default = "TunListener::default_excluded_routes")]
        pub excluded_routes: Vec<String>,
        #{doc("MTU size on the interface")}
        #[serde(default = "TunListener::default_mtu_size")]
        pub mtu_size: usize,
        #{doc("TCP receive window size in bytes. 0 uses optimized default (256 KB). Adjust only for constrained environments")}
        #[serde(default = "TunListener::default_tcp_recv_buf_size")]
        pub tcp_recv_buf_size: usize,
        #{doc("TCP send buffer size in bytes. 0 uses optimized default (256 KB). Adjust only for constrained environments")}
        #[serde(default = "TunListener::default_tcp_send_buf_size")]
        pub tcp_send_buf_size: usize,
        #{doc("Allow changing system DNS servers")}
        #[serde(default = "TunListener::default_change_system_dns")]
        pub change_system_dns: bool,
        #{doc(r#"TUN / Wintun device name.
On Linux: TUN interface name (empty = kernel-assigned).
On macOS: request a specific `utun<N>` unit (empty = kernel-assigned).
On Windows: Wintun adapter name (empty = auto-generated from hostname)."#)}
        #[serde(default = "TunListener::default_device_name")]
        pub device_name: String,
        #{doc("Attach to a pre-existing TUN device named `device_name` instead of creating one. Requires `device_name` to be non-empty. Linux only; ignored on Windows and macOS.")}
        #[serde(default = "TunListener::default_use_existing")]
        pub use_existing: bool,
    }
}

impl Settings {
    pub fn default_loglevel() -> String {
        "info".into()
    }

    pub fn available_vpn_modes() -> &'static [&'static str] {
        &["general", "selective"]
    }

    pub fn default_vpn_mode() -> String {
        "general".into()
    }

    pub fn default_killswitch_enabled() -> bool {
        true
    }

    pub fn default_killswitch_allow_ports() -> Vec<u16> {
        Vec::new()
    }

    pub fn default_post_quantum_group_enabled() -> bool {
        // Keep in sync with common/include/vpn/default_settings.h
        // VPN_DEFAULT_POST_QUANTUM_GROUP_ENABLED
        true
    }

    pub fn default_exclusions_tcp_early_ack_enabled() -> bool {
        // Keep in sync with common/src/default_settings.h
        // VPN_DEFAULT_EXCLUSIONS_TCP_EARLY_ACK_ENABLED
        false
    }

    pub fn default_exclusions_preresolve_enabled() -> bool {
        // Keep in sync with common/src/default_settings.h
        // VPN_DEFAULT_EXCLUSIONS_PRERESOLVE_ENABLED
        true
    }

    pub fn default_exclusions_preresolve_max_queries() -> u32 {
        // Keep in sync with common/src/default_settings.h
        // VPN_DEFAULT_EXCLUSIONS_PRERESOLVE_MAX_QUERIES
        50
    }

    pub fn default_exclusions_scannable_ports() -> String {
        // Keep in sync with common/src/default_settings.h
        // VPN_DEFAULT_EXCLUSIONS_SCANNABLE_PORTS
        "443,80,8080,8008,853".into()
    }
}

impl Listener {
    pub fn default_kind() -> String {
        "tun".into()
    }

    pub fn available_kinds() -> &'static [&'static str] {
        &["socks", "tun"]
    }

    pub fn to_kind_string(&self) -> String {
        match self {
            Listener::Socks(_) => "socks",
            Listener::Tun(_) => "tun",
        }
        .into()
    }
}

impl SocksListener {
    pub fn default_address() -> String {
        "127.0.0.1:1080".into()
    }
}

impl TunListener {
    pub fn default_bound_if() -> String {
        "".into()
    }

    pub fn default_included_routes() -> Vec<String> {
        vec!["0.0.0.0/0".into(), "2000::/3".into()]
    }

    pub fn default_excluded_routes() -> Vec<String> {
        vec![
            "0.0.0.0/8".into(),
            "10.0.0.0/8".into(),
            "169.254.0.0/16".into(),
            "172.16.0.0/12".into(),
            "192.168.0.0/16".into(),
            "224.0.0.0/3".into(),
        ]
    }
    pub fn default_mtu_size() -> usize {
        1350
    }

    pub fn default_tcp_recv_buf_size() -> usize {
        0
    }

    pub fn default_tcp_send_buf_size() -> usize {
        0
    }

    pub fn default_change_system_dns() -> bool {
        true
    }

    pub fn default_device_name() -> String {
        "".into()
    }

    pub fn default_use_existing() -> bool {
        false
    }
}
