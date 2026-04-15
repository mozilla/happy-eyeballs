#![allow(dead_code)]

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Instant,
};

use happy_eyeballs::{
    CONNECTION_ATTEMPT_DELAY, ConnectionAttemptHttpVersions, ConnectionResult, DnsRecordType,
    DnsResult, EchConfig, Endpoint, HappyEyeballs, HttpSettings, HttpVersion, Id, Input,
    NetworkConfig, Output, ProtocolSessionResult, RESOLUTION_DELAY, ServiceInfo, Session,
};

pub const HOSTNAME: &str = "example.com";
pub const SVC1: &str = "svc1.example.com.";
pub const PORT: u16 = 443;
pub const CUSTOM_PORT: u16 = 8443;
pub const V6_ADDR: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
pub const V6_ADDR_2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
pub const V6_ADDR_3: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);
pub const V4_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub const V4_ADDR_2: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
pub const ECH_CONFIG_BYTES: &[u8] = &[1, 2, 3, 4, 5];

pub fn ech_config() -> EchConfig {
    EchConfig::new(ECH_CONFIG_BYTES.to_vec())
}

pub trait HappyEyeballsExt {
    fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant);
    fn expect_connection_attempts(&mut self, now: &mut Instant, connections: Vec<Output>);
}

impl HappyEyeballsExt for HappyEyeballs {
    fn expect(&mut self, input_output: Vec<(Option<Input>, Option<Output>)>, now: Instant) {
        for (input, expected_output) in input_output {
            if let Some(input) = input {
                self.process_input(input, now);
            }
            let output = self.process_output(now);
            assert_eq!(expected_output, output);
        }
    }

    fn expect_connection_attempts(&mut self, now: &mut Instant, connections: Vec<Output>) {
        for conn in connections {
            *now += CONNECTION_ATTEMPT_DELAY;
            self.expect(
                vec![
                    (None, Some(conn)),
                    (None, Some(out_connection_attempt_delay())),
                ],
                *now,
            );
        }
        *now += CONNECTION_ATTEMPT_DELAY;
        self.expect(vec![(None, None)], *now);
    }
}

pub fn in_dns_https_positive(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv6_hints: vec![],
            ipv4_hints: vec![],
            ech_config: None,
            port: None,
        }])),
    }
}

pub fn in_dns_https_positive_ech(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv6_hints: vec![],
            ipv4_hints: vec![],
            ech_config: Some(ech_config()),
            port: None,
        }])),
    }
}

pub fn in_dns_https_positive_no_alpn(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::new(),
            ipv6_hints: vec![],
            ipv4_hints: vec![],
            ech_config: None,
            port: None,
        }])),
    }
}

fn in_dns_https_with_hints(id: Id, ipv4_hints: Vec<Ipv4Addr>, ipv6_hints: Vec<Ipv6Addr>) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv4_hints,
            ipv6_hints,
            ech_config: None,
            port: None,
        }])),
    }
}

pub fn in_dns_https_positive_v6_hints(id: Id) -> Input {
    in_dns_https_with_hints(id, vec![], vec![V6_ADDR])
}

pub fn in_dns_https_positive_v4_hints(id: Id) -> Input {
    in_dns_https_with_hints(id, vec![V4_ADDR], vec![])
}

pub fn in_dns_https_positive_v4_and_v6_hints(id: Id) -> Input {
    in_dns_https_with_hints(id, vec![V4_ADDR], vec![V6_ADDR])
}

pub fn in_dns_https_positive_svc1(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: SVC1.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv6_hints: vec![V6_ADDR_2],
            ipv4_hints: vec![],
            ech_config: None,
            port: None,
        }])),
    }
}

pub fn in_dns_https_negative(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Err(())),
    }
}

pub fn in_dns_aaaa_positive(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Aaaa(Ok(vec![V6_ADDR])),
    }
}

pub fn in_dns_a_positive(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::A(Ok(vec![V4_ADDR])),
    }
}

pub fn in_dns_aaaa_negative(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Aaaa(Err(())),
    }
}

pub fn in_dns_a_negative(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::A(Err(())),
    }
}

pub fn in_connection_result_positive(id: Id) -> Input {
    in_connection_result_positive_with_version(id, HttpVersion::H2)
}

pub fn in_connection_result_positive_with_version(id: Id, http_version: HttpVersion) -> Input {
    Input::ConnectionResult {
        id,
        result: ConnectionResult::Success { http_version },
    }
}

pub fn in_connection_result_negative(id: Id) -> Input {
    Input::ConnectionResult {
        id,
        result: ConnectionResult::Failure("connection refused".to_string()),
    }
}

pub fn in_connection_result_ech_retry(id: Id) -> Input {
    Input::ConnectionResult {
        id,
        result: ConnectionResult::EchRetry(ech_config()),
    }
}

pub fn out_send_dns_https(id: Id) -> Output {
    Output::SendDnsQuery {
        id,
        hostname: HOSTNAME.into(),
        record_type: DnsRecordType::Https,
    }
}

pub fn out_send_dns_aaaa(id: Id) -> Output {
    Output::SendDnsQuery {
        id,
        hostname: HOSTNAME.into(),
        record_type: DnsRecordType::Aaaa,
    }
}

pub fn out_send_dns_svc1(id: Id) -> Output {
    Output::SendDnsQuery {
        id,
        hostname: SVC1.into(),
        record_type: DnsRecordType::Aaaa,
    }
}

pub fn out_send_dns_a(id: Id) -> Output {
    Output::SendDnsQuery {
        id,
        hostname: HOSTNAME.into(),
        record_type: DnsRecordType::A,
    }
}

pub fn out_attempt_v6_h1_h2(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H2OrH1,
            ech_config: None,
        },
    }
}

pub fn out_attempt_v6_h2(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: None,
        },
    }
}

pub fn out_attempt_v6_h3(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H3,
            ech_config: None,
        },
    }
}

pub fn out_attempt_v6_h3_custom_port(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), CUSTOM_PORT),
            http_version: ConnectionAttemptHttpVersions::H3,
            ech_config: None,
        },
    }
}

pub fn out_attempt_v4_h1_h2(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H2OrH1,
            ech_config: None,
        },
    }
}

pub fn out_attempt_v4_h2(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: None,
        },
    }
}

pub fn out_attempt_v4_h3(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), PORT),
            http_version: ConnectionAttemptHttpVersions::H3,
            ech_config: None,
        },
    }
}

pub fn out_attempt_v4_h3_custom_port(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), CUSTOM_PORT),
            http_version: ConnectionAttemptHttpVersions::H3,
            ech_config: None,
        },
    }
}

pub fn out_attempt_v6_h2_custom_port(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V6_ADDR.into(), CUSTOM_PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: None,
        },
    }
}

pub fn out_attempt_v4_h2_custom_port(id: Id) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(V4_ADDR.into(), CUSTOM_PORT),
            http_version: ConnectionAttemptHttpVersions::H2,
            ech_config: None,
        },
    }
}

pub fn out_attempt(
    id: Id,
    addr: IpAddr,
    port: u16,
    http_version: ConnectionAttemptHttpVersions,
) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            address: SocketAddr::new(addr, port),
            http_version,
            ech_config: None,
        },
    }
}

pub fn out_resolution_delay() -> Output {
    Output::Timer {
        duration: RESOLUTION_DELAY,
    }
}

pub fn out_connection_attempt_delay() -> Output {
    Output::Timer {
        duration: CONNECTION_ATTEMPT_DELAY,
    }
}

pub fn in_http_settings(id: Id, extended_connect: bool, webtransport: bool) -> Input {
    Input::HttpSettings {
        id,
        settings: HttpSettings {
            extended_connect_supported: extended_connect,
            webtransport_supported: webtransport,
        },
    }
}

pub fn in_http_settings_extended_connect(id: Id) -> Input {
    in_http_settings(id, true, false)
}

pub fn in_http_settings_webtransport(id: Id) -> Input {
    in_http_settings(id, true, true)
}

pub fn in_http_settings_no_extended_connect(id: Id) -> Input {
    in_http_settings(id, false, false)
}

pub fn in_session_result_success(id: Id) -> Input {
    Input::ProtocolSessionResult {
        id,
        result: ProtocolSessionResult::Success,
    }
}

pub fn in_session_result_failure(id: Id) -> Input {
    Input::ProtocolSessionResult {
        id,
        result: ProtocolSessionResult::Failure,
    }
}

pub fn out_establish_websocket(id: Id) -> Output {
    Output::EstablishProtocolSession {
        id,
        session: Session::WebSocket,
    }
}

pub fn out_establish_webtransport(id: Id) -> Output {
    Output::EstablishProtocolSession {
        id,
        session: Session::WebTransport,
    }
}

/// Send DNS queries, provide HTTPS negative + AAAA positive + A negative,
/// arrive at the first connection attempt.
///
/// Assumes default dual-stack-prefer-v6 with HOSTNAME.
pub fn dns_phase_aaaa_only(
    he: &mut HappyEyeballs,
    now: Instant,
    expected_attempt: Output,
) {
    he.expect(
        vec![
            (None, Some(out_send_dns_https(Id::from(0)))),
            (None, Some(out_send_dns_aaaa(Id::from(1)))),
            (None, Some(out_send_dns_a(Id::from(2)))),
            (
                Some(in_dns_aaaa_positive(Id::from(1))),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_a_negative(Id::from(2))),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_https_negative(Id::from(0))),
                Some(expected_attempt),
            ),
        ],
        now,
    );
}

/// Send DNS queries, provide HTTPS positive + AAAA positive + A negative.
/// For tests that need HTTPS service records (e.g. H3).
pub fn dns_phase_aaaa_only_https_positive(
    he: &mut HappyEyeballs,
    now: Instant,
    expected_attempt: Output,
) {
    he.expect(
        vec![
            (None, Some(out_send_dns_https(Id::from(0)))),
            (None, Some(out_send_dns_aaaa(Id::from(1)))),
            (None, Some(out_send_dns_a(Id::from(2)))),
            (
                Some(in_dns_aaaa_positive(Id::from(1))),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_a_negative(Id::from(2))),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_https_positive(Id::from(0))),
                Some(expected_attempt),
            ),
        ],
        now,
    );
}

/// Send DNS queries, provide HTTPS negative + AAAA positive + A positive.
/// Two endpoints available (v6 + v4), expects connection attempt delay after
/// the first attempt.
pub fn dns_phase_aaaa_and_a(
    he: &mut HappyEyeballs,
    now: Instant,
    expected_attempt: Output,
) {
    he.expect(
        vec![
            (None, Some(out_send_dns_https(Id::from(0)))),
            (None, Some(out_send_dns_aaaa(Id::from(1)))),
            (None, Some(out_send_dns_a(Id::from(2)))),
            (
                Some(in_dns_aaaa_positive(Id::from(1))),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_a_positive(Id::from(2))),
                Some(out_resolution_delay()),
            ),
            (
                Some(in_dns_https_negative(Id::from(0))),
                Some(expected_attempt),
            ),
            (None, Some(out_connection_attempt_delay())),
        ],
        now,
    );
}

pub fn setup() -> (Instant, HappyEyeballs) {
    setup_with_config(NetworkConfig::default())
}

pub fn setup_with_config(config: NetworkConfig) -> (Instant, HappyEyeballs) {
    let _ = env_logger::builder().is_test(true).try_init();
    let now = Instant::now();
    let he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();
    (now, he)
}
