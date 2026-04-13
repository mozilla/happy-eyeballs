use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use happy_eyeballs::{
    CONNECTION_ATTEMPT_DELAY, ConnectionResult, DnsResult, EchConfig, HappyEyeballs, HttpVersion,
    Id, Input, IpPreference, NetworkConfig, Output, RESOLUTION_DELAY, ServiceInfo,
};

fn main() {
    divan::main();
}

const HOSTNAME: &str = "example.com";
const PORT: u16 = 443;
const V6_ADDR: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const V6_ADDR_2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
const V6_ADDR_3: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);
const V4_ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const V4_ADDR_2: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

fn id(n: u64) -> Id {
    Id::from(n)
}

fn dns_https_negative(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Err(())),
    }
}

fn dns_https_ech(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv6_hints: vec![V6_ADDR],
            ipv4_hints: vec![],
            ech_config: Some(EchConfig::new(vec![1, 2, 3, 4, 5])),
            port: None,
        }])),
    }
}

fn dns_https_many(id: Id) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv6_hints: vec![V6_ADDR, V6_ADDR_2, V6_ADDR_3],
            ipv4_hints: vec![V4_ADDR, V4_ADDR_2],
            ech_config: None,
            port: None,
        }])),
    }
}

fn dns_aaaa(id: Id, addrs: Result<Vec<Ipv6Addr>, ()>) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Aaaa(addrs),
    }
}

fn dns_a(id: Id, addrs: Result<Vec<Ipv4Addr>, ()>) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::A(addrs),
    }
}

fn conn_success(id: Id) -> Input {
    Input::ConnectionResult {
        id,
        result: ConnectionResult::Success,
    }
}

fn conn_failure(id: Id) -> Input {
    Input::ConnectionResult {
        id,
        result: ConnectionResult::Failure(String::new()),
    }
}

/// Drains all initial `SendDnsQuery` outputs from the state machine.
///
/// Consumes the first non-`SendDnsQuery` output (always `None` in the current
/// state machine) to detect the end of the query sequence.
fn drain_dns_queries(he: &mut HappyEyeballs, now: Instant) {
    while matches!(he.process_output(now), Some(Output::SendDnsQuery { .. })) {}
}

fn setup() -> (Instant, HappyEyeballs) {
    setup_with_config(NetworkConfig::default())
}

fn setup_with_config(config: NetworkConfig) -> (Instant, HappyEyeballs) {
    let now = Instant::now();
    let mut he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();
    drain_dns_queries(&mut he, now);
    (now, he)
}

/// Feeds negative AAAA and A results, draining the resolution-delay timer after each.
///
/// Assumes default-config query ID assignment: HTTPS=0, AAAA=1, A=2.
fn fail_address_queries(he: &mut HappyEyeballs, now: Instant) {
    he.process_input(dns_aaaa(id(1), Err(())), now);
    let output = he.process_output(now);
    assert_eq!(
        output,
        Some(Output::Timer {
            duration: RESOLUTION_DELAY
        })
    );
    he.process_input(dns_a(id(2), Err(())), now);
    let output = he.process_output(now);
    assert_eq!(
        output,
        Some(Output::Timer {
            duration: RESOLUTION_DELAY
        })
    );
}

/// Minimal path: IPv6-only config, single address, one connection attempt.
///
/// Baseline for the per-iteration cost of the state machine.
#[divan::bench]
fn simple_ipv6_only(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        let (now, mut he) = setup_with_config(NetworkConfig {
            ip: IpPreference::Ipv6Only,
            ..NetworkConfig::default()
        });

        // HTTPS fails; state machine waits for preferred family (AAAA)
        he.process_input(dns_https_negative(id(0)), now);
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: RESOLUTION_DELAY }));

        // AAAA resolves; connection attempt fires
        he.process_input(dns_aaaa(id(1), Ok(vec![V6_ADDR])), now);
        let output = he.process_output(now);
        assert!(matches!(output, Some(Output::AttemptConnection { id: attempt_id, .. }) if attempt_id == id(2)));
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: CONNECTION_ATTEMPT_DELAY }));

        // Connection succeeds
        he.process_input(conn_success(id(2)), now);
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Succeeded));

        divan::black_box(he)
    });
}

/// Dual-stack racing: IPv6 attempt followed by IPv4 after connection delay.
///
/// Exercises connection attempt delay, address family interleaving, and
/// the fallback from a failed IPv6 attempt to a successful IPv4 attempt.
#[divan::bench]
fn dual_stack_racing(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        let (mut now, mut he) = setup();

        // HTTPS fails; state machine waits for preferred family (AAAA)
        he.process_input(dns_https_negative(id(0)), now);
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: RESOLUTION_DELAY }));

        // AAAA resolves; v6 connection attempt fires without waiting for A
        he.process_input(dns_aaaa(id(1), Ok(vec![V6_ADDR])), now);
        let output = he.process_output(now);
        assert!(matches!(output, Some(Output::AttemptConnection { id: attempt_id, .. }) if attempt_id == id(3)));

        // A resolves; connection attempt delay before v4
        he.process_input(dns_a(id(2), Ok(vec![V4_ADDR])), now);
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: CONNECTION_ATTEMPT_DELAY }));
        now += CONNECTION_ATTEMPT_DELAY;

        let output = he.process_output(now);
        assert!(matches!(output, Some(Output::AttemptConnection { id: attempt_id, .. }) if attempt_id == id(4)));
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: CONNECTION_ATTEMPT_DELAY }));

        // IPv6 fails, IPv4 succeeds
        he.process_input(conn_failure(id(3)), now);
        he.process_input(conn_success(id(4)), now);
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Succeeded));

        divan::black_box(he)
    });
}

/// HTTPS record with ECH config and H3/H2 ALPN, IPv6 hint.
///
/// Exercises ServiceInfo processing, ECH config propagation to endpoints,
/// and HTTP version splitting in `endpoints_to_attempt_domain`.
#[divan::bench]
fn https_with_ech(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        let (now, mut he) = setup();
        fail_address_queries(&mut he, now); // AAAA and A both fail; only HTTPS hints provide addresses

        // HTTPS arrives with ECH + H3+H2 ALPN + IPv6 hint
        he.process_input(dns_https_ech(id(0)), now);
        let output = he.process_output(now);
        assert!(matches!(output, Some(Output::AttemptConnection { id: attempt_id, .. }) if attempt_id == id(3)));
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: CONNECTION_ATTEMPT_DELAY }));

        // H3 attempt succeeds before H2 is started
        he.process_input(conn_success(id(3)), now);
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Succeeded));

        divan::black_box(he)
    });
}

/// HTTPS record with many endpoints: 3 IPv6 + 2 IPv4 hints, H3+H2 ALPN.
///
/// Exercises `endpoints_to_attempt_domain` with a larger endpoint set (up to
/// 10 endpoints), cycling through all connection attempts until all fail.
#[divan::bench]
fn many_endpoints(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        let (mut now, mut he) = setup();
        fail_address_queries(&mut he, now); // AAAA and A both fail; only HTTPS hints provide addresses

        // HTTPS: 3 IPv6 hints + 2 IPv4 hints, H3+H2 ALPN = up to 10 endpoints
        he.process_input(dns_https_many(id(0)), now);

        // Drive all connection attempts to failure
        loop {
            match he.process_output(now) {
                Some(Output::AttemptConnection { id, .. }) => {
                    he.process_input(conn_failure(id), now);
                }
                Some(Output::Timer { duration }) => now += duration,
                Some(Output::CancelConnection { .. }) => {}
                None
                | Some(Output::Succeeded | Output::Failed(_) | Output::SendDnsQuery { .. }) => {
                    break;
                }
            }
        }

        divan::black_box(he)
    });
}
