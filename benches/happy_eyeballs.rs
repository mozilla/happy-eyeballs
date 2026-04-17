use std::{
    collections::{HashSet, VecDeque},
    net::{Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use happy_eyeballs::{
    CONNECTION_ATTEMPT_DELAY, ConnectionResult, DnsResult, EchConfig, FailureReason, HappyEyeballs,
    HttpVersion, Id, Input, IpPreference, NetworkConfig, Output, RESOLUTION_DELAY, ServiceInfo,
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

fn dns_https(id: Id, ipv6_hints: Vec<Ipv6Addr>, ech_config: Option<EchConfig>) -> Input {
    Input::DnsResult {
        id,
        result: DnsResult::Https(Ok(vec![ServiceInfo {
            priority: 1,
            target_name: HOSTNAME.into(),
            alpn_http_versions: HashSet::from([HttpVersion::H3, HttpVersion::H2]),
            ipv6_hints,
            ipv4_hints: vec![],
            ech_config,
            port: None,
        }])),
    }
}

fn dns_https_positive(id: Id) -> Input {
    dns_https(id, vec![], None)
}

fn dns_https_ech(id: Id) -> Input {
    dns_https(id, vec![V6_ADDR], Some(EchConfig::new(vec![1, 2, 3, 4, 5])))
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
fn drain_dns_queries(he: &mut HappyEyeballs, now: Instant) {
    while matches!(he.process_output(now), Some(Output::SendDnsQuery { .. })) {}
}

/// Feeds an HTTPS-negative result (id=0) and asserts the resulting resolution-delay timer.
fn fail_https_query(he: &mut HappyEyeballs, now: Instant) {
    he.process_input(dns_https_negative(id(0)), now);
    let output = he.process_output(now);
    assert_eq!(
        output,
        Some(Output::Timer {
            duration: RESOLUTION_DELAY
        })
    );
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

        fail_https_query(&mut he, now);

        he.process_input(dns_aaaa(id(1), Ok(vec![V6_ADDR])), now);
        let output = he.process_output(now);
        assert!(matches!(output, Some(Output::AttemptConnection { id: attempt_id, .. }) if attempt_id == id(2)));
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: CONNECTION_ATTEMPT_DELAY }));

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

        fail_https_query(&mut he, now);

        // v6 fires without waiting for A (move-on after preferred family + HTTPS done)
        he.process_input(dns_aaaa(id(1), Ok(vec![V6_ADDR])), now);
        let output = he.process_output(now);
        assert!(matches!(output, Some(Output::AttemptConnection { id: attempt_id, .. }) if attempt_id == id(3)));

        he.process_input(dns_a(id(2), Ok(vec![V4_ADDR])), now);
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: CONNECTION_ATTEMPT_DELAY }));
        now += CONNECTION_ATTEMPT_DELAY;

        let output = he.process_output(now);
        assert!(matches!(output, Some(Output::AttemptConnection { id: attempt_id, .. }) if attempt_id == id(4)));
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: CONNECTION_ATTEMPT_DELAY }));

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
///
/// HTTPS is fed while AAAA/A are still in-flight so the IPv6 hint remains
/// valid (hints are discarded once the address queries complete).
#[divan::bench]
fn https_with_ech(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        let (mut now, mut he) = setup();

        // Fed before AAAA/A complete so the hint remains valid
        he.process_input(dns_https_ech(id(0)), now);
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: RESOLUTION_DELAY }));

        now += RESOLUTION_DELAY;
        let output = he.process_output(now);
        assert!(matches!(output, Some(Output::AttemptConnection { id: attempt_id, .. }) if attempt_id == id(3)));
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Timer { duration: CONNECTION_ATTEMPT_DELAY }));

        // Succeeds before H2 attempt is started
        he.process_input(conn_success(id(3)), now);
        let output = he.process_output(now);
        assert_eq!(output, Some(Output::Succeeded));

        divan::black_box(he)
    });
}

/// Many endpoints: HTTPS with H3/H2 ALPN, 3 resolved IPv6 + 2 resolved IPv4 addresses.
///
/// Exercises `endpoints_to_attempt_domain` with a larger endpoint set
/// (3v6 + 2v4) × 2 HTTP versions = 10 endpoints, cycling through all
/// connection attempts until all fail.
#[divan::bench]
fn many_endpoints(bencher: divan::Bencher) {
    bencher.bench_local(|| {
        let (mut now, mut he) = setup();

        // All DNS fed upfront so all addresses are available at once
        he.process_input(dns_https_positive(id(0)), now);
        he.process_input(
            dns_aaaa(id(1), Ok(vec![V6_ADDR, V6_ADDR_2, V6_ADDR_3])),
            now,
        );
        he.process_input(dns_a(id(2), Ok(vec![V4_ADDR, V4_ADDR_2])), now);

        // Drive all connection attempts to failure, respecting the
        // CONNECTION_ATTEMPT_DELAY between attempts as in real usage.
        let mut in_flight = VecDeque::new();
        let result = loop {
            match he.process_output(now) {
                Some(Output::AttemptConnection { id, .. }) => in_flight.push_back(id),
                Some(Output::Timer { duration }) => {
                    now += duration;
                    if let Some(id) = in_flight.pop_front() {
                        he.process_input(conn_failure(id), now);
                    }
                }
                Some(Output::CancelConnection { .. }) => {}
                output => break output,
            }
        };
        assert_eq!(result, Some(Output::Failed(FailureReason::Connection)));

        divan::black_box(he)
    });
}
