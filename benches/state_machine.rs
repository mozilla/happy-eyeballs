//! Benchmarks for the Happy Eyeballs v3 state machine.
//!
//! The crate is a pure, deterministic state machine: the caller feeds it
//! [`Input`]s and drains [`Output`]s. Every benchmark therefore drives a
//! complete connection establishment, from the first DNS query to the final
//! `Succeeded`/`Failed` output, using a small in-benchmark driver that answers
//! DNS queries and connection attempts from a canned scenario.
//!
//! The scenarios cover the paths that matter in production: plain dual-stack
//! resolution, HTTPS (SVCB) records with alternative target names, large
//! address sets (endpoint flattening, interleaving and racing), failing races,
//! ECH retries, Optimistic DNS revalidation, the by-name resolution modes and
//! alt-svc.

use std::{
    collections::VecDeque,
    hint::black_box,
    net::{Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use divan::Bencher;
use happy_eyeballs::{
    AltSvc, ConnectionResult, DnsRecordType, DnsResult, EchConfig, HappyEyeballs, HttpVersion,
    HttpVersions, Input, IpPreference, NetworkConfig, Output, ResolutionMode, ServiceInfo,
};

fn main() {
    divan::main();
}

const HOSTNAME: &str = "example.com";
const SVC1: &str = "svc1.example.com.";
const SVC2: &str = "svc2.example.com.";
const PORT: u16 = 443;

/// Upper bound on driver iterations, so a scenario can never spin forever
/// inside a benchmark.
const MAX_STEPS: usize = 100_000;

fn v6(n: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)
}

fn v4(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, n)
}

fn v6_addrs(count: u16) -> Vec<Ipv6Addr> {
    (1..=count).map(v6).collect()
}

fn v4_addrs(count: u8) -> Vec<Ipv4Addr> {
    (1..=count).map(v4).collect()
}

fn ech_config() -> EchConfig {
    EchConfig::new(vec![1, 2, 3, 4, 5, 6, 7, 8])
}

fn service_info(priority: u16, target_name: &str, alpns: &[HttpVersion]) -> ServiceInfo {
    ServiceInfo {
        priority,
        target_name: target_name.into(),
        alpn_http_versions: alpns.iter().copied().collect(),
        ech_config: None,
        ipv4_hints: vec![],
        ipv6_hints: vec![],
        port: None,
    }
}

/// How the driver answers connection attempts.
#[derive(Clone, Copy)]
enum Connections {
    /// The nth attempt (0-based) succeeds; every earlier attempt fails.
    SucceedOn(usize),
    /// Every attempt fails, so the whole race runs to exhaustion.
    AllFail,
    /// The first attempt is rejected with an ECH `retry_config`; the retry to
    /// the same endpoint then succeeds.
    EchRetryThenSuccess,
}

/// A canned set of DNS answers and connection results, plus the network
/// configuration the state machine runs with.
struct Scenario {
    config: NetworkConfig,
    /// Answer to every HTTPS (SVCB) query, or `None` to leave it unanswered.
    https: Option<Result<Vec<ServiceInfo>, ()>>,
    /// Answer to every AAAA query.
    aaaa: Result<Vec<Ipv6Addr>, ()>,
    /// Answer to every A query.
    a: Result<Vec<Ipv4Addr>, ()>,
    /// Whether the resolver answers from a stale cache entry when the query
    /// allows it (Optimistic DNS).
    stale: bool,
    connections: Connections,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            config: NetworkConfig::default(),
            https: Some(Ok(vec![service_info(
                1,
                HOSTNAME,
                &[HttpVersion::H3, HttpVersion::H2, HttpVersion::H1],
            )])),
            aaaa: Ok(v6_addrs(1)),
            a: Ok(v4_addrs(1)),
            stale: false,
            connections: Connections::SucceedOn(0),
        }
    }
}

impl Scenario {
    fn dns_result(&self, record_type: DnsRecordType) -> Option<DnsResult> {
        match record_type {
            DnsRecordType::Https => self.https.clone().map(DnsResult::Https),
            DnsRecordType::Aaaa => Some(DnsResult::Aaaa(self.aaaa.clone())),
            DnsRecordType::A => Some(DnsResult::A(self.a.clone())),
        }
    }

    fn connection_result(&self, attempt: usize, is_ech_retry: bool) -> ConnectionResult {
        match self.connections {
            Connections::SucceedOn(n) if attempt == n => ConnectionResult::Success,
            Connections::SucceedOn(_) | Connections::AllFail => {
                ConnectionResult::Failure("connection refused".to_string())
            }
            // A retry to a retry is not allowed, so only the very first attempt
            // reports one.
            Connections::EchRetryThenSuccess if attempt == 0 && !is_ech_retry => {
                ConnectionResult::EchRetry(ech_config())
            }
            Connections::EchRetryThenSuccess => ConnectionResult::Success,
        }
    }
}

/// Drive one full connection establishment and return the number of outputs the
/// state machine produced.
///
/// DNS queries and connection attempts are answered from `scenario`; answers are
/// queued and delivered whenever the state machine has nothing left to emit, so
/// the machine sees them the way a caller's event loop would.
fn drive(scenario: &Scenario, start: Instant) -> usize {
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, scenario.config.clone()).unwrap();
    let mut now = start;
    let mut pending: VecDeque<Input> = VecDeque::new();
    let mut attempts = 0;
    let mut outputs = 0;

    for _ in 0..MAX_STEPS {
        match he.process_output(now) {
            Some(Output::SendDnsQuery {
                id,
                record_type,
                allow_stale,
                ..
            }) => {
                outputs += 1;
                if let Some(result) = scenario.dns_result(record_type) {
                    pending.push_back(Input::DnsResult {
                        id,
                        result,
                        stale: scenario.stale && allow_stale,
                    });
                }
            }
            Some(Output::AttemptConnection {
                id, is_ech_retry, ..
            }) => {
                outputs += 1;
                let result = scenario.connection_result(attempts, is_ech_retry);
                attempts += 1;
                pending.push_back(Input::ConnectionResult { id, result });
            }
            Some(Output::CancelConnection { .. }) => outputs += 1,
            Some(Output::Timer { duration }) => {
                outputs += 1;
                if let Some(input) = pending.pop_front() {
                    he.process_input(input, now);
                } else {
                    // Nothing to deliver: let the timer expire.
                    now += duration;
                }
            }
            Some(Output::Succeeded | Output::Failed(_)) => {
                outputs += 1;
                break;
            }
            None => match pending.pop_front() {
                Some(input) => he.process_input(input, now),
                None => break,
            },
        }
    }

    outputs
}

fn bench_scenario(bencher: Bencher, scenario: Scenario) {
    let start = Instant::now();
    bencher.bench(|| black_box(drive(black_box(&scenario), start)));
}

/// Dual-stack origin with an HTTPS record advertising h3/h2/h1; the first
/// attempt succeeds. The common, happy path.
#[divan::bench]
fn dual_stack_success(bencher: Bencher) {
    bench_scenario(bencher, Scenario::default());
}

/// Same, but every attempt fails, so the full race runs to exhaustion before
/// the machine reports a connection failure.
#[divan::bench]
fn dual_stack_all_attempts_fail(bencher: Bencher) {
    bench_scenario(
        bencher,
        Scenario {
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );
}

/// No HTTPS record (negative answer): plain A/AAAA racing over h2/h1.
#[divan::bench]
fn no_https_record(bencher: Bencher) {
    bench_scenario(
        bencher,
        Scenario {
            https: Some(Err(())),
            ..Scenario::default()
        },
    );
}

/// DNS resolution fails entirely, the shortest path through the machine.
#[divan::bench]
fn dns_resolution_failure(bencher: Bencher) {
    bench_scenario(
        bencher,
        Scenario {
            https: Some(Err(())),
            aaaa: Err(()),
            a: Err(()),
            ..Scenario::default()
        },
    );
}

/// Two HTTPS records pointing at alternative target names with address hints:
/// each target name is resolved in turn, and the resulting endpoints are
/// grouped by service priority.
#[divan::bench]
fn https_records_with_target_names(bencher: Bencher) {
    let mut svc1 = service_info(1, SVC1, &[HttpVersion::H3, HttpVersion::H2]);
    svc1.ipv6_hints = vec![v6(10)];
    svc1.ipv4_hints = vec![v4(10)];
    let mut svc2 = service_info(2, SVC2, &[HttpVersion::H2, HttpVersion::H1]);
    svc2.ipv6_hints = vec![v6(20)];

    bench_scenario(
        bencher,
        Scenario {
            https: Some(Ok(vec![svc1, svc2])),
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );
}

/// Large address sets: the record set flattens into `addrs * 2 families * 2
/// protocol variants` endpoints that are interleaved and then raced until one
/// succeeds (here, the last one).
#[divan::bench(args = [2, 8, 32])]
fn many_addresses_race(bencher: Bencher, addrs: u8) {
    let succeed_on = usize::from(addrs) * 4 - 1;
    bench_scenario(
        bencher,
        Scenario {
            aaaa: Ok(v6_addrs(u16::from(addrs))),
            a: Ok(v4_addrs(addrs)),
            connections: Connections::SucceedOn(succeed_on),
            ..Scenario::default()
        },
    );
}

/// Large address sets where the first attempt wins: dominated by endpoint
/// flattening, ordering and interleaving rather than by the race itself.
#[divan::bench(args = [2, 8, 32])]
fn many_addresses_first_wins(bencher: Bencher, addrs: u8) {
    bench_scenario(
        bencher,
        Scenario {
            aaaa: Ok(v6_addrs(u16::from(addrs))),
            a: Ok(v4_addrs(addrs)),
            ..Scenario::default()
        },
    );
}

/// The server rejects ECH and supplies a `retry_config`: the machine schedules
/// a retry to the same endpoint with the new configuration.
#[divan::bench]
fn ech_retry(bencher: Bencher) {
    let mut svc = service_info(1, HOSTNAME, &[HttpVersion::H3, HttpVersion::H2]);
    svc.ech_config = Some(ech_config());

    bench_scenario(
        bencher,
        Scenario {
            https: Some(Ok(vec![svc])),
            connections: Connections::EchRetryThenSuccess,
            ..Scenario::default()
        },
    );
}

/// Optimistic DNS: the resolver answers from a stale cache entry, which the
/// machine uses at once while emitting background revalidation queries.
#[divan::bench]
fn optimistic_dns_stale_answers(bencher: Bencher) {
    bench_scenario(
        bencher,
        Scenario {
            stale: true,
            ..Scenario::default()
        },
    );
}

/// IPv6-only network: only AAAA is queried and only IPv6 endpoints are raced.
#[divan::bench]
fn ipv6_only(bencher: Bencher) {
    bench_scenario(
        bencher,
        Scenario {
            config: NetworkConfig {
                ip: IpPreference::Ipv6Only,
                ..NetworkConfig::default()
            },
            aaaa: Ok(v6_addrs(4)),
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );
}

/// HTTP/1.1 only, dual stack: the ALPN filtering drops h3 and h2 from every
/// record before endpoints are built.
#[divan::bench]
fn http1_only(bencher: Bencher) {
    bench_scenario(
        bencher,
        Scenario {
            config: NetworkConfig {
                http_versions: HttpVersions {
                    h1: true,
                    h2: false,
                    h3: false,
                },
                ..NetworkConfig::default()
            },
            aaaa: Ok(v6_addrs(4)),
            a: Ok(v4_addrs(4)),
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );
}

/// Alt-svc entries from previous connections are resolved and raced alongside
/// the origin.
#[divan::bench]
fn with_alt_svc(bencher: Bencher) {
    bench_scenario(
        bencher,
        Scenario {
            config: NetworkConfig {
                alt_svc: vec![
                    AltSvc {
                        host: Some(SVC1.to_string()),
                        port: Some(PORT),
                        http_version: HttpVersion::H3,
                    },
                    AltSvc {
                        host: Some(SVC2.to_string()),
                        port: None,
                        http_version: HttpVersion::H2,
                    },
                ],
                ..NetworkConfig::default()
            },
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );
}

/// By-name mode: no DNS at all, the origin is attempted by hostname.
#[divan::bench]
fn by_name(bencher: Bencher) {
    bench_scenario(
        bencher,
        Scenario {
            config: NetworkConfig {
                resolution: ResolutionMode::ByName,
                ..NetworkConfig::default()
            },
            ..Scenario::default()
        },
    );
}

/// By-name mode with the origin HTTPS record fetched for its ALPN, so h3 is
/// attempted by name as well.
#[divan::bench]
fn by_name_with_https_rr(bencher: Bencher) {
    bench_scenario(
        bencher,
        Scenario {
            config: NetworkConfig {
                resolution: ResolutionMode::ByNameWithHttpsRr,
                ..NetworkConfig::default()
            },
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );
}

/// Constructing the state machine, which parses the target host.
mod construction {
    use super::{HOSTNAME, HappyEyeballs, PORT};
    use std::hint::black_box;

    #[divan::bench(args = [HOSTNAME, "192.0.2.1", "[2001:db8::1]"])]
    fn new(host: &str) -> HappyEyeballs {
        HappyEyeballs::new(black_box(host), black_box(PORT)).unwrap()
    }
}
