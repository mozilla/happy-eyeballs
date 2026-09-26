//! Benchmarks for the Happy Eyeballs v3 state machine.
//!
//! The crate is a pure, deterministic state machine: the caller feeds it
//! [`Input`]s and drains [`Output`]s. Every benchmark therefore drives a
//! complete connection establishment, from the first DNS query to the final
//! `Succeeded`/`Failed` output, using a small driver that answers DNS queries
//! and connection attempts from a canned scenario.
//!
//! The scenarios cover the paths that matter in production: plain dual-stack
//! resolution, HTTPS (SVCB) records with alternative target names, large
//! address sets (endpoint flattening, interleaving and racing), failing races,
//! ECH retries, Optimistic DNS revalidation, the by-name resolution modes and
//! alt-svc.
//!
//! The record builders, driver methods and constants are the ones the
//! integration tests use, shared from `tests/common`.

#[path = "../tests/common/mod.rs"]
mod common;
use common::*;

use std::{
    collections::VecDeque,
    hint::black_box,
    net::{Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use happy_eyeballs::{
    AltSvc, DnsRecordType, DnsResult, HappyEyeballs, HttpVersion, HttpVersions, Id, Input,
    IpPreference, NetworkConfig, Output, ResolutionMode, ServiceInfo,
};

/// Upper bound on driver iterations, so a scenario can never spin forever
/// inside a benchmark.
const MAX_STEPS: usize = 100_000;

/// `count` consecutive IPv6 addresses starting at [`V6_ADDR`]. The tests only
/// ever need a handful of named addresses; the benchmarks scale the count.
fn v6_addrs(count: u16) -> Vec<Ipv6Addr> {
    let base = u128::from(V6_ADDR);
    (0..u128::from(count)).map(|n| (base + n).into()).collect()
}

/// `count` consecutive IPv4 addresses starting at [`V4_ADDR`], the IPv4
/// counterpart of [`v6_addrs`].
fn v4_addrs(count: u8) -> Vec<Ipv4Addr> {
    let base = u32::from(V4_ADDR);
    (0..u32::from(count)).map(|n| (base + n).into()).collect()
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
#[derive(Clone)]
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
    /// The answer to a query of `record_type`, or `None` to leave the query
    /// unanswered.
    fn dns_input(&self, id: Id, record_type: DnsRecordType, allow_stale: bool) -> Option<Input> {
        let result = match record_type {
            DnsRecordType::Https => self.https.clone().map(DnsResult::Https)?,
            DnsRecordType::Aaaa => DnsResult::Aaaa(self.aaaa.clone()),
            DnsRecordType::A => DnsResult::A(self.a.clone()),
        };
        Some(Input::DnsResult {
            id,
            result,
            stale: self.stale && allow_stale,
        })
    }

    /// The result of the `attempt`th (0-based) connection attempt.
    fn connection_input(&self, id: Id, attempt: usize, is_ech_retry: bool) -> Input {
        match self.connections {
            Connections::SucceedOn(n) if attempt == n => in_connection_result_positive(id),
            Connections::SucceedOn(_) | Connections::AllFail => in_connection_result_negative(id),
            // A retry to a retry is not allowed, so only the very first attempt
            // reports one.
            Connections::EchRetryThenSuccess if attempt == 0 && !is_ech_retry => {
                in_connection_result_ech_retry(id)
            }
            Connections::EchRetryThenSuccess => in_connection_result_positive(id),
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
        let Some(output) = he.process_output(now) else {
            // Nothing left to emit: deliver the next queued answer, if any.
            let Some(input) = pending.pop_front() else {
                break;
            };
            he.input(input, now);
            continue;
        };
        outputs += 1;

        match output {
            Output::SendDnsQuery {
                id,
                record_type,
                allow_stale,
                ..
            } => pending.extend(scenario.dns_input(id, record_type, allow_stale)),
            Output::AttemptConnection {
                id, is_ech_retry, ..
            } => {
                pending.push_back(scenario.connection_input(id, attempts, is_ech_retry));
                attempts += 1;
            }
            Output::CancelConnection { .. } => {}
            Output::Timer { duration } => {
                if let Some(input) = pending.pop_front() {
                    he.input(input, now);
                } else {
                    // Nothing to deliver: let the timer expire.
                    now += duration;
                }
            }
            Output::Succeeded | Output::Failed(_) => break,
        }
    }

    outputs
}

/// Drive `scenario` to completion, under `id`.
fn bench_scenario(group: &mut BenchmarkGroup<'_, WallTime>, id: BenchmarkId, scenario: &Scenario) {
    let start = Instant::now();
    group.bench_with_input(id, scenario, |b, scenario| {
        b.iter(|| black_box(drive(black_box(scenario), start)));
    });
}

/// The individual connection establishment scenarios.
fn scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("scenario");
    let mut bench = |name: &str, scenario: &Scenario| {
        bench_scenario(&mut group, BenchmarkId::from_parameter(name), scenario);
    };

    // Dual-stack origin with an HTTPS record advertising h3/h2/h1; the first
    // attempt succeeds. The common, happy path.
    bench("dual_stack_success", &Scenario::default());

    // Same, but every attempt fails, so the full race runs to exhaustion before
    // the machine reports a connection failure.
    bench(
        "dual_stack_all_attempts_fail",
        &Scenario {
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );

    // No HTTPS record (negative answer): plain A/AAAA racing over h2/h1.
    bench(
        "no_https_record",
        &Scenario {
            https: Some(Err(())),
            ..Scenario::default()
        },
    );

    // DNS resolution fails entirely, the shortest path through the machine.
    bench(
        "dns_resolution_failure",
        &Scenario {
            https: Some(Err(())),
            aaaa: Err(()),
            a: Err(()),
            ..Scenario::default()
        },
    );

    // Two HTTPS records pointing at alternative target names with address
    // hints: each target name is resolved in turn, and the resulting endpoints
    // are grouped by service priority.
    bench(
        "https_records_with_target_names",
        &Scenario {
            https: Some(Ok(vec![
                service_info(1, SVC1, &[HttpVersion::H3, HttpVersion::H2])
                    .ipv6_hints(vec![V6_ADDR_2])
                    .ipv4_hints(vec![V4_ADDR_2]),
                service_info(2, SVC2, &[HttpVersion::H2, HttpVersion::H1])
                    .ipv6_hints(vec![V6_ADDR_3]),
            ])),
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );

    // The server rejects ECH and supplies a `retry_config`: the machine
    // schedules a retry to the same endpoint with the new configuration.
    bench(
        "ech_retry",
        &Scenario {
            https: Some(Ok(vec![
                service_info(1, HOSTNAME, &[HttpVersion::H3, HttpVersion::H2]).ech(),
            ])),
            connections: Connections::EchRetryThenSuccess,
            ..Scenario::default()
        },
    );

    // Optimistic DNS: the resolver answers from a stale cache entry, which the
    // machine uses at once while emitting background revalidation queries.
    bench(
        "optimistic_dns_stale_answers",
        &Scenario {
            stale: true,
            ..Scenario::default()
        },
    );

    // IPv6-only network: only AAAA is queried and only IPv6 endpoints are
    // raced.
    bench(
        "ipv6_only",
        &Scenario {
            config: NetworkConfig {
                ip: IpPreference::Ipv6Only,
                ..NetworkConfig::default()
            },
            aaaa: Ok(v6_addrs(4)),
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );

    // HTTP/1.1 only, dual stack: the ALPN filtering drops h3 and h2 from every
    // record before endpoints are built.
    bench(
        "http1_only",
        &Scenario {
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

    // Alt-svc entries from previous connections are resolved and raced
    // alongside the origin.
    bench(
        "with_alt_svc",
        &Scenario {
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

    // By-name mode: no DNS at all, the origin is attempted by hostname.
    bench(
        "by_name",
        &Scenario {
            config: NetworkConfig {
                resolution: ResolutionMode::ByName,
                ..NetworkConfig::default()
            },
            ..Scenario::default()
        },
    );

    // By-name mode with the origin HTTPS record fetched for its ALPN, so h3 is
    // attempted by name as well.
    bench(
        "by_name_with_https_rr",
        &Scenario {
            config: NetworkConfig {
                resolution: ResolutionMode::ByNameWithHttpsRr,
                ..NetworkConfig::default()
            },
            connections: Connections::AllFail,
            ..Scenario::default()
        },
    );

    group.finish();
}

/// Large address sets: the record set flattens into `addrs * 2 families * 2
/// protocol variants` endpoints that are interleaved and then raced, either
/// until the last endpoint succeeds (`race`) or until the first one does
/// (`first_wins`, dominated by flattening, ordering and interleaving rather
/// than by the race itself).
fn many_addresses(c: &mut Criterion) {
    let mut group = c.benchmark_group("many_addresses");

    for addrs in [2_u8, 8, 32] {
        let first_wins = Scenario {
            aaaa: Ok(v6_addrs(u16::from(addrs))),
            a: Ok(v4_addrs(addrs)),
            ..Scenario::default()
        };
        let race = Scenario {
            connections: Connections::SucceedOn(usize::from(addrs) * 4 - 1),
            ..first_wins.clone()
        };

        bench_scenario(&mut group, BenchmarkId::new("race", addrs), &race);
        bench_scenario(
            &mut group,
            BenchmarkId::new("first_wins", addrs),
            &first_wins,
        );
    }

    group.finish();
}

/// Constructing the state machine, which parses the target host.
fn construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("construction");

    for host in [HOSTNAME, "192.0.2.1", "[2001:db8::1]"] {
        group.bench_with_input(BenchmarkId::from_parameter(host), host, |b, host| {
            b.iter(|| HappyEyeballs::new(black_box(host), black_box(PORT)).unwrap());
        });
    }

    group.finish();
}

criterion_group!(benches, scenarios, many_addresses, construction);
criterion_main!(benches);
