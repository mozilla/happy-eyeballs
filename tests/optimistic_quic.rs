//! Optimistic QUIC: when nothing is known about the protocols the origin
//! supports (no alt-svc, no HTTPS record), one HTTP/3 attempt runs in parallel
//! with the regular TCP attempts.

#![allow(clippy::disallowed_methods, reason = "tests may use Instant::now")]

mod common;
use common::*;

use std::{num::NonZeroU32, time::Instant};

use happy_eyeballs::{
    AltSvc, CONNECTION_ATTEMPT_DELAY, ConnectionAttemptHttpVersions, DnsResult, FailureReason,
    HappyEyeballs, HttpVersion, HttpVersions, Id, Input, NetworkConfig, Output, RESOLUTION_DELAY,
};

fn optimistic_config() -> NetworkConfig {
    NetworkConfig {
        optimistic_quic: true,
        ..NetworkConfig::default()
    }
}

/// Resolve the origin with a negative HTTPS answer and positive AAAA and A
/// answers, leaving the machine ready to make its first attempt (id 3).
fn resolve_without_signal(he: &mut HappyEyeballs, now: Instant) {
    expect_initial_dns_queries(he, now);
    he.input(in_dns_https_negative(Id::from(0)), now);
    he.expect(out_resolution_delay(), now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
    he.input(in_dns_a_positive(Id::from(2)), now);
}

/// Resolve as in [`resolve_without_signal`] and expect the optimistic attempt
/// (id 3), followed right away by the first regular attempt (id 4).
fn start_race(he: &mut HappyEyeballs, now: Instant) {
    resolve_without_signal(he, now);
    he.expect(out_attempt_v6_h3(Id::from(3)).optimistic(), now);
    he.expect(out_attempt_v6_h1_h2(Id::from(4)), now);
}

#[test]
fn starts_before_first_attempt() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    start_race(&mut he, now);
    he.expect(out_connection_attempt_delay(), now);

    now += CONNECTION_ATTEMPT_DELAY;
    he.expect(out_attempt_v4_h1_h2(Id::from(5)), now);
    he.expect(out_connection_attempt_delay(), now);

    // Only one optimistic attempt is ever made.
    now += CONNECTION_ATTEMPT_DELAY;
    he.expect_idle(now);
}

#[test]
fn success_cancels_tcp() {
    let now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    start_race(&mut he, now);

    he.input(in_connection_result_positive(Id::from(3)), now);
    he.expect_all(
        [
            Output::CancelConnection { id: Id::from(4) },
            Output::Succeeded,
        ],
        now,
    );
}

#[test]
fn failure_leaves_race_untouched() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    start_race(&mut he, now);
    he.input(in_connection_result_negative(Id::from(3)), now);
    he.expect(out_connection_attempt_delay(), now);

    now += CONNECTION_ATTEMPT_DELAY;
    he.expect(out_attempt_v4_h1_h2(Id::from(5)), now);
    he.input(in_connection_result_positive(Id::from(4)), now);
    he.expect_all(
        [
            Output::CancelConnection { id: Id::from(5) },
            Output::Succeeded,
        ],
        now,
    );
}

/// The optimistic attempt does not grow the connection attempt delay.
#[test]
fn does_not_grow_delay() {
    let now = Instant::now();
    let config = NetworkConfig {
        connection_attempt_delay_multiplier: NonZeroU32::new(2).unwrap(),
        ..optimistic_config()
    };
    let mut he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();

    start_race(&mut he, now);
    he.expect(out_connection_attempt_delay(), now);
}

/// The whole race fails once the optimistic attempt and every regular attempt
/// have failed.
#[test]
fn all_fail() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    start_race(&mut he, now);
    he.input(in_connection_result_negative(Id::from(4)), now);
    he.expect(out_attempt_v4_h1_h2(Id::from(5)), now);
    he.input(in_connection_result_negative(Id::from(5)), now);
    // Still waiting on the optimistic attempt.
    now += CONNECTION_ATTEMPT_DELAY;
    he.expect_idle(now);
    he.input(in_connection_result_negative(Id::from(3)), now);
    he.expect(Output::Failed(FailureReason::Connection), now);
}

#[test]
fn disabled_by_default() {
    let now = Instant::now();
    let mut he = HappyEyeballs::new(HOSTNAME, PORT).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(out_attempt_v6_h1_h2(Id::from(3)), now);
    he.expect(out_connection_attempt_delay(), now);
}

/// A pending HTTPS query, e.g. a slow or timed out one, is no signal either:
/// once the resolution delay has passed, the optimistic attempt is made.
#[test]
fn https_query_pending() {
    let mut now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    expect_initial_dns_queries(&mut he, now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
    he.input(in_dns_a_positive(Id::from(2)), now);
    he.expect(out_resolution_delay(), now);

    now += RESOLUTION_DELAY;
    he.expect(out_attempt_v6_h3(Id::from(3)).optimistic(), now);
    he.expect(out_attempt_v6_h1_h2(Id::from(4)), now);
}

/// An empty HTTPS answer (NODATA) is negative, like a failed one: the
/// optimistic attempt is made.
#[test]
fn empty_https_record() {
    let now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    expect_initial_dns_queries(&mut he, now);
    he.input(
        Input::DnsResult {
            id: Id::from(0),
            result: DnsResult::Https(Ok(vec![])),
            stale: false,
        },
        now,
    );
    he.expect(out_resolution_delay(), now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
    he.input(in_dns_a_positive(Id::from(2)), now);
    he.expect(out_attempt_v6_h3(Id::from(3)).optimistic(), now);
    he.expect(out_attempt_v6_h1_h2(Id::from(4)), now);
}

/// No optimistic attempt with a positive HTTPS record, even without HTTP/3.
#[test]
fn not_with_https_record() {
    let now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config()).unwrap();

    expect_initial_dns_queries(&mut he, now);
    he.input(
        Input::DnsResult {
            id: Id::from(0),
            result: DnsResult::Https(Ok(vec![service_info(1, HOSTNAME, &[HttpVersion::H2])])),
            stale: false,
        },
        now,
    );
    he.expect(out_resolution_delay(), now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
    he.input(in_dns_a_positive(Id::from(2)), now);
    he.expect(out_attempt_v6_h2(Id::from(3)), now);
    he.expect(out_connection_attempt_delay(), now);
}

/// No optimistic attempt with an alt-svc entry, even without HTTP/3.
#[test]
fn not_with_alt_svc() {
    let now = Instant::now();
    let config = NetworkConfig {
        alt_svc: vec![AltSvc {
            host: None,
            port: None,
            http_version: HttpVersion::H2,
        }],
        ..optimistic_config()
    };
    let mut he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(out_attempt_v6_h1_h2(Id::from(3)), now);
    he.expect(out_connection_attempt_delay(), now);
}

#[test]
fn not_with_h3_disabled() {
    let now = Instant::now();
    let config = NetworkConfig {
        http_versions: HttpVersions {
            h3: false,
            ..HttpVersions::default()
        },
        ..optimistic_config()
    };
    let mut he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, config).unwrap();

    resolve_without_signal(&mut he, now);
    he.expect(out_attempt_v6_h1_h2(Id::from(3)), now);
    he.expect(out_connection_attempt_delay(), now);
}

#[test]
fn ip_host() {
    let now = Instant::now();
    let mut he =
        HappyEyeballs::new_with_network_config("[2001:db8::1]", PORT, optimistic_config()).unwrap();

    he.expect(out_attempt_v6_h3(Id::from(0)).optimistic(), now);
    he.expect(out_attempt_v6_h1_h2(Id::from(1)), now);
    he.expect(out_connection_attempt_delay(), now);
}

/// An HTTPS record with h3 arrives while the optimistic attempt is in progress.
/// Its HTTP/3 endpoint to the same address is attempted normally, in parallel.
fn https_record_during_optimistic_attempt(https: fn(Id) -> Input, ech: bool) {
    use ConnectionAttemptHttpVersions::H3;

    let with_ech = |output: Output| if ech { output.ech() } else { output };

    let mut now = Instant::now();
    let mut he = HappyEyeballs::new_with_network_config(HOSTNAME, PORT, optimistic_config())
        .expect("valid host");

    expect_initial_dns_queries(&mut he, now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
    he.input(in_dns_a_positive(Id::from(2)), now);
    he.expect(out_resolution_delay(), now);
    now += RESOLUTION_DELAY;
    he.expect(out_attempt_v6_h3(Id::from(3)).optimistic(), now);
    he.expect(out_attempt_v6_h1_h2(Id::from(4)), now);

    he.input(https(Id::from(0)), now);
    now += CONNECTION_ATTEMPT_DELAY;
    he.expect(with_ech(attempt(Id::from(5), V6_ADDR, H3)), now);
}

#[test]
fn https_record_during_optimistic_attempt_no_ech() {
    https_record_during_optimistic_attempt(in_dns_https_positive, false);
}

#[test]
fn https_record_during_optimistic_attempt_ech() {
    https_record_during_optimistic_attempt(in_dns_https_positive_ech, true);
}
