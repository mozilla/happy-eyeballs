#![allow(clippy::disallowed_methods, reason = "tests may use Instant::now")]

/// > Make the state machine 0-RTT aware
///
/// Early data is a dimension of the attempt variants, next to address family
/// and HTTP version: for an endpoint a resumption token covers, the candidate
/// list carries two variants, `offer_early_data: true` first and
/// `offer_early_data: false` after, interleaved like any other pair.
mod common;
use common::*;

use std::time::Instant;

use happy_eyeballs::{
    CONNECTION_ATTEMPT_DELAY, ConnectionAttemptHttpVersions, Endpoint, EndpointTarget,
    HappyEyeballs, HttpVersions, Id, NetworkConfig, Output,
};

fn out_attempt_v6_h3(id: Id, offer_early_data: bool) -> Output {
    Output::AttemptConnection {
        id,
        endpoint: Endpoint {
            target: EndpointTarget::Address(std::net::SocketAddr::new(V6_ADDR.into(), PORT)),
            http_version: ConnectionAttemptHttpVersions::H3,
            ech_config: None,
            offer_early_data,
        },
        is_ech_retry: false,
        offer_early_data,
    }
}

fn config_with_early_data(early_data: HttpVersions) -> NetworkConfig {
    NetworkConfig {
        early_data,
        ..NetworkConfig::default()
    }
}

/// Reach the connection phase for the default host: an HTTPS record with HTTP/3
/// and HTTP/2 ALPN, then AAAA and A answers.
fn reach_connection_phase(he: &mut HappyEyeballs, now: Instant) {
    expect_initial_dns_queries(he, now);
    he.input(in_dns_https_positive(Id::from(0)), now);
    he.expect(out_resolution_delay(), now);
    he.input(in_dns_a_positive(Id::from(2)), now);
    he.expect(out_resolution_delay(), now);
    he.input(in_dns_aaaa_positive(Id::from(1)), now);
}

/// Without a resumption token, the first attempt carries
/// `offer_early_data: false`.
#[test]
fn no_early_data_by_default() {
    let (now, mut he) = setup_with_config(config_with_early_data(HttpVersions::none()));
    reach_connection_phase(&mut he, now);

    he.expect(out_attempt_v6_h3(Id::from(3), false), now);
}

/// An HTTP/3 resumption token races the HTTP/3 endpoint twice: the early-data
/// variant first, then the plain one, one connection attempt delay apart.
#[test]
fn early_data_variant_is_offered_first() {
    let config = config_with_early_data(HttpVersions {
        h1: false,
        h2: false,
        h3: true,
    });
    let (mut now, mut he) = setup_with_config(config);
    reach_connection_phase(&mut he, now);

    // The early-data variant is attempted immediately.
    he.expect(out_attempt_v6_h3(Id::from(3), true), now);

    // The plain variant of the same endpoint is next, one delay later.
    now += CONNECTION_ATTEMPT_DELAY;
    he.expect(out_attempt_v6_h3(Id::from(4), false), now);
    he.expect(out_connection_attempt_delay(), now);
}

/// A token is per protocol variant: an HTTP/2 token says nothing about HTTP/3,
/// so the HTTP/3 endpoint is not raced twice.
#[test]
fn h2_token_does_not_cover_h3_endpoint() {
    let config = config_with_early_data(HttpVersions {
        h1: false,
        h2: true,
        h3: false,
    });
    let (now, mut he) = setup_with_config(config);
    reach_connection_phase(&mut he, now);

    // The first endpoint is HTTP/3, which no token covers here.
    he.expect(out_attempt_v6_h3(Id::from(3), false), now);
}

/// Because both variants are queued, a blackholed 0-RTT attempt costs exactly
/// one connection attempt delay before the plain variant is tried.
#[test]
fn blackholed_early_data_falls_back_after_one_delay() {
    let config = config_with_early_data(HttpVersions {
        h1: false,
        h2: false,
        h3: true,
    });
    let (mut now, mut he) = setup_with_config(config);
    reach_connection_phase(&mut he, now);

    // First attempt: offers early data.
    let first = he.process_output(now).expect("an attempt");
    let Output::AttemptConnection {
        offer_early_data: true,
        ..
    } = first
    else {
        panic!("expected an early-data attempt, got {first:?}");
    };

    // One delay later the plain variant of the same endpoint is attempted.
    now += CONNECTION_ATTEMPT_DELAY;
    he.expect(out_attempt_v6_h3(Id::from(4), false), now);
}
