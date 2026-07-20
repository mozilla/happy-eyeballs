mod common;

use common::*;
use happy_eyeballs::{
    ConnectionAttemptHttpVersions, FailureReason, HttpVersion, Id, NetworkConfig, Output, Session,
    CONNECTION_ATTEMPT_DELAY,
};

fn websocket_config() -> NetworkConfig {
    NetworkConfig {
        session: Some(Session::WebSocket),
        ..NetworkConfig::default()
    }
}

/// WebSocket over H1: transport connects → EstablishProtocolSession immediately
/// (no settings needed) → session success → Succeeded.
#[test]
fn websocket_h1_happy_path() {
    let config = NetworkConfig {
        session: Some(Session::WebSocket),
        http_versions: happy_eyeballs::HttpVersions {
            h1: true,
            h2: false,
            h3: false,
        },
        ..NetworkConfig::default()
    };
    let (now, mut he) = setup_with_config(config);

    dns_phase_aaaa_only(
        &mut he,
        now,
        out_attempt(
            Id::from(3),
            V6_ADDR.into(),
            PORT,
            ConnectionAttemptHttpVersions::H1,
        ),
    );

    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H1,
                )),
                Some(out_establish_websocket(Id::from(3))),
            ),
            (
                Some(in_session_result_success(Id::from(3))),
                Some(Output::Succeeded),
            ),
        ],
        now,
    );
}

/// WebSocket over H2: transport → wait for settings → establish → succeed.
#[test]
fn websocket_h2_happy_path() {
    let config = NetworkConfig {
        session: Some(Session::WebSocket),
        http_versions: happy_eyeballs::HttpVersions {
            h1: false,
            h2: true,
            h3: false,
        },
        ..NetworkConfig::default()
    };
    let (now, mut he) = setup_with_config(config);

    dns_phase_aaaa_only(&mut he, now, out_attempt_v6_h2(Id::from(3)));

    he.expect(
        vec![(
            Some(in_connection_result_positive_with_version(
                Id::from(3),
                HttpVersion::H2,
            )),
            None,
        )],
        now,
    );

    he.expect(
        vec![
            (
                Some(in_http_settings_extended_connect(Id::from(3))),
                Some(out_establish_websocket(Id::from(3))),
            ),
            (
                Some(in_session_result_success(Id::from(3))),
                Some(Output::Succeeded),
            ),
        ],
        now,
    );
}

/// WebSocket over H2: settings without Extended CONNECT → tries next endpoint.
#[test]
fn websocket_h2_no_extended_connect() {
    let config = NetworkConfig {
        session: Some(Session::WebSocket),
        http_versions: happy_eyeballs::HttpVersions {
            h1: false,
            h2: true,
            h3: false,
        },
        ..NetworkConfig::default()
    };
    let (now, mut he) = setup_with_config(config);

    dns_phase_aaaa_and_a(&mut he, now, out_attempt_v6_h2(Id::from(3)));

    // Transport connects → no delay on InProgress connections anymore →
    // next endpoint starts immediately.
    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H2,
                )),
                Some(out_attempt_v4_h2(Id::from(4))),
            ),
            (None, Some(out_connection_attempt_delay())),
        ],
        now,
    );

    // Settings say no Extended CONNECT → connection 3 fails. Connection 4
    // is already in-progress, so just the delay timer.
    he.expect(
        vec![(
            Some(in_http_settings_no_extended_connect(Id::from(3))),
            Some(out_connection_attempt_delay()),
        )],
        now,
    );
}

/// WebSocket: all connections lack Extended CONNECT → ProtocolNotSupported.
#[test]
fn websocket_all_protocol_not_supported() {
    let config = NetworkConfig {
        session: Some(Session::WebSocket),
        http_versions: happy_eyeballs::HttpVersions {
            h1: false,
            h2: true,
            h3: false,
        },
        ..NetworkConfig::default()
    };
    let (now, mut he) = setup_with_config(config);

    dns_phase_aaaa_only(&mut he, now, out_attempt_v6_h2(Id::from(3)));

    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H2,
                )),
                None,
            ),
            (
                Some(in_http_settings_no_extended_connect(Id::from(3))),
                Some(Output::Failed(FailureReason::ProtocolNotSupported)),
            ),
        ],
        now,
    );
}

/// WebSocket session establishment fails → try next endpoint.
#[test]
fn websocket_session_failure_tries_next() {
    let config = NetworkConfig {
        session: Some(Session::WebSocket),
        http_versions: happy_eyeballs::HttpVersions {
            h1: false,
            h2: true,
            h3: false,
        },
        ..NetworkConfig::default()
    };
    let (now, mut he) = setup_with_config(config);

    dns_phase_aaaa_and_a(&mut he, now, out_attempt_v6_h2(Id::from(3)));

    // Transport success → second endpoint starts (no InProgress delay).
    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H2,
                )),
                Some(out_attempt_v4_h2(Id::from(4))),
            ),
            (None, Some(out_connection_attempt_delay())),
            (
                Some(in_http_settings_extended_connect(Id::from(3))),
                Some(out_establish_websocket(Id::from(3))),
            ),
        ],
        now,
    );

    // Session fails on connection 3 — connection 4 already in progress,
    // delay timer emitted.
    he.expect(
        vec![(
            Some(in_session_result_failure(Id::from(3))),
            Some(out_connection_attempt_delay()),
        )],
        now,
    );
}

/// Two connections race. First fully succeeds → cancel the second.
#[test]
fn websocket_racing_first_wins() {
    let config = NetworkConfig {
        session: Some(Session::WebSocket),
        http_versions: happy_eyeballs::HttpVersions {
            h1: false,
            h2: true,
            h3: false,
        },
        ..NetworkConfig::default()
    };
    let (mut now, mut he) = setup_with_config(config);

    dns_phase_aaaa_and_a(&mut he, now, out_attempt_v6_h2(Id::from(3)));

    now += CONNECTION_ATTEMPT_DELAY;
    he.expect(
        vec![
            (None, Some(out_attempt_v4_h2(Id::from(4)))),
            (None, Some(out_connection_attempt_delay())),
        ],
        now,
    );

    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H2,
                )),
                // Connection 4 still in-progress → delay timer.
                Some(out_connection_attempt_delay()),
            ),
            (
                Some(in_http_settings_extended_connect(Id::from(3))),
                Some(out_establish_websocket(Id::from(3))),
            ),
            (
                Some(in_session_result_success(Id::from(3))),
                Some(Output::CancelConnection { id: Id::from(4) }),
            ),
            (None, Some(Output::Succeeded)),
        ],
        now,
    );
}

/// Two connections race. Both get transport + settings. Second completes
/// session first → cancel the first.
#[test]
fn websocket_racing_second_wins() {
    let config = NetworkConfig {
        session: Some(Session::WebSocket),
        http_versions: happy_eyeballs::HttpVersions {
            h1: false,
            h2: true,
            h3: false,
        },
        ..NetworkConfig::default()
    };
    let (mut now, mut he) = setup_with_config(config);

    dns_phase_aaaa_and_a(&mut he, now, out_attempt_v6_h2(Id::from(3)));

    now += CONNECTION_ATTEMPT_DELAY;
    he.expect(
        vec![
            (None, Some(out_attempt_v4_h2(Id::from(4)))),
            (None, Some(out_connection_attempt_delay())),
        ],
        now,
    );

    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H2,
                )),
                // Connection 4 still InProgress → delay timer.
                Some(out_connection_attempt_delay()),
            ),
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(4),
                    HttpVersion::H2,
                )),
                // Both Connected but no settings yet.
                None,
            ),
            (
                Some(in_http_settings_extended_connect(Id::from(3))),
                Some(out_establish_websocket(Id::from(3))),
            ),
            (
                Some(in_http_settings_extended_connect(Id::from(4))),
                Some(out_establish_websocket(Id::from(4))),
            ),
        ],
        now,
    );

    he.expect(
        vec![
            (
                Some(in_session_result_success(Id::from(4))),
                Some(Output::CancelConnection { id: Id::from(3) }),
            ),
            (None, Some(Output::Succeeded)),
        ],
        now,
    );
}

/// WebSocket over H3: transport → settings → establish → succeed.
#[test]
fn websocket_h3_happy_path() {
    let config = NetworkConfig {
        session: Some(Session::WebSocket),
        http_versions: happy_eyeballs::HttpVersions {
            h1: false,
            h2: false,
            h3: true,
        },
        ..NetworkConfig::default()
    };
    let (now, mut he) = setup_with_config(config);

    dns_phase_aaaa_only_https_positive(&mut he, now, out_attempt_v6_h3(Id::from(3)));

    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H3,
                )),
                None,
            ),
            (
                Some(in_http_settings_extended_connect(Id::from(3))),
                Some(out_establish_websocket(Id::from(3))),
            ),
            (
                Some(in_session_result_success(Id::from(3))),
                Some(Output::Succeeded),
            ),
        ],
        now,
    );
}

/// WebTransport over H3 happy path.
#[test]
fn webtransport_h3_happy_path() {
    let config = NetworkConfig {
        session: Some(Session::WebTransport),
        http_versions: happy_eyeballs::HttpVersions {
            h1: false,
            h2: false,
            h3: true,
        },
        ..NetworkConfig::default()
    };
    let (now, mut he) = setup_with_config(config);

    dns_phase_aaaa_only_https_positive(&mut he, now, out_attempt_v6_h3(Id::from(3)));

    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H3,
                )),
                None,
            ),
            (
                Some(in_http_settings_webtransport(Id::from(3))),
                Some(out_establish_webtransport(Id::from(3))),
            ),
            (
                Some(in_session_result_success(Id::from(3))),
                Some(Output::Succeeded),
            ),
        ],
        now,
    );
}

/// WebTransport: settings have extended_connect but NOT webtransport →
/// ProtocolNotSupported.
#[test]
fn webtransport_h3_no_webtransport_setting() {
    let config = NetworkConfig {
        session: Some(Session::WebTransport),
        http_versions: happy_eyeballs::HttpVersions {
            h1: false,
            h2: false,
            h3: true,
        },
        ..NetworkConfig::default()
    };
    let (now, mut he) = setup_with_config(config);

    dns_phase_aaaa_only_https_positive(&mut he, now, out_attempt_v6_h3(Id::from(3)));

    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H3,
                )),
                None,
            ),
            (
                Some(in_http_settings_extended_connect(Id::from(3))),
                Some(Output::Failed(FailureReason::ProtocolNotSupported)),
            ),
        ],
        now,
    );
}

/// WebSocket with H2OrH1: caller negotiates H2 via ALPN → settings flow.
#[test]
fn websocket_h2orh1_negotiated_h2() {
    let (now, mut he) = setup_with_config(websocket_config());

    dns_phase_aaaa_only(&mut he, now, out_attempt_v6_h1_h2(Id::from(3)));

    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H2,
                )),
                None,
            ),
            (
                Some(in_http_settings_extended_connect(Id::from(3))),
                Some(out_establish_websocket(Id::from(3))),
            ),
            (
                Some(in_session_result_success(Id::from(3))),
                Some(Output::Succeeded),
            ),
        ],
        now,
    );
}

/// WebSocket with H2OrH1: caller negotiates H1 → immediate session
/// establishment (no settings).
#[test]
fn websocket_h2orh1_negotiated_h1() {
    let (now, mut he) = setup_with_config(websocket_config());

    dns_phase_aaaa_only(&mut he, now, out_attempt_v6_h1_h2(Id::from(3)));

    he.expect(
        vec![
            (
                Some(in_connection_result_positive_with_version(
                    Id::from(3),
                    HttpVersion::H1,
                )),
                Some(out_establish_websocket(Id::from(3))),
            ),
            (
                Some(in_session_result_success(Id::from(3))),
                Some(Output::Succeeded),
            ),
        ],
        now,
    );
}

/// Plain HTTP (session: None) — transport success = overall success.
#[test]
fn plain_http_transport_success_is_overall_success() {
    let (now, mut he) = setup();

    dns_phase_aaaa_only(&mut he, now, out_attempt_v6_h1_h2(Id::from(3)));

    he.expect(
        vec![
            (
                Some(in_connection_result_positive(Id::from(3))),
                Some(Output::Succeeded),
            ),
        ],
        now,
    );
}
