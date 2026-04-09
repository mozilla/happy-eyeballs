mod common;
use common::*;

use happy_eyeballs::{HappyEyeballs, HttpVersion, Id, ServiceInfo, TargetName};

#[test]
fn id_roundtrip() {
    for n in [0u64, 42] {
        assert_eq!(u64::from(Id::from(n)), n);
    }
}

#[test]
fn ech_config_as_ref() {
    assert_eq!(ech_config().as_ref(), ECH_CONFIG_BYTES);
}

#[test]
fn target_name_conversions() {
    let name = TargetName::from(HOSTNAME);
    assert_eq!(format!("{name:?}"), HOSTNAME);
    assert_eq!(String::from(name), HOSTNAME);
}

#[test]
fn service_info_debug() {
    // With optional fields populated: all conditional fields must appear.
    let full = ServiceInfo {
        priority: 1,
        target_name: HOSTNAME.into(),
        alpn_http_versions: [HttpVersion::H3].into(),
        ech_config: Some(ech_config()),
        ipv4_hints: vec![V4_ADDR],
        ipv6_hints: vec![V6_ADDR],
        port: None,
    };
    let s = format!("{full:?}");
    assert!(s.contains("alpn"), "missing 'alpn': {s}");
    assert!(s.contains("ipv4"), "missing 'ipv4': {s}");
    assert!(s.contains("ipv6"), "missing 'ipv6': {s}");

    // With optional fields empty: conditional fields must not appear.
    let bare = ServiceInfo {
        alpn_http_versions: Default::default(),
        ech_config: None,
        ipv4_hints: vec![],
        ipv6_hints: vec![],
        ..full
    };
    let s = format!("{bare:?}");
    assert!(!s.contains("alpn"), "unexpected 'alpn': {s}");
    assert!(!s.contains("ipv4"), "unexpected 'ipv4': {s}");
    assert!(!s.contains("ipv6"), "unexpected 'ipv6': {s}");
}

#[test]
fn happy_eyeballs_debug() {
    let (now, mut he) = setup();

    // Fresh domain host: always has "target" and "port", never "dns_queries" yet.
    let s = format!("{he:?}");
    assert!(s.contains("target"), "missing 'target': {s}");
    assert!(s.contains("port"), "missing 'port': {s}");
    assert!(!s.contains("dns_queries"), "unexpected 'dns_queries': {s}");

    // After first process_output, dns_queries is populated.
    let _ = he.process_output(now);
    let s = format!("{he:?}");
    assert!(s.contains("dns_queries"), "missing 'dns_queries': {s}");

    // IP host: first process_output immediately starts a connection.
    let mut he_ip = HappyEyeballs::new(&format!("[{V6_ADDR}]"), PORT).unwrap();
    let _ = he_ip.process_output(now);
    let s = format!("{he_ip:?}");
    assert!(
        s.contains("connection_attempts"),
        "missing 'connection_attempts': {s}"
    );

    // Feed EchRetry for the in-progress connection to populate ech_retries.
    he_ip.process_input(in_connection_result_ech_retry(Id::from(0)), now);
    let s = format!("{he_ip:?}");
    assert!(s.contains("ech_retries"), "missing 'ech_retries': {s}");
}
