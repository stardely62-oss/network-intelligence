//! Probes against local test servers (loopback only, no external network).

mod support;

use ni_core::probe::{ProbeReport, TcpOutcome, UdpOutcome};
use ni_probe::{tcp, udp, Families, Target};
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(2);

#[test]
fn tcp_connect_succeeds_ipv4_and_ipv6() {
    let a = support::tcp_echo("127.0.0.1:0");
    let r = tcp::connect_once(a.ip(), a.port(), T);
    assert!(
        matches!(r.outcome, TcpOutcome::Connected { .. }),
        "{:?}",
        r.outcome
    );
    if let Ok(l) = std::net::TcpListener::bind("[::1]:0") {
        let a6 = l.local_addr().unwrap();
        drop(l);
        let a6 = support::tcp_echo(&a6.to_string());
        let r = tcp::connect_once(a6.ip(), a6.port(), T);
        assert!(
            matches!(r.outcome, TcpOutcome::Connected { .. }),
            "{:?}",
            r.outcome
        );
        assert_eq!(r.family, ni_core::addr::Family::Ipv6);
    }
}

/// Windows answers a refused SYN only after its own SYN retransmissions
/// (about 2 s on loopback), so the probe needs a timeout well above that to
/// classify a closed port correctly. Linux refuses immediately.
#[test]
fn tcp_closed_port_is_refused_not_timeout() {
    let a = support::closed_tcp_port("127.0.0.1:0");
    let r = tcp::connect_once(a.ip(), a.port(), Duration::from_secs(5));
    match &r.outcome {
        TcpOutcome::Refused { error, elapsed_ms } => {
            eprintln!("refused after {elapsed_ms} ms");
            assert!(
                error.name.as_deref().unwrap_or("").contains("CONNREFUSED"),
                "{error:?}"
            )
        }
        o => panic!("expected refused, got {o:?}"),
    }
}

#[test]
fn tcp_timeout_is_bounded_in_controlled_conditions() {
    let (_listener, a) = support::tcp_never_accepting();
    let timeout = Duration::from_millis(400);
    let mut outcomes = Vec::new();
    // Fill the accept queue; later attempts cannot complete.
    for _ in 0..6 {
        let start = Instant::now();
        let r = tcp::connect_once(a.ip(), a.port(), timeout);
        assert!(
            start.elapsed() < timeout + Duration::from_millis(600),
            "probe exceeded its timeout"
        );
        outcomes.push(r.outcome);
    }
    let last = outcomes.last().unwrap();
    #[cfg(target_os = "linux")]
    assert!(
        matches!(last, TcpOutcome::TimedOut { timeout_ms: 400 }),
        "{outcomes:?}"
    );
    #[cfg(not(target_os = "linux"))]
    assert!(
        matches!(
            last,
            TcpOutcome::TimedOut { .. } | TcpOutcome::Refused { .. }
        ),
        "{outcomes:?}"
    );
}

#[test]
fn udp_reply_is_received() {
    let a = support::udp_echo("127.0.0.1:0");
    let r = udp::send_once(a.ip(), a.port(), b"ping", T);
    assert!(
        matches!(r.outcome, UdpOutcome::Reply { bytes: 9, .. }),
        "{:?}",
        r.outcome
    );
}

#[test]
fn udp_silence_is_no_reply_only() {
    let s = support::udp_silent("127.0.0.1:0");
    let a = s.local_addr().unwrap();
    let r = udp::send_once(a.ip(), a.port(), b"hello", Duration::from_millis(300));
    assert!(
        matches!(r.outcome, UdpOutcome::NoReply { timeout_ms: 300 }),
        "{:?}",
        r.outcome
    );
    drop(s);
}

#[test]
fn udp_closed_port_reports_port_unreachable() {
    let a = support::closed_udp_port("127.0.0.1:0");
    let r = udp::send_once(a.ip(), a.port(), b"x", Duration::from_secs(1));
    assert!(
        matches!(r.outcome, UdpOutcome::PortUnreachable { .. }),
        "{:?}",
        r.outcome
    );
}

#[test]
fn probe_by_name_uses_system_resolver_and_family_filter() {
    let a = support::tcp_echo("127.0.0.1:0");
    let r = tcp::probe(
        &Target::Host("localhost".into()),
        a.port(),
        Families {
            ipv4: true,
            ipv6: false,
        },
        T,
    );
    let ProbeReport::Tcp { dns, attempts, .. } = &r else {
        panic!()
    };
    assert!(dns.is_some());
    assert!(attempts.iter().all(|a| a.addr.is_ipv4()));
    assert!(r.ok(), "{}", r.summary());
}

#[test]
fn family_filter_can_leave_nothing_to_probe() {
    let r = tcp::probe(
        &Target::Ip("127.0.0.1".parse().unwrap()),
        9,
        Families {
            ipv4: false,
            ipv6: true,
        },
        T,
    );
    let ProbeReport::Tcp { attempts, .. } = &r else {
        panic!()
    };
    assert!(attempts.is_empty());
    assert!(!r.ok());
}
