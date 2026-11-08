use ni_core::addr::Family;
use ni_core::endpoint::{EndpointKey, EndpointRecord, ObservationConfidence, Protocol, TcpState};
use ni_core::finding::{Confidence, Finding};
use ni_core::probe::*;
use ni_core::process::ProcessIdentity;
use ni_core::source::{Coverage, DataSource};
use ni_diagnostics::{catalog, evaluate, RuleStatus, SessionEvidence};
use std::net::IpAddr;

fn ep(
    id: u64,
    remote: &str,
    port: u16,
    states: &[TcpState],
    first: i64,
    last: i64,
    obs: u64,
) -> EndpointRecord {
    let r: IpAddr = remote.parse().unwrap();
    EndpointRecord {
        id,
        key: EndpointKey {
            protocol: Protocol::Tcp,
            local_addr: "10.0.0.2".parse().unwrap(),
            local_port: 50000 + id as u16,
            remote_addr: Some(r),
            remote_port: Some(port),
            process: ProcessIdentity {
                pid: 1,
                created: Some(1),
            },
        },
        socket_family: Family::of(&r),
        remote_family: Some(Family::of(&r)),
        remote_scope: None,
        state: states.last().copied(),
        states_seen: states.to_vec(),
        first_seen: first,
        last_seen: last,
        observations: obs,
        episodes: 1,
        present: false,
        gone_at: Some(last + 1000),
        socket_created_at: None,
        source: DataSource::ObservedProcess,
        confidence: ObservationConfidence::High,
        snapshots_in_state: obs,
        state_since: first,
    }
}

fn cov() -> Coverage {
    Coverage {
        provider: "test".into(),
        poll_interval_ms: 1000,
        snapshots_ok: 10,
        ..Default::default()
    }
}

fn tcp_probe(id: &str, addr: &str, port: u16, outcome: TcpOutcome) -> ProbeRecord {
    let a: IpAddr = addr.parse().unwrap();
    ProbeRecord {
        id: id.into(),
        session_id: Some("s".into()),
        started_at: 0,
        finished_at: 1,
        report: ProbeReport::Tcp {
            target: format!("{addr}:{port}"),
            dns: None,
            attempts: vec![TcpAttempt {
                addr: a,
                family: Family::of(&a),
                port,
                started_at: 0,
                outcome,
            }],
        },
    }
}

fn err(name: &str) -> OsError {
    OsError {
        code: Some(1),
        name: Some(name.into()),
        message: name.into(),
    }
}

fn rules_of(f: &[Finding]) -> Vec<&str> {
    f.iter().map(|f| f.rule.as_str()).collect()
}

fn run(eps: &[EndpointRecord], probes: &[ProbeRecord]) -> Vec<Finding> {
    evaluate(&SessionEvidence {
        endpoints: eps,
        probes,
        coverage: &cov(),
        duration_ms: 60_000,
    })
}

#[test]
fn stalled_handshake_detected_only_when_long_and_never_established() {
    let eps = vec![
        ep(1, "203.0.113.10", 443, &[TcpState::SynSent], 0, 5000, 6),
        // Short SYN_SENT: normal connection setup, not reported.
        ep(2, "203.0.113.11", 443, &[TcpState::SynSent], 0, 500, 1),
        // Eventually established: not reported.
        ep(
            3,
            "203.0.113.12",
            443,
            &[TcpState::SynSent, TcpState::Established],
            0,
            9000,
            9,
        ),
    ];
    let f = run(&eps, &[]);
    let stalled: Vec<_> = f
        .iter()
        .filter(|f| f.rule == "tcp.handshake_stalled")
        .collect();
    assert_eq!(stalled.len(), 1);
    assert!(stalled[0].title.contains("203.0.113.10:443"));
    assert_eq!(stalled[0].confidence, Confidence::Low);
    assert!(!stalled[0].alternative_explanations.is_empty());
}

#[test]
fn refused_is_not_presented_as_filtering() {
    let f = run(
        &[],
        &[tcp_probe(
            "p",
            "198.51.100.1",
            443,
            TcpOutcome::Refused {
                elapsed_ms: 1.0,
                error: err("WSAECONNREFUSED"),
            },
        )],
    );
    let r = f.iter().find(|f| f.rule == "probe.tcp_result").unwrap();
    assert!(r.hypotheses.iter().all(|h| !h.text.contains("DPI")));
    assert!(r.title.contains("отклонено"));
}

#[test]
fn app_vs_probe_comparison() {
    let eps = vec![ep(1, "203.0.113.10", 443, &[TcpState::SynSent], 0, 5000, 6)];
    let probes = vec![tcp_probe(
        "p",
        "203.0.113.10",
        443,
        TcpOutcome::Connected {
            elapsed_ms: 20.0,
            local: String::new(),
        },
    )];
    let f = run(&eps, &probes);
    assert!(rules_of(&f).contains(&"compare.app_vs_probe"));
    let c = f.iter().find(|f| f.rule == "compare.app_vs_probe").unwrap();
    assert_eq!(c.confidence, Confidence::VeryLow);
    assert_eq!(c.observations.len(), 2);
    assert_ne!(
        c.observations[0].source, c.observations[1].source,
        "app and probe observations keep their sources"
    );
}

#[test]
fn ipv6_only_failure() {
    let p = ProbeRecord {
        id: "p".into(),
        session_id: None,
        started_at: 0,
        finished_at: 0,
        report: ProbeReport::Tcp {
            target: "example.org:443".into(),
            dns: None,
            attempts: vec![
                TcpAttempt {
                    addr: "192.0.2.1".parse().unwrap(),
                    family: Family::Ipv4,
                    port: 443,
                    started_at: 0,
                    outcome: TcpOutcome::Connected {
                        elapsed_ms: 5.0,
                        local: String::new(),
                    },
                },
                TcpAttempt {
                    addr: "2001:db8::1".parse().unwrap(),
                    family: Family::Ipv6,
                    port: 443,
                    started_at: 0,
                    outcome: TcpOutcome::TimedOut { timeout_ms: 3000 },
                },
            ],
        },
    };
    let f = run(&[], &[p]);
    assert!(f
        .iter()
        .any(|f| f.rule == "probe.family_difference" && f.title.contains("IPv6 — нет")));
}

#[test]
fn dns_special_answer_and_failure() {
    let d = |name: &str, outcome| ProbeRecord {
        id: name.into(),
        session_id: None,
        started_at: 0,
        finished_at: 0,
        report: ProbeReport::Dns(DnsResult {
            name: name.into(),
            resolver: "system".into(),
            elapsed_ms: 1.0,
            outcome,
        }),
    };
    let f = run(
        &[],
        &[
            d(
                "blocked.example",
                DnsOutcome::Resolved {
                    ipv4: vec!["0.0.0.0".parse().unwrap()],
                    ipv6: vec![],
                },
            ),
            d(
                "ok.example",
                DnsOutcome::Resolved {
                    ipv4: vec!["93.184.215.14".parse().unwrap()],
                    ipv6: vec![],
                },
            ),
            d(
                "localhost",
                DnsOutcome::Resolved {
                    ipv4: vec!["127.0.0.1".parse().unwrap()],
                    ipv6: vec![],
                },
            ),
            d(
                "gone.example",
                DnsOutcome::Failed {
                    error: err("WSAHOST_NOT_FOUND"),
                },
            ),
        ],
    );
    let special: Vec<_> = f
        .iter()
        .filter(|f| f.rule == "dns.special_answer")
        .collect();
    assert_eq!(special.len(), 1);
    assert!(special[0].title.starts_with("blocked.example"));
    assert_eq!(
        f.iter().filter(|f| f.rule == "probe.dns_failure").count(),
        1
    );
}

#[test]
fn udp_silence_is_info_with_very_low_confidence() {
    let p = ProbeRecord {
        id: "u".into(),
        session_id: None,
        started_at: 0,
        finished_at: 0,
        report: ProbeReport::Udp {
            target: "x:3478".into(),
            dns: None,
            attempts: vec![UdpAttempt {
                addr: "192.0.2.5".parse().unwrap(),
                family: Family::Ipv4,
                port: 3478,
                payload_len: 20,
                started_at: 0,
                outcome: UdpOutcome::NoReply { timeout_ms: 1000 },
            }],
        },
    };
    let f = run(&[], &[p]);
    let u = f.iter().find(|f| f.rule == "probe.udp_result").unwrap();
    assert_eq!(u.severity, ni_core::finding::Severity::Info);
    assert_eq!(u.confidence, Confidence::VeryLow);
}

#[test]
fn coverage_finding_always_present_and_reports_failures() {
    let c = Coverage {
        provider: "unavailable".into(),
        snapshots_ok: 0,
        snapshots_failed: 3,
        last_error: Some("data source unavailable".into()),
        ..Default::default()
    };
    let f = evaluate(&SessionEvidence {
        endpoints: &[],
        probes: &[],
        coverage: &c,
        duration_ms: 0,
    });
    assert_eq!(f[0].rule, "observability.coverage");
    assert_eq!(f[0].severity, ni_core::finding::Severity::Problem);
}

/// Policy: no finding states a cause with more than Medium confidence, and
/// filtering/DPI hypotheses never exceed Low.
#[test]
fn confidence_policy_holds_for_all_rules() {
    let eps = vec![
        ep(1, "203.0.113.10", 443, &[TcpState::SynSent], 0, 5000, 6),
        ep(2, "2001:db8::10", 443, &[TcpState::SynSent], 0, 9000, 9),
    ];
    let probes = vec![
        tcp_probe(
            "a",
            "203.0.113.10",
            443,
            TcpOutcome::Connected {
                elapsed_ms: 1.0,
                local: String::new(),
            },
        ),
        tcp_probe(
            "b",
            "203.0.113.11",
            443,
            TcpOutcome::TimedOut { timeout_ms: 1000 },
        ),
        tcp_probe(
            "c",
            "203.0.113.12",
            443,
            TcpOutcome::Refused {
                elapsed_ms: 1.0,
                error: err("x"),
            },
        ),
        tcp_probe(
            "d",
            "203.0.113.13",
            443,
            TcpOutcome::Unreachable {
                elapsed_ms: 1.0,
                error: err("x"),
            },
        ),
    ];
    for f in run(&eps, &probes) {
        if f.rule != "observability.coverage" {
            assert!(f.confidence <= Confidence::Medium, "{}", f.id);
        }
        for h in &f.hypotheses {
            let l = h.text.to_lowercase();
            if l.contains("dpi") || l.contains("фильтрац") {
                assert!(h.confidence <= Confidence::Low, "{}: {}", f.id, h.text);
            }
        }
        assert!(
            !f.limitations.is_empty() || f.rule == "observability.coverage",
            "{} lacks limitations",
            f.id
        );
    }
}

#[test]
fn catalog_lists_planned_dpi_rules_without_findings() {
    let c = catalog();
    assert!(c
        .iter()
        .any(|r| r.id == "sni.filtering" && r.status == RuleStatus::Planned));
    assert!(c.iter().any(|r| r.status == RuleStatus::Implemented));
    let f = run(&[], &[]);
    assert!(f
        .iter()
        .all(|f| !f.rule.starts_with("sni.") && !f.rule.starts_with("tls.")));
}
