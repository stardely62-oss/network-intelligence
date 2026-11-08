use ni_collector::{CollectorState, SessionSink};
use ni_core::addr::Family;
use ni_core::endpoint::{Protocol, SocketRow, TcpState};
use ni_core::event::{Event, EventKind};
use ni_core::finding::{Category, Confidence, Finding, Severity};
use ni_core::probe::{DnsOutcome, DnsResult, ProbeRecord, ProbeReport};
use ni_core::process::{ProcessAccess, ProcessIdentity, ProcessInfo, TargetSpec};
use ni_core::session::{SessionMeta, SessionSettings, SessionStatus, SESSION_SCHEMA_VERSION};
use ni_core::source::{Coverage, DataSource, SnapshotProvider, SourceError};
use ni_storage::{EventFilter, Store, StoreError, StoreSink, SCHEMA_VERSION};
use std::sync::{Arc, Mutex};

fn app() -> ProcessInfo {
    ProcessInfo {
        identity: ProcessIdentity {
            pid: 100,
            created: Some(10),
        },
        parent_pid: Some(1),
        name: "app.exe".into(),
        path: Some(r"C:\Users\alice\AppData\Local\App\app.exe".into()),
        access: ProcessAccess::Full,
        threads: 3,
        created_at: None,
    }
}

fn spec() -> TargetSpec {
    let a = app();
    TargetSpec {
        root: a.identity,
        name: a.name,
        path: a.path,
        include_children: true,
        include_same_image: false,
    }
}

fn meta(id: &str, started: i64) -> SessionMeta {
    SessionMeta {
        id: id.into(),
        schema: SESSION_SCHEMA_VERSION,
        title: "app.exe".into(),
        started_at: started,
        ended_at: None,
        status: SessionStatus::Recording,
        target: spec(),
        settings: SessionSettings::default(),
        coverage: Coverage::default(),
        note: String::new(),
        app_version: "0.1.0".into(),
    }
}

struct Fixed(Vec<SocketRow>);
impl SnapshotProvider for Fixed {
    fn name(&self) -> &'static str {
        "fixed"
    }
    fn processes(&mut self) -> Result<Vec<ProcessInfo>, SourceError> {
        Ok(vec![app()])
    }
    fn tcp(&mut self) -> Result<Vec<SocketRow>, SourceError> {
        Ok(self
            .0
            .iter()
            .filter(|r| r.protocol == Protocol::Tcp)
            .cloned()
            .collect())
    }
    fn udp(&mut self) -> Result<Vec<SocketRow>, SourceError> {
        Ok(self
            .0
            .iter()
            .filter(|r| r.protocol == Protocol::Udp)
            .cloned()
            .collect())
    }
}

fn tcp(remote: &str, lport: u16, st: TcpState) -> SocketRow {
    let r: std::net::IpAddr = remote.parse().unwrap();
    SocketRow {
        protocol: Protocol::Tcp,
        socket_family: Family::of(&r),
        local_addr: if r.is_ipv4() {
            "192.168.1.5".parse().unwrap()
        } else {
            "2001:db8::5".parse().unwrap()
        },
        local_port: lport,
        remote_addr: Some(r),
        remote_port: Some(443),
        pid: 100,
        state: Some(st),
        socket_created_at: None,
    }
}

fn udp(port: u16) -> SocketRow {
    SocketRow {
        protocol: Protocol::Udp,
        socket_family: Family::Ipv4,
        local_addr: "0.0.0.0".parse().unwrap(),
        local_port: port,
        remote_addr: None,
        remote_port: None,
        pid: 100,
        state: None,
        socket_created_at: None,
    }
}

#[test]
fn migrations_apply_and_newer_db_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ni.sqlite3");
    {
        let s = Store::open(&path).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    }
    // Reopening is idempotent.
    assert_eq!(
        Store::open(&path).unwrap().schema_version().unwrap(),
        SCHEMA_VERSION
    );
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
    }
    assert!(matches!(Store::open(&path), Err(StoreError::TooNew { .. })));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn session_roundtrip_with_batches_groups_and_events() {
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    store
        .lock()
        .unwrap()
        .create_session(&meta("s1", 1))
        .unwrap();
    let mut sink = StoreSink {
        store: store.clone(),
        session_id: "s1".into(),
    };
    let mut st = CollectorState::new("s1".into(), "fixed", spec(), SessionSettings::default());

    let mut p = Fixed(vec![
        tcp("198.51.100.1", 50000, TcpState::SynSent),
        tcp("198.51.100.1", 50001, TcpState::Established),
        udp(5353),
    ]);
    sink.write(&st.tick(1000, &mut p)).unwrap();
    p.0[0].state = Some(TcpState::Established);
    p.0.push(tcp("2001:db8::99", 50002, TcpState::Established));
    sink.write(&st.tick(2000, &mut p)).unwrap();
    p.0.remove(1);
    sink.write(&st.tick(3000, &mut p)).unwrap();

    let s = store.lock().unwrap();
    let eps = s.endpoints("s1").unwrap();
    assert_eq!(eps.len(), 4);
    let gone = eps.iter().find(|e| e.key.local_port == 50001).unwrap();
    assert!(!gone.present);
    assert_eq!(gone.gone_at, Some(3000));

    let groups = s.address_groups("s1").unwrap();
    let g = groups
        .iter()
        .find(|g| g.remote_addr.as_deref() == Some("198.51.100.1"))
        .unwrap();
    assert_eq!((g.endpoints, g.tcp, g.present), (2, 2, 1));
    assert_eq!(g.states, vec!["SYN_SENT", "ESTABLISHED"]);
    assert!(groups.iter().any(|g| g.remote_addr.is_none() && g.udp == 1));
    assert!(groups.iter().any(|g| g.family.as_deref() == Some("ipv6")));

    let all = s.events("s1", &EventFilter::default()).unwrap();
    assert_eq!(all.total, all.events.len() as u64);
    let changed = s
        .events(
            "s1",
            &EventFilter {
                kinds: vec!["endpoint_state_changed".into()],
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(changed.total, 1);
    let by_addr = s
        .events(
            "s1",
            &EventFilter {
                addr: Some("2001:db8".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(by_addr.total, 1);
    let ranged = s
        .events(
            "s1",
            &EventFilter {
                from: Some(2500),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(ranged.events.iter().all(|e| e.event.ts >= 2500));
    let paged = s
        .events(
            "s1",
            &EventFilter {
                limit: Some(2),
                offset: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(paged.events.len(), 2);

    assert_eq!(s.snapshots("s1").unwrap().len(), 3);
    assert_eq!(s.processes("s1").unwrap().len(), 1);
    let c = s.counts("s1").unwrap();
    assert_eq!(
        (
            c.endpoints,
            c.tcp_endpoints,
            c.udp_endpoints,
            c.remote_addresses
        ),
        (4, 3, 1, 2)
    );
}

#[test]
fn final_batch_completes_session_and_interrupted_are_closed() {
    let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    {
        let s = store.lock().unwrap();
        s.create_session(&meta("done", 1)).unwrap();
        s.create_session(&meta("crashed", 2)).unwrap();
    }
    let st = CollectorState::new(
        "done".into(),
        "fixed",
        spec(),
        SessionSettings {
            poll_interval_ms: 250,
            ..Default::default()
        },
    );
    let h = ni_collector::start(
        st,
        Box::new(Fixed(vec![])),
        Box::new(StoreSink {
            store: store.clone(),
            session_id: "done".into(),
        }),
        Box::new(|_| {}),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    h.stop("user").unwrap();

    let s = store.lock().unwrap();
    let m = s.session("done").unwrap();
    assert_eq!(m.status, SessionStatus::Completed);
    assert!(m.ended_at.is_some());
    assert!(m.coverage.snapshots_ok >= 1);
    assert_eq!(s.close_interrupted().unwrap(), 1);
    let c = s.session("crashed").unwrap();
    assert_eq!(c.status, SessionStatus::Interrupted);
    assert_eq!(c.ended_at, Some(2));
}

#[test]
fn markers_notes_probes_findings_settings_and_deletion() {
    let mut s = Store::open_in_memory().unwrap();
    s.create_session(&meta("s", 1)).unwrap();
    s.add_event(
        "s",
        &Event::new(
            5,
            DataSource::User,
            EventKind::UserMarker {
                label: "звонок оборвался".into(),
            },
        ),
    )
    .unwrap();
    s.set_note("s", "проблема при входе в голосовой канал")
        .unwrap();
    assert_eq!(
        s.session("s").unwrap().note,
        "проблема при входе в голосовой канал"
    );
    let markers = s
        .events(
            "s",
            &EventFilter {
                sources: vec!["user".into()],
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(markers.total, 1);

    let probe = ProbeRecord {
        id: "p1".into(),
        session_id: Some("s".into()),
        started_at: 10,
        finished_at: 20,
        report: ProbeReport::Dns(DnsResult {
            name: "example.com".into(),
            resolver: "system".into(),
            elapsed_ms: 3.0,
            outcome: DnsOutcome::Resolved {
                ipv4: vec!["93.184.215.14".parse().unwrap()],
                ipv6: vec![],
            },
        }),
    };
    s.save_probe(&probe).unwrap();
    s.save_probe(&ProbeRecord {
        id: "p2".into(),
        session_id: None,
        ..probe.clone()
    })
    .unwrap();
    assert_eq!(s.probes(Some("s")).unwrap(), vec![probe]);
    assert_eq!(s.probes(None).unwrap().len(), 1);

    let f = Finding {
        id: "r:x".into(),
        rule: "r".into(),
        category: Category::TcpHandshake,
        severity: Severity::Warning,
        title: "t".into(),
        observations: vec![],
        evidence: vec![],
        hypotheses: vec![],
        alternative_explanations: vec![],
        confidence: Confidence::Low,
        limitations: vec![],
        suggested_checks: vec![],
    };
    s.save_findings("s", std::slice::from_ref(&f)).unwrap();
    s.save_findings("s", std::slice::from_ref(&f)).unwrap();
    assert_eq!(s.findings("s").unwrap(), vec![f]);

    s.set_setting("poll", "500").unwrap();
    s.set_setting("poll", "750").unwrap();
    assert_eq!(s.setting("poll").unwrap().as_deref(), Some("750"));

    s.delete_session("s").unwrap();
    assert!(matches!(s.session("s"), Err(StoreError::NotFound(_))));
    assert_eq!(
        s.events("s", &EventFilter::default()).unwrap().total,
        0,
        "cascade"
    );
    assert!(s.probes(Some("s")).unwrap().is_empty());
    s.create_session(&meta("t", 1)).unwrap();
    s.delete_all().unwrap();
    assert!(s.sessions().unwrap().is_empty());
    assert!(s.probes(None).unwrap().is_empty());
}

#[test]
fn delete_older_than_keeps_recent_and_recording() {
    let s = Store::open_in_memory().unwrap();
    let mut old = meta("old", 100);
    old.status = SessionStatus::Completed;
    s.create_session(&old).unwrap();
    s.create_session(&meta("rec", 100)).unwrap();
    let mut new = meta("new", 10_000);
    new.status = SessionStatus::Completed;
    s.create_session(&new).unwrap();
    assert_eq!(s.delete_older_than(5000).unwrap(), 1);
    let ids: Vec<String> = s
        .sessions()
        .unwrap()
        .into_iter()
        .map(|x| x.meta.id)
        .collect();
    assert_eq!(ids, vec!["new", "rec"]);
}
