//! Collector behaviour on recorded snapshot sequences. The provider here is
//! a test double replaying fixed inputs; it is never used by the app.

use ni_collector::{CollectorState, SessionSink, TickBatch};
use ni_core::addr::Family;
use ni_core::endpoint::{Protocol, SocketRow, TcpState};
use ni_core::event::EventKind;
use ni_core::process::{ProcessAccess, ProcessIdentity, ProcessInfo, TargetSpec};
use ni_core::session::SessionSettings;
use ni_core::source::{SnapshotProvider, SourceError};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

type Step = (
    Result<Vec<ProcessInfo>, SourceError>,
    Result<Vec<SocketRow>, SourceError>,
);

struct Replay(VecDeque<Step>);

impl SnapshotProvider for Replay {
    fn name(&self) -> &'static str {
        "replay"
    }
    fn processes(&mut self) -> Result<Vec<ProcessInfo>, SourceError> {
        self.0.front().unwrap().0.clone()
    }
    fn tcp(&mut self) -> Result<Vec<SocketRow>, SourceError> {
        self.0.front().unwrap().1.clone()
    }
    fn udp(&mut self) -> Result<Vec<SocketRow>, SourceError> {
        self.0.pop_front();
        Ok(vec![])
    }
}

fn p(pid: u32, created: u64, name: &str) -> ProcessInfo {
    ProcessInfo {
        identity: ProcessIdentity {
            pid,
            created: Some(created),
        },
        parent_pid: Some(1),
        name: name.into(),
        path: Some(format!("C:\\{name}")),
        access: ProcessAccess::Full,
        threads: 1,
        created_at: None,
    }
}

fn row(pid: u32, lport: u16, state: TcpState) -> SocketRow {
    SocketRow {
        protocol: Protocol::Tcp,
        socket_family: Family::Ipv4,
        local_addr: "10.0.0.2".parse().unwrap(),
        local_port: lport,
        remote_addr: Some("198.51.100.20".parse().unwrap()),
        remote_port: Some(443),
        pid,
        state: Some(state),
        socket_created_at: None,
    }
}

fn spec(root: &ProcessInfo, same_image: bool) -> TargetSpec {
    TargetSpec {
        root: root.identity,
        name: root.name.clone(),
        path: root.path.clone(),
        include_children: true,
        include_same_image: same_image,
    }
}

fn run(spec: TargetSpec, steps: Vec<Step>) -> Vec<TickBatch> {
    let n = steps.len();
    let mut prov = Replay(steps.into());
    let mut st = CollectorState::new("s".into(), "replay", spec, SessionSettings::default());
    (0..n)
        .map(|i| st.tick(1000 * (i as i64 + 1), &mut prov))
        .collect()
}

fn kinds(b: &[TickBatch]) -> Vec<&'static str> {
    b.iter()
        .flat_map(|b| b.events.iter().map(|e| e.kind.name()))
        .collect()
}

#[test]
fn process_exit_during_session_is_recorded_and_its_endpoints_disappear() {
    let app = p(100, 10, "app.exe");
    let b = run(
        spec(&app, false),
        vec![
            (
                Ok(vec![app.clone()]),
                Ok(vec![row(100, 50000, TcpState::Established)]),
            ),
            (Ok(vec![]), Ok(vec![])),
        ],
    );
    assert_eq!(
        kinds(&b),
        [
            "process_tracked",
            "endpoint_appeared",
            "process_exited",
            "endpoint_disappeared"
        ]
    );
    assert!(b[1].processes[0].exited_at.is_some());
}

#[test]
fn pid_reuse_keeps_processes_separate() {
    let app = p(100, 10, "app.exe");
    let other = p(100, 99, "other.exe");
    let b = run(
        spec(&app, false),
        vec![
            (
                Ok(vec![app.clone()]),
                Ok(vec![row(100, 50000, TcpState::Established)]),
            ),
            // PID 100 now belongs to another program with its own socket.
            (
                Ok(vec![other]),
                Ok(vec![row(100, 50001, TcpState::Established)]),
            ),
        ],
    );
    assert_eq!(
        kinds(&b),
        [
            "process_tracked",
            "endpoint_appeared",
            "pid_reused",
            "endpoint_disappeared"
        ]
    );
    assert_eq!(
        b[1].snapshot.attributed_rows, 0,
        "rows of the new PID owner must not be attributed"
    );
}

#[test]
fn restart_with_same_image_is_followed() {
    let app = p(100, 10, "app.exe");
    let again = p(200, 50, "app.exe");
    let b = run(
        spec(&app, true),
        vec![
            (Ok(vec![app.clone()]), Ok(vec![])),
            (
                Ok(vec![again]),
                Ok(vec![row(200, 50002, TcpState::SynSent)]),
            ),
        ],
    );
    assert_eq!(
        kinds(&b),
        [
            "process_tracked",
            "process_exited",
            "process_tracked",
            "endpoint_appeared"
        ]
    );
}

#[test]
fn unavailable_source_is_reported_not_faked() {
    let app = p(100, 10, "app.exe");
    let unavailable = || SourceError::Unavailable {
        reason: "test".into(),
    };
    let b = run(
        spec(&app, false),
        vec![(Err(unavailable()), Err(unavailable()))],
    );
    assert!(b[0].endpoints.is_empty());
    assert_eq!(kinds(&b), ["source_error", "source_error"]);
    assert_eq!(b[0].coverage.snapshots_failed, 1);
    assert!(!b[0].coverage.tcp_available);
    assert!(b[0]
        .snapshot
        .error
        .as_deref()
        .unwrap()
        .contains("unavailable"));
}

#[test]
fn tcp_table_failure_does_not_create_disappearances() {
    let app = p(100, 10, "app.exe");
    let b = run(
        spec(&app, false),
        vec![
            (
                Ok(vec![app.clone()]),
                Ok(vec![row(100, 50000, TcpState::Established)]),
            ),
            (
                Ok(vec![app.clone()]),
                Err(SourceError::AccessDenied { detail: "x".into() }),
            ),
            (
                Ok(vec![app.clone()]),
                Ok(vec![row(100, 50000, TcpState::Established)]),
            ),
        ],
    );
    assert_eq!(
        kinds(&b),
        ["process_tracked", "endpoint_appeared", "source_error"]
    );
    assert_eq!(b[2].coverage.snapshots_ok, 2);
    assert_eq!(b[2].coverage.max_gap_ms, 2000);
}

#[test]
fn listeners_can_be_excluded() {
    let app = p(100, 10, "app.exe");
    let mut l = row(100, 8080, TcpState::Listen);
    l.remote_addr = Some("0.0.0.0".parse().unwrap());
    l.remote_port = Some(0);
    let mut prov = Replay(vec![(Ok(vec![app.clone()]), Ok(vec![l]))].into());
    let settings = SessionSettings {
        include_listeners: false,
        ..Default::default()
    };
    let mut st = CollectorState::new("s".into(), "replay", spec(&app, false), settings);
    let b = st.tick(1, &mut prov);
    assert_eq!(b.snapshot.attributed_rows, 0);
}

struct Mem(Arc<Mutex<Vec<TickBatch>>>);
impl SessionSink for Mem {
    fn write(&mut self, b: &TickBatch) -> Result<(), String> {
        self.0.lock().unwrap().push(b.clone());
        Ok(())
    }
}

#[test]
fn threaded_collector_starts_and_stops_with_final_batch() {
    let app = p(100, 10, "app.exe");
    let steps: VecDeque<Step> = (0..1000)
        .map(|_| (Ok(vec![app.clone()]), Ok(vec![])))
        .collect();
    let store = Arc::new(Mutex::new(Vec::new()));
    let settings = SessionSettings {
        poll_interval_ms: 250,
        ..Default::default()
    };
    let st = CollectorState::new("s".into(), "replay", spec(&app, false), settings);
    let statuses = Arc::new(Mutex::new(0usize));
    let s2 = statuses.clone();
    let h = ni_collector::start(
        st,
        Box::new(Replay(steps)),
        Box::new(Mem(store.clone())),
        Box::new(move |_| *s2.lock().unwrap() += 1),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let sum = h.stop("user").unwrap();
    let batches = store.lock().unwrap();
    assert!(batches.len() >= 3, "{}", batches.len());
    assert!(matches!(
        batches[0].events[0].kind,
        EventKind::SessionStarted
    ));
    let last = batches.last().unwrap();
    assert!(last.is_final);
    assert!(
        matches!(&last.events[0].kind, EventKind::SessionStopped { reason } if reason == "user")
    );
    assert!(sum.coverage.snapshots_ok >= 2);
    assert!(*statuses.lock().unwrap() >= 1);
}
