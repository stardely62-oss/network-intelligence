//! Snapshot collection for a diagnostic session.
//!
//! A background thread polls a [`SnapshotProvider`] at the session interval,
//! keeps the target process set up to date ([`TargetTracker`]), correlates
//! socket rows into endpoints ([`Correlator`]) and hands one [`TickBatch`]
//! per snapshot to a [`SessionSink`] (storage). The UI is notified through a
//! throttled status callback instead of per-row updates.

use ni_core::correlate::Correlator;
use ni_core::endpoint::{EndpointRecord, Protocol, SocketRow, TcpState};
use ni_core::event::{Event, EventKind};
use ni_core::process::{TargetSpec, TargetTracker, TrackedProcess, TrackerChange};
use ni_core::session::{LiveStatus, SessionCounts, SessionSettings};
use ni_core::source::{snapshot_limitations, Coverage, DataSource, SnapshotProvider, SourceError};
use ni_core::time::{now_ms, UnixMs};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotInfo {
    pub ts: UnixMs,
    pub duration_ms: f64,
    pub processes_ok: bool,
    pub tcp_ok: bool,
    pub udp_ok: bool,
    pub tcp_rows_total: usize,
    pub udp_rows_total: usize,
    pub attributed_rows: usize,
    pub error: Option<String>,
}

/// Everything one snapshot produced, persisted atomically by the sink.
#[derive(Debug, Clone)]
pub struct TickBatch {
    pub snapshot: SnapshotInfo,
    pub events: Vec<Event>,
    /// New or changed endpoint records (full current state).
    pub endpoints: Vec<EndpointRecord>,
    /// All processes tracked so far (small; full state each tick).
    pub processes: Vec<TrackedProcess>,
    pub coverage: Coverage,
    /// The closing batch written when the collector stops: it carries no
    /// snapshot and must not be stored as one.
    pub is_final: bool,
}

pub trait SessionSink: Send {
    fn write(&mut self, batch: &TickBatch) -> Result<(), String>;
}

pub type StatusFn = Box<dyn Fn(LiveStatus) + Send>;

/// Deterministic per-snapshot logic, independent of threads and clocks.
pub struct CollectorState {
    pub session_id: String,
    settings: SessionSettings,
    tracker: TargetTracker,
    correlator: Correlator,
    coverage: Coverage,
    last_ok: Option<UnixMs>,
    events_total: u64,
}

impl CollectorState {
    pub fn new(
        session_id: String,
        provider_name: &str,
        spec: TargetSpec,
        settings: SessionSettings,
    ) -> Self {
        let settings = settings.clamped();
        let coverage = Coverage {
            provider: provider_name.to_string(),
            poll_interval_ms: settings.poll_interval_ms,
            tcp_available: false,
            udp_available: false,
            etw_available: false,
            limitations: snapshot_limitations(),
            ..Default::default()
        };
        Self {
            session_id,
            settings,
            tracker: TargetTracker::new(spec),
            correlator: Correlator::new(),
            coverage,
            last_ok: None,
            events_total: 0,
        }
    }

    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    pub fn tick(&mut self, ts: UnixMs, provider: &mut dyn SnapshotProvider) -> TickBatch {
        let started = Instant::now();
        let mut events = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut err = |component: &str, e: &SourceError, events: &mut Vec<Event>| {
            errors.push(format!("{component}: {e}"));
            events.push(Event::new(
                ts,
                DataSource::SystemSnapshot,
                EventKind::SourceError {
                    component: component.into(),
                    message: e.to_string(),
                },
            ));
        };

        let procs = provider.processes();
        let processes_ok = procs.is_ok();
        match &procs {
            Ok(list) => {
                for ch in self.tracker.update(ts, list) {
                    events.push(change_event(ts, ch));
                }
            }
            Err(e) => err("processes", e, &mut events),
        }

        let tcp = provider.tcp();
        let udp = provider.udp();
        let (tcp_ok, udp_ok) = (tcp.is_ok(), udp.is_ok());
        let tcp_rows_total = tcp.as_ref().map(|v| v.len()).unwrap_or(0);
        let udp_rows_total = udp.as_ref().map(|v| v.len()).unwrap_or(0);
        if let Err(e) = &tcp {
            err("tcp", e, &mut events);
        }
        if let Err(e) = &udp {
            err("udp", e, &mut events);
        }

        // Without a process list the owner of a row cannot be verified, so
        // no rows are attributed and no endpoint is declared gone.
        let mut protocols = Vec::new();
        let mut attributed: Vec<(SocketRow, ni_core::process::ProcessIdentity)> = Vec::new();
        if processes_ok {
            for (ok, rows, proto) in [(tcp_ok, &tcp, Protocol::Tcp), (udp_ok, &udp, Protocol::Udp)]
            {
                if !ok {
                    continue;
                }
                protocols.push(proto);
                for row in rows.as_ref().expect("ok") {
                    if !self.settings.include_listeners && row.state == Some(TcpState::Listen) {
                        continue;
                    }
                    if let Some(id) = self.tracker.owner(row.pid) {
                        attributed.push((row.clone(), id));
                    }
                }
            }
        }
        let attributed_rows = attributed.len();
        let res = self.correlator.ingest(ts, &attributed, &protocols);
        events.extend(res.events);
        let mut touched: Vec<u64> = res.touched;
        touched.sort_unstable();
        touched.dedup();
        let endpoints = touched
            .iter()
            .filter_map(|id| self.correlator.get(*id).cloned())
            .collect();

        // Coverage bookkeeping.
        let all_ok = processes_ok && tcp_ok && udp_ok;
        if all_ok {
            self.coverage.snapshots_ok += 1;
            if let Some(prev) = self.last_ok {
                self.coverage.max_gap_ms = self.coverage.max_gap_ms.max((ts - prev).max(0) as u64);
            }
            self.last_ok = Some(ts);
        } else {
            self.coverage.snapshots_failed += 1;
        }
        self.coverage.tcp_available |= tcp_ok;
        self.coverage.udp_available |= udp_ok;
        let error = (!errors.is_empty()).then(|| errors.join("; "));
        if error.is_some() {
            self.coverage.last_error = error.clone();
        }
        self.coverage.pid_only_identities = self
            .tracker
            .history()
            .iter()
            .filter(|p| p.info.identity.is_pid_only())
            .count() as u64;
        self.events_total += events.len() as u64;

        TickBatch {
            snapshot: SnapshotInfo {
                ts,
                duration_ms: started.elapsed().as_secs_f64() * 1000.0,
                processes_ok,
                tcp_ok,
                udp_ok,
                tcp_rows_total,
                udp_rows_total,
                attributed_rows,
                error,
            },
            events,
            endpoints,
            processes: self.tracker.history().to_vec(),
            coverage: self.coverage.clone(),
            is_final: false,
        }
    }

    pub fn counts(&self) -> SessionCounts {
        let mut c = SessionCounts::default();
        let mut remotes = HashSet::new();
        for r in self.correlator.records() {
            c.endpoints += 1;
            match r.key.protocol {
                Protocol::Tcp => c.tcp_endpoints += 1,
                Protocol::Udp => c.udp_endpoints += 1,
            }
            if r.present {
                c.present_endpoints += 1;
            }
            if let Some(a) = r.key.remote_addr {
                remotes.insert(a);
            }
        }
        c.remote_addresses = remotes.len() as u64;
        c.events = self.events_total;
        c.processes = self.tracker.history().len() as u64;
        c
    }

    pub fn status(&self, ts: UnixMs, last: &SnapshotInfo, running: bool) -> LiveStatus {
        LiveStatus {
            session_id: self.session_id.clone(),
            ts,
            snapshots_ok: self.coverage.snapshots_ok,
            snapshots_failed: self.coverage.snapshots_failed,
            last_snapshot_ms: last.duration_ms,
            tracked_alive: self.tracker.alive().count(),
            processes: self.tracker.history().to_vec(),
            counts: self.counts(),
            last_error: last.error.clone(),
            running,
        }
    }
}

fn change_event(ts: UnixMs, ch: TrackerChange) -> Event {
    let kind = match ch {
        TrackerChange::Tracked(p) => EventKind::ProcessTracked {
            identity: p.info.identity,
            name: p.info.name,
            path: p.info.path,
            reason: p.reason,
        },
        TrackerChange::Exited {
            identity,
            last_seen,
            ..
        } => EventKind::ProcessExited {
            identity,
            last_seen,
        },
        TrackerChange::PidReused { old, new, new_name } => {
            EventKind::PidReused { old, new, new_name }
        }
    };
    Event::new(ts, DataSource::SystemSnapshot, kind)
}

/// Final information returned when a collector stops.
#[derive(Debug, Clone)]
pub struct CollectorSummary {
    pub coverage: Coverage,
    pub counts: SessionCounts,
    pub sink_errors: u64,
}

pub struct CollectorHandle {
    stop: mpsc::Sender<String>,
    join: Option<JoinHandle<CollectorSummary>>,
}

impl CollectorHandle {
    /// Stops the loop after the current snapshot and waits for it.
    pub fn stop(mut self, reason: &str) -> Option<CollectorSummary> {
        let _ = self.stop.send(reason.to_string());
        self.join.take().and_then(|j| j.join().ok())
    }
    pub fn is_finished(&self) -> bool {
        self.join.as_ref().map(|j| j.is_finished()).unwrap_or(true)
    }
}

impl Drop for CollectorHandle {
    fn drop(&mut self) {
        let _ = self.stop.send("dropped".into());
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Starts the collection thread. The first snapshot is taken immediately.
pub fn start(
    mut state: CollectorState,
    mut provider: Box<dyn SnapshotProvider>,
    mut sink: Box<dyn SessionSink>,
    on_status: StatusFn,
) -> std::io::Result<CollectorHandle> {
    let (tx, rx) = mpsc::channel::<String>();
    let interval = Duration::from_millis(state.settings.poll_interval_ms);
    let join = std::thread::Builder::new()
        .name("ni-collector".into())
        .spawn(move || {
            let mut sink_errors = 0u64;
            let mut last_status = Instant::now() - Duration::from_secs(10);
            let started = now_ms();
            let first = Event::new(started, DataSource::User, EventKind::SessionStarted);
            let mut pending_first = Some(first);
            let reason = loop {
                let tick_start = Instant::now();
                let ts = now_ms();
                let mut batch = state.tick(ts, provider.as_mut());
                if let Some(e) = pending_first.take() {
                    batch.events.insert(0, e);
                }
                if let Err(e) = sink.write(&batch) {
                    sink_errors += 1;
                    state.coverage.last_error = Some(format!("storage: {e}"));
                }
                if last_status.elapsed() >= Duration::from_millis(900) {
                    on_status(state.status(ts, &batch.snapshot, true));
                    last_status = Instant::now();
                }
                let wait = interval.saturating_sub(tick_start.elapsed());
                match rx.recv_timeout(wait) {
                    Ok(reason) => break reason,
                    Err(RecvTimeoutError::Disconnected) => break "dropped".to_string(),
                    Err(RecvTimeoutError::Timeout) => {}
                }
            };
            let ts = now_ms();
            let stop = TickBatch {
                snapshot: SnapshotInfo {
                    ts,
                    duration_ms: 0.0,
                    processes_ok: true,
                    tcp_ok: true,
                    udp_ok: true,
                    tcp_rows_total: 0,
                    udp_rows_total: 0,
                    attributed_rows: 0,
                    error: None,
                },
                events: vec![Event::new(
                    ts,
                    DataSource::User,
                    EventKind::SessionStopped { reason },
                )],
                endpoints: Vec::new(),
                processes: state.tracker.history().to_vec(),
                coverage: state.coverage.clone(),
                is_final: true,
            };
            if sink.write(&stop).is_err() {
                sink_errors += 1;
            }
            let last = stop.snapshot.clone();
            on_status(state.status(ts, &last, false));
            CollectorSummary {
                coverage: state.coverage.clone(),
                counts: state.counts(),
                sink_errors,
            }
        })?;
    Ok(CollectorHandle {
        stop: tx,
        join: Some(join),
    })
}
