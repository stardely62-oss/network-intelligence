//! Timeline events. Every event is a real observation or a user/probe action
//! and carries its data source and the time it was observed.

use crate::endpoint::{Protocol, TcpState};
use crate::process::{ProcessIdentity, TrackReason};
use crate::source::DataSource;
use crate::time::UnixMs;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointRef {
    pub endpoint_id: u64,
    pub protocol: Protocol,
    pub pid: u32,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum EventKind {
    SessionStarted,
    SessionStopped {
        reason: String,
    },
    ProcessTracked {
        identity: ProcessIdentity,
        name: String,
        path: Option<String>,
        reason: TrackReason,
    },
    /// The process was absent from the process list at `ts`; it exited
    /// after `last_seen`.
    ProcessExited {
        identity: ProcessIdentity,
        last_seen: UnixMs,
    },
    PidReused {
        old: ProcessIdentity,
        new: ProcessIdentity,
        new_name: String,
    },
    /// First snapshot containing this endpoint (or a new episode of it).
    EndpointAppeared {
        endpoint: EndpointRef,
        state: Option<TcpState>,
        episode: u32,
        socket_created_at: Option<UnixMs>,
    },
    EndpointStateChanged {
        endpoint: EndpointRef,
        from: TcpState,
        to: TcpState,
    },
    /// Absent from the snapshot at `ts`; last seen at `last_seen`. The exact
    /// close time is unknown.
    EndpointDisappeared {
        endpoint: EndpointRef,
        last_seen: UnixMs,
        last_state: Option<TcpState>,
    },
    /// A data source failed for one snapshot.
    SourceError {
        component: String,
        message: String,
    },
    ProbeStarted {
        probe_id: String,
        kind: String,
        target: String,
    },
    ProbeFinished {
        probe_id: String,
        kind: String,
        target: String,
        summary: String,
        ok: bool,
    },
    UserMarker {
        label: String,
    },
}

impl EventKind {
    /// Stable short name, stored in its own column for filtering.
    pub fn name(&self) -> &'static str {
        match self {
            EventKind::SessionStarted => "session_started",
            EventKind::SessionStopped { .. } => "session_stopped",
            EventKind::ProcessTracked { .. } => "process_tracked",
            EventKind::ProcessExited { .. } => "process_exited",
            EventKind::PidReused { .. } => "pid_reused",
            EventKind::EndpointAppeared { .. } => "endpoint_appeared",
            EventKind::EndpointStateChanged { .. } => "endpoint_state_changed",
            EventKind::EndpointDisappeared { .. } => "endpoint_disappeared",
            EventKind::SourceError { .. } => "source_error",
            EventKind::ProbeStarted { .. } => "probe_started",
            EventKind::ProbeFinished { .. } => "probe_finished",
            EventKind::UserMarker { .. } => "user_marker",
        }
    }

    pub fn endpoint(&self) -> Option<&EndpointRef> {
        match self {
            EventKind::EndpointAppeared { endpoint, .. }
            | EventKind::EndpointStateChanged { endpoint, .. }
            | EventKind::EndpointDisappeared { endpoint, .. } => Some(endpoint),
            _ => None,
        }
    }

    pub fn pid(&self) -> Option<u32> {
        match self {
            EventKind::ProcessTracked { identity, .. }
            | EventKind::ProcessExited { identity, .. } => Some(identity.pid),
            EventKind::PidReused { old, .. } => Some(old.pid),
            _ => self.endpoint().map(|e| e.pid),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// Time of the observation (snapshot time for snapshot-derived events).
    pub ts: UnixMs,
    pub source: DataSource,
    pub kind: EventKind,
}

impl Event {
    pub fn new(ts: UnixMs, source: DataSource, kind: EventKind) -> Self {
        Self { ts, source, kind }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_and_tag() {
        let e = Event::new(
            5,
            DataSource::ObservedProcess,
            EventKind::EndpointStateChanged {
                endpoint: EndpointRef {
                    endpoint_id: 1,
                    protocol: Protocol::Tcp,
                    pid: 42,
                    local_addr: "10.0.0.2".parse().unwrap(),
                    local_port: 50000,
                    remote_addr: Some("2001:db8::1".parse().unwrap()),
                    remote_port: Some(443),
                },
                from: TcpState::SynSent,
                to: TcpState::Established,
            },
        );
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["source"], "observed_process");
        assert_eq!(j["kind"]["type"], "endpointStateChanged");
        assert_eq!(j["kind"]["from"], "SYN_SENT");
        assert_eq!(j["kind"]["endpoint"]["remoteAddr"], "2001:db8::1");
        let back: Event = serde_json::from_value(j).unwrap();
        assert_eq!(back, e);
        assert_eq!(e.kind.name(), "endpoint_state_changed");
        assert_eq!(e.kind.pid(), Some(42));
    }
}
