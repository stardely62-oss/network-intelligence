//! Diagnostic session metadata.

use crate::process::{TargetSpec, TrackedProcess};
use crate::source::Coverage;
use crate::time::UnixMs;
use serde::{Deserialize, Serialize};

pub const SESSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionStatus {
    Recording,
    Completed,
    /// The application exited/crashed while recording; the session was
    /// closed on the next start. Data up to the last snapshot is kept.
    Interrupted,
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionStatus::Recording => "recording",
            SessionStatus::Completed => "completed",
            SessionStatus::Interrupted => "interrupted",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "recording" => SessionStatus::Recording,
            "completed" => SessionStatus::Completed,
            "interrupted" => SessionStatus::Interrupted,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSettings {
    /// Snapshot interval. Lower values see more short-lived connections at
    /// a higher CPU cost; nothing guarantees complete coverage.
    pub poll_interval_ms: u64,
    pub include_children: bool,
    pub include_same_image: bool,
    /// Also record LISTEN sockets (servers inside the application).
    pub include_listeners: bool,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            poll_interval_ms: 1000,
            include_children: true,
            include_same_image: true,
            include_listeners: true,
        }
    }
}

impl SessionSettings {
    pub const MIN_POLL_MS: u64 = 250;
    pub const MAX_POLL_MS: u64 = 10_000;
    pub fn clamped(mut self) -> Self {
        self.poll_interval_ms = self
            .poll_interval_ms
            .clamp(Self::MIN_POLL_MS, Self::MAX_POLL_MS);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMeta {
    pub id: String,
    pub schema: u32,
    pub title: String,
    pub started_at: UnixMs,
    pub ended_at: Option<UnixMs>,
    pub status: SessionStatus,
    pub target: TargetSpec,
    pub settings: SessionSettings,
    pub coverage: Coverage,
    pub note: String,
    pub app_version: String,
}

/// Aggregate shown while recording and in session lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SessionCounts {
    pub endpoints: u64,
    pub tcp_endpoints: u64,
    pub udp_endpoints: u64,
    pub present_endpoints: u64,
    pub remote_addresses: u64,
    pub events: u64,
    pub processes: u64,
    pub probes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveStatus {
    pub session_id: String,
    pub ts: UnixMs,
    pub snapshots_ok: u64,
    pub snapshots_failed: u64,
    pub last_snapshot_ms: f64,
    pub tracked_alive: usize,
    pub processes: Vec<TrackedProcess>,
    pub counts: SessionCounts,
    pub last_error: Option<String>,
    pub running: bool,
}
