//! Data sources, their errors and the observation coverage of a session.

use crate::endpoint::SocketRow;
use crate::process::ProcessInfo;
use serde::{Deserialize, Serialize};

/// Where a piece of data came from. Shown next to every value in the UI so
/// an active probe result is never confused with what the application did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSource {
    /// Attributed to the analysed process (e.g. a socket table row owned by
    /// one of its PIDs).
    ObservedProcess,
    /// A check Network Intelligence performed itself on user request.
    ActiveProbe,
    /// System-wide state not attributed to a process (process list, errors
    /// of the snapshot itself).
    SystemSnapshot,
    /// Event Tracing for Windows. Reserved: no ETW collector exists in 0.1.
    Etw,
    /// Entered by the user (notes, markers).
    User,
}

impl DataSource {
    pub fn as_str(self) -> &'static str {
        match self {
            DataSource::ObservedProcess => "observed_process",
            DataSource::ActiveProbe => "active_probe",
            DataSource::SystemSnapshot => "system_snapshot",
            DataSource::Etw => "etw",
            DataSource::User => "user",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SourceError {
    /// The source does not exist on this platform/build.
    #[error("data source unavailable: {reason}")]
    Unavailable { reason: String },
    #[error("access denied: {detail}")]
    AccessDenied { detail: String },
    #[error("OS error {code}: {message}")]
    Os { code: i64, message: String },
}

/// A periodic snapshot provider (socket tables + process list).
///
/// Implementations must return only data actually read from the OS. A
/// snapshot is a point-in-time inventory: connections that open and close
/// between two calls are not visible.
pub trait SnapshotProvider: Send {
    /// Short machine name of the provider, stored with the session.
    fn name(&self) -> &'static str;
    fn processes(&mut self) -> Result<Vec<ProcessInfo>, SourceError>;
    fn tcp(&mut self) -> Result<Vec<SocketRow>, SourceError>;
    fn udp(&mut self) -> Result<Vec<SocketRow>, SourceError>;
}

/// Future event-driven collectors (ETW, WFP) implement this. 0.1 ships no
/// implementation; the trait exists so the collector and storage do not
/// assume that snapshots are the only possible input.
pub trait EventProvider: Send {
    fn name(&self) -> &'static str;
    /// Drains events received since the previous call.
    fn drain(&mut self) -> Result<Vec<crate::event::Event>, SourceError>;
}

/// A provider for platforms without an implementation. Every call reports
/// [`SourceError::Unavailable`]; it never returns fabricated rows.
pub struct UnavailableProvider {
    pub reason: String,
}

impl SnapshotProvider for UnavailableProvider {
    fn name(&self) -> &'static str {
        "unavailable"
    }
    fn processes(&mut self) -> Result<Vec<ProcessInfo>, SourceError> {
        Err(SourceError::Unavailable {
            reason: self.reason.clone(),
        })
    }
    fn tcp(&mut self) -> Result<Vec<SocketRow>, SourceError> {
        Err(SourceError::Unavailable {
            reason: self.reason.clone(),
        })
    }
    fn udp(&mut self) -> Result<Vec<SocketRow>, SourceError> {
        Err(SourceError::Unavailable {
            reason: self.reason.clone(),
        })
    }
}

/// What a session could and could not observe. Stored with the session and
/// included in every report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    pub provider: String,
    pub poll_interval_ms: u64,
    pub snapshots_ok: u64,
    pub snapshots_failed: u64,
    /// Largest gap between two successful snapshots (ms). Connections that
    /// lived shorter than the gaps can be missed entirely.
    pub max_gap_ms: u64,
    /// Tracked processes whose creation time could not be read (identity is
    /// PID-only and PID reuse cannot be ruled out).
    pub pid_only_identities: u64,
    pub tcp_available: bool,
    pub udp_available: bool,
    pub etw_available: bool,
    /// Human-readable, fixed explanations of blind spots.
    pub limitations: Vec<String>,
    pub last_error: Option<String>,
}

/// The fixed limitations of the snapshot collector, stated in every session.
pub fn snapshot_limitations() -> Vec<String> {
    vec![
        "Таблицы сокетов опрашиваются периодически: соединения, открытые и закрытые между двумя снимками, не видны.".into(),
        "Исчезновение endpoint означает его отсутствие в более позднем снимке, а не точный момент закрытия.".into(),
        "UDP-строки — только локальные привязки: в системной таблице UDP нет удалённого адреса, пакетов и ответов.".into(),
        "TCP-сокеты в TIME_WAIT обычно принадлежат PID 0 и не могут быть отнесены к приложению.".into(),
        "DNS-имена, байты, пакеты, RTT и повторные передачи в версии 0.1 не собираются (нет источника ETW/ESTATS).".into(),
        "Пакеты не перехватываются: содержимое, TLS/SNI и признаки DPI не наблюдаются.".into(),
    ]
}
