//! Versioned JSON reports of a diagnostic session.
//!
//! The report contains the session as stored: endpoints, address groups,
//! events, probes, findings and the coverage/limitations. Redaction is
//! applied to the serialised document so no field can be missed by a
//! forgotten code path:
//!
//! * private, loopback, CGNAT and link-local IPs → stable pseudonyms
//!   (`private-ipv4-1`); optionally every local address;
//! * file system paths → file name only (removes user names and folders);
//! * notes and marker labels → removed unless explicitly included.

mod redact;

use ni_core::endpoint::EndpointRecord;
use ni_core::finding::Finding;
use ni_core::probe::ProbeRecord;
use ni_core::process::TrackedProcess;
use ni_core::session::{SessionCounts, SessionMeta};
use ni_core::time::now_ms;
use ni_storage::{AddressGroup, EventFilter, SnapshotRow, Store, StoredEvent};
use serde::{Deserialize, Serialize};

pub const REPORT_FORMAT: &str = "network-intelligence.session-report";
pub const REPORT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportOptions {
    /// Replace private/loopback/link-local/CGNAT addresses with pseudonyms.
    pub redact_private_ips: bool,
    /// Replace every local socket address (including public ones assigned
    /// to this machine) with pseudonyms.
    pub redact_local_addresses: bool,
    /// Reduce file paths to file names.
    pub redact_paths: bool,
    /// Include the session note and marker labels.
    pub include_notes: bool,
    /// Include the full event list (can be large).
    pub include_events: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            redact_private_ips: true,
            redact_local_addresses: true,
            redact_paths: true,
            include_notes: false,
            include_events: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotSummary {
    pub count: u64,
    pub failed: u64,
    pub avg_duration_ms: f64,
    pub max_duration_ms: f64,
    pub first: Option<i64>,
    pub last: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub format: String,
    pub schema: u32,
    pub event_schema: u32,
    pub finding_schema: u32,
    pub generated_at: i64,
    pub generator: String,
    pub redaction: ExportOptions,
    /// Plain-language statement of what this report can and cannot show.
    pub disclaimer: Vec<String>,
    pub session: SessionMeta,
    pub counts: SessionCounts,
    pub processes: Vec<TrackedProcess>,
    pub address_groups: Vec<AddressGroup>,
    pub endpoints: Vec<EndpointRecord>,
    pub events: Vec<StoredEvent>,
    pub events_total: u64,
    pub snapshots: SnapshotSummary,
    pub probes: Vec<ProbeRecord>,
    pub findings: Vec<Finding>,
    /// Rule catalog (implemented and planned) at export time.
    pub rules: Vec<serde_json::Value>,
}

pub fn build(
    store: &Store,
    session_id: &str,
    opts: ExportOptions,
    generator: &str,
) -> ni_storage::Result<Report> {
    let session = store.session(session_id)?;
    let events = if opts.include_events {
        let mut out = Vec::new();
        let mut offset = 0u32;
        loop {
            let page = store.events(
                session_id,
                &EventFilter {
                    limit: Some(5000),
                    offset: Some(offset),
                    ..Default::default()
                },
            )?;
            let n = page.events.len() as u32;
            out.extend(page.events);
            if n < 5000 {
                break;
            }
            offset += n;
        }
        out
    } else {
        Vec::new()
    };
    let snaps: Vec<SnapshotRow> = store.snapshots(session_id)?;
    let durations: Vec<f64> = snaps.iter().map(|s| s.duration_ms).collect();
    let snapshots = SnapshotSummary {
        count: snaps.len() as u64,
        failed: snaps.iter().filter(|s| !s.ok).count() as u64,
        avg_duration_ms: if durations.is_empty() {
            0.0
        } else {
            durations.iter().sum::<f64>() / durations.len() as f64
        },
        max_duration_ms: durations.iter().cloned().fold(0.0, f64::max),
        first: snaps.first().map(|s| s.ts),
        last: snaps.last().map(|s| s.ts),
    };
    let counts = store.counts(session_id)?;
    Ok(Report {
        format: REPORT_FORMAT.into(),
        schema: REPORT_SCHEMA,
        event_schema: ni_core::EVENT_SCHEMA_VERSION,
        finding_schema: ni_core::finding::FINDING_SCHEMA_VERSION,
        generated_at: now_ms(),
        generator: generator.into(),
        redaction: opts,
        disclaimer: vec![
            "Отчёт содержит только реально наблюдавшиеся данные и результаты проверок, выполненных Network Intelligence.".into(),
            "Источник «observed_process» — строки системных таблиц сокетов, отнесённые к процессу; «active_probe» — проверки самого Network Intelligence, не приложения.".into(),
            "Снимки таблиц не являются захватом пакетов и не гарантируют обнаружения всех кратковременных соединений.".into(),
            "Гипотезы в выводах не являются доказательством причины, в том числе DPI-блокировки.".into(),
        ],
        events_total: counts.events,
        counts,
        processes: store.processes(session_id)?,
        address_groups: store.address_groups(session_id)?,
        endpoints: store.endpoints(session_id)?,
        events,
        snapshots,
        probes: store.probes(Some(session_id))?,
        findings: store.findings(session_id)?,
        rules: ni_diagnostics::catalog().iter().filter_map(|r| serde_json::to_value(r).ok()).collect(),
        session,
    })
}

/// Serialises the report with redaction applied.
pub fn to_json(report: &Report) -> serde_json::Result<String> {
    let mut v = serde_json::to_value(report)?;
    redact::apply(&mut v, &report.redaction);
    serde_json::to_string_pretty(&v)
}
