//! SQLite storage of diagnostic sessions.
//!
//! One database file per user (`%LOCALAPPDATA%\NetworkIntelligence\ni.sqlite3`
//! in the desktop app). Schema changes go through numbered migrations
//! tracked in `PRAGMA user_version`; a database created by a newer version
//! is refused instead of being modified.
//!
//! Every record keeps its full JSON form (`json` column) next to a few
//! indexed columns used for filtering, so the model can evolve without
//! losing data.

mod migrations;

use ni_collector::{SessionSink, TickBatch};
use ni_core::endpoint::EndpointRecord;
use ni_core::event::{Event, EventKind};
use ni_core::finding::Finding;
use ni_core::probe::ProbeRecord;
use ni_core::process::TrackedProcess;
use ni_core::session::{SessionCounts, SessionMeta, SessionStatus};
use ni_core::source::Coverage;
use ni_core::time::UnixMs;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub use migrations::SCHEMA_VERSION;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database schema {found} is newer than supported {supported}")]
    TooNew { found: u32, supported: u32 },
    #[error("session not found: {0}")]
    NotFound(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub meta: SessionMeta,
    pub counts: SessionCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredEvent {
    pub id: i64,
    #[serde(flatten)]
    pub event: Event,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventFilter {
    #[serde(default)]
    pub kinds: Vec<String>,
    pub protocol: Option<String>,
    /// Substring match on the remote address.
    pub addr: Option<String>,
    pub pid: Option<u32>,
    pub from: Option<UnixMs>,
    pub to: Option<UnixMs>,
    #[serde(default)]
    pub sources: Vec<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventPage {
    pub total: u64,
    pub events: Vec<StoredEvent>,
}

/// All endpoints sharing one remote address (or one local binding for
/// endpoints without a remote, e.g. UDP).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressGroup {
    /// Remote address; `None` groups endpoints without a remote address.
    pub remote_addr: Option<String>,
    pub family: Option<String>,
    pub scope: Option<String>,
    pub endpoints: u64,
    pub tcp: u64,
    pub udp: u64,
    pub ports: Vec<u16>,
    pub pids: Vec<u32>,
    pub states: Vec<String>,
    pub first_seen: UnixMs,
    pub last_seen: UnixMs,
    pub observations: u64,
    pub episodes: u64,
    pub present: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotRow {
    pub ts: UnixMs,
    pub duration_ms: f64,
    pub ok: bool,
    pub tcp_rows: u64,
    pub udp_rows: u64,
    pub attributed: u64,
    pub error: Option<String>,
}

fn parse<T: serde::de::DeserializeOwned>(i: usize, s: String) -> rusqlite::Result<T> {
    serde_json::from_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Text, Box::new(e))
    })
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        restrict_permissions(path);
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let mut s = Self { conn };
        migrations::migrate(&mut s.conn)?;
        Ok(s)
    }

    pub fn schema_version(&self) -> Result<u32> {
        Ok(self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?)
    }

    // ----- sessions -----

    pub fn create_session(&self, m: &SessionMeta) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sessions(id, schema, title, started_at, ended_at, status, target_json, settings_json, coverage_json, note, app_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                m.id,
                m.schema,
                m.title,
                m.started_at,
                m.ended_at,
                m.status.as_str(),
                serde_json::to_string(&m.target)?,
                serde_json::to_string(&m.settings)?,
                serde_json::to_string(&m.coverage)?,
                m.note,
                m.app_version
            ],
        )?;
        Ok(())
    }

    pub fn finish_session(
        &self,
        id: &str,
        ended_at: UnixMs,
        status: SessionStatus,
        coverage: &Coverage,
    ) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE sessions SET ended_at = ?2, status = ?3, coverage_json = ?4 WHERE id = ?1",
            params![
                id,
                ended_at,
                status.as_str(),
                serde_json::to_string(coverage)?
            ],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound(id.into()));
        }
        Ok(())
    }

    /// Sessions left in `recording` by a crash or forced exit are closed as
    /// `interrupted` at the time of their last stored snapshot.
    pub fn close_interrupted(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE sessions SET status = 'interrupted',
               ended_at = COALESCE((SELECT MAX(ts) FROM snapshots WHERE session_id = sessions.id), started_at)
             WHERE status = 'recording'",
            [],
        )?)
    }

    pub fn set_note(&self, id: &str, note: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions SET note = ?2 WHERE id = ?1",
            params![id, note],
        )?;
        Ok(())
    }

    pub fn rename_session(&self, id: &str, title: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions SET title = ?2 WHERE id = ?1",
            params![id, title],
        )?;
        Ok(())
    }

    fn meta_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SessionMeta> {
        let status: String = r.get(5)?;
        Ok(SessionMeta {
            id: r.get(0)?,
            schema: r.get(1)?,
            title: r.get(2)?,
            started_at: r.get(3)?,
            ended_at: r.get(4)?,
            status: SessionStatus::parse(&status).unwrap_or(SessionStatus::Interrupted),
            target: parse(6, r.get(6)?)?,
            settings: parse(7, r.get(7)?)?,
            coverage: parse(8, r.get(8)?)?,
            note: r.get(9)?,
            app_version: r.get(10)?,
        })
    }

    const META_COLS: &'static str =
        "id, schema, title, started_at, ended_at, status, target_json, settings_json, coverage_json, note, app_version";

    pub fn session(&self, id: &str) -> Result<SessionMeta> {
        self.conn
            .query_row(
                &format!("SELECT {} FROM sessions WHERE id = ?1", Self::META_COLS),
                [id],
                Self::meta_from_row,
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(id.into()))
    }

    pub fn sessions(&self) -> Result<Vec<SessionSummary>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {} FROM sessions ORDER BY started_at DESC",
            Self::META_COLS
        ))?;
        let metas: Vec<SessionMeta> = st
            .query_map([], Self::meta_from_row)?
            .collect::<rusqlite::Result<_>>()?;
        metas
            .into_iter()
            .map(|meta| {
                Ok(SessionSummary {
                    counts: self.counts(&meta.id)?,
                    meta,
                })
            })
            .collect()
    }

    pub fn counts(&self, id: &str) -> Result<SessionCounts> {
        let (endpoints, tcp, udp, present, remotes): (i64, i64, i64, i64, i64) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(protocol='tcp'),0), COALESCE(SUM(protocol='udp'),0), COALESCE(SUM(present),0),
                    COUNT(DISTINCT remote_addr)
             FROM endpoints WHERE session_id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let events: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE session_id = ?1",
            [id],
            |r| r.get(0),
        )?;
        let processes: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM processes WHERE session_id = ?1",
            [id],
            |r| r.get(0),
        )?;
        let probes: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM probes WHERE session_id = ?1",
            [id],
            |r| r.get(0),
        )?;
        Ok(SessionCounts {
            endpoints: endpoints as u64,
            tcp_endpoints: tcp as u64,
            udp_endpoints: udp as u64,
            present_endpoints: present as u64,
            remote_addresses: remotes as u64,
            events: events as u64,
            processes: processes as u64,
            probes: probes as u64,
        })
    }

    pub fn delete_session(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM sessions WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Deletes all sessions, probes and findings, then compacts the file so
    /// deleted data does not linger in free pages.
    pub fn delete_all(&self) -> Result<()> {
        self.conn.execute_batch(
            "DELETE FROM probes; DELETE FROM sessions; PRAGMA wal_checkpoint(TRUNCATE); VACUUM;",
        )?;
        Ok(())
    }

    pub fn delete_older_than(&self, ts: UnixMs) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM sessions WHERE started_at < ?1 AND status != 'recording'",
            [ts],
        )?;
        self.conn.execute(
            "DELETE FROM probes WHERE session_id IS NULL AND started_at < ?1",
            [ts],
        )?;
        Ok(n)
    }

    // ----- collection -----

    pub fn write_batch(&mut self, session_id: &str, b: &TickBatch) -> Result<()> {
        let tx = self.conn.transaction()?;
        if !b.is_final {
            let s = &b.snapshot;
            tx.execute(
                "INSERT INTO snapshots(session_id, ts, duration_ms, ok, tcp_rows, udp_rows, attributed, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    session_id,
                    s.ts,
                    s.duration_ms,
                    s.processes_ok && s.tcp_ok && s.udp_ok,
                    s.tcp_rows_total as i64,
                    s.udp_rows_total as i64,
                    s.attributed_rows as i64,
                    s.error
                ],
            )?;
        }
        insert_events(&tx, session_id, &b.events)?;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO endpoints(session_id, id, protocol, family, local_addr, local_port, remote_addr, remote_port, pid,
                                       state, first_seen, last_seen, observations, episodes, present, json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
                 ON CONFLICT(session_id, id) DO UPDATE SET state = excluded.state, last_seen = excluded.last_seen,
                   observations = excluded.observations, episodes = excluded.episodes, present = excluded.present,
                   json = excluded.json",
            )?;
            for e in &b.endpoints {
                st.execute(params![
                    session_id,
                    e.id as i64,
                    e.key.protocol.as_str(),
                    e.socket_family.as_str(),
                    e.key.local_addr.to_string(),
                    e.key.local_port,
                    e.key.remote_addr.map(|a| a.to_string()),
                    e.key.remote_port,
                    e.key.process.pid,
                    e.state.map(|s| s.as_str()),
                    e.first_seen,
                    e.last_seen,
                    e.observations as i64,
                    e.episodes,
                    e.present,
                    serde_json::to_string(e)?
                ])?;
            }
        }
        upsert_processes(&tx, session_id, &b.processes)?;
        tx.execute(
            "UPDATE sessions SET coverage_json = ?2 WHERE id = ?1",
            params![session_id, serde_json::to_string(&b.coverage)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn add_event(&mut self, session_id: &str, e: &Event) -> Result<()> {
        let tx = self.conn.transaction()?;
        insert_events(&tx, session_id, std::slice::from_ref(e))?;
        tx.commit()?;
        Ok(())
    }

    // ----- queries -----

    pub fn endpoints(&self, session_id: &str) -> Result<Vec<EndpointRecord>> {
        let mut st = self
            .conn
            .prepare("SELECT json FROM endpoints WHERE session_id = ?1 ORDER BY id")?;
        let rows = st.query_map([session_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for j in rows {
            out.push(serde_json::from_str(&j?)?);
        }
        Ok(out)
    }

    pub fn address_groups(&self, session_id: &str) -> Result<Vec<AddressGroup>> {
        let eps = self.endpoints(session_id)?;
        let mut groups: Vec<AddressGroup> = Vec::new();
        let mut index: std::collections::HashMap<Option<String>, usize> =
            std::collections::HashMap::new();
        for e in &eps {
            let key = e.key.remote_addr.map(|a| a.to_string());
            let i = *index.entry(key.clone()).or_insert_with(|| {
                groups.push(AddressGroup {
                    remote_addr: key.clone(),
                    family: e.remote_family.map(|f| f.as_str().to_string()),
                    scope: e.remote_scope.map(|s| {
                        serde_json::to_value(s)
                            .ok()
                            .and_then(|v| v.as_str().map(String::from))
                            .unwrap_or_default()
                    }),
                    endpoints: 0,
                    tcp: 0,
                    udp: 0,
                    ports: vec![],
                    pids: vec![],
                    states: vec![],
                    first_seen: e.first_seen,
                    last_seen: e.last_seen,
                    observations: 0,
                    episodes: 0,
                    present: 0,
                });
                groups.len() - 1
            });
            let g = &mut groups[i];
            g.endpoints += 1;
            match e.key.protocol {
                ni_core::endpoint::Protocol::Tcp => g.tcp += 1,
                ni_core::endpoint::Protocol::Udp => g.udp += 1,
            }
            let port = e.key.remote_port.unwrap_or(e.key.local_port);
            if !g.ports.contains(&port) {
                g.ports.push(port);
            }
            if !g.pids.contains(&e.key.process.pid) {
                g.pids.push(e.key.process.pid);
            }
            for s in &e.states_seen {
                let s = s.as_str().to_string();
                if !g.states.contains(&s) {
                    g.states.push(s);
                }
            }
            g.first_seen = g.first_seen.min(e.first_seen);
            g.last_seen = g.last_seen.max(e.last_seen);
            g.observations += e.observations;
            g.episodes += e.episodes as u64;
            g.present += e.present as u64;
        }
        for g in &mut groups {
            g.ports.sort_unstable();
            g.pids.sort_unstable();
        }
        groups.sort_by_key(|g| std::cmp::Reverse(g.last_seen));
        Ok(groups)
    }

    pub fn processes(&self, session_id: &str) -> Result<Vec<TrackedProcess>> {
        let mut st = self
            .conn
            .prepare("SELECT json FROM processes WHERE session_id = ?1 ORDER BY first_seen, pid")?;
        let rows = st.query_map([session_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for j in rows {
            out.push(serde_json::from_str(&j?)?);
        }
        Ok(out)
    }

    pub fn events(&self, session_id: &str, f: &EventFilter) -> Result<EventPage> {
        let mut sql = String::from(" FROM events WHERE session_id = ?");
        let mut args: Vec<rusqlite::types::Value> = vec![session_id.to_string().into()];
        if !f.kinds.is_empty() {
            sql.push_str(&format!(
                " AND kind IN ({})",
                vec!["?"; f.kinds.len()].join(",")
            ));
            args.extend(f.kinds.iter().map(|k| k.clone().into()));
        }
        if !f.sources.is_empty() {
            sql.push_str(&format!(
                " AND source IN ({})",
                vec!["?"; f.sources.len()].join(",")
            ));
            args.extend(f.sources.iter().map(|k| k.clone().into()));
        }
        if let Some(p) = &f.protocol {
            sql.push_str(" AND protocol = ?");
            args.push(p.clone().into());
        }
        if let Some(a) = f.addr.as_ref().filter(|a| !a.is_empty()) {
            sql.push_str(" AND remote_addr LIKE ? ESCAPE '\\'");
            let esc = a
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            args.push(format!("%{esc}%").into());
        }
        if let Some(pid) = f.pid {
            sql.push_str(" AND pid = ?");
            args.push((pid as i64).into());
        }
        if let Some(t) = f.from {
            sql.push_str(" AND ts >= ?");
            args.push(t.into());
        }
        if let Some(t) = f.to {
            sql.push_str(" AND ts <= ?");
            args.push(t.into());
        }
        let total: i64 = self.conn.query_row(
            &format!("SELECT COUNT(*){sql}"),
            rusqlite::params_from_iter(args.iter()),
            |r| r.get(0),
        )?;
        let limit = f.limit.unwrap_or(500).min(5000) as i64;
        let offset = f.offset.unwrap_or(0) as i64;
        let q = format!("SELECT id, json{sql} ORDER BY ts, id LIMIT {limit} OFFSET {offset}");
        let mut st = self.conn.prepare(&q)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (id, j) = row?;
            events.push(StoredEvent {
                id,
                event: serde_json::from_str(&j)?,
            });
        }
        Ok(EventPage {
            total: total as u64,
            events,
        })
    }

    pub fn snapshots(&self, session_id: &str) -> Result<Vec<SnapshotRow>> {
        let mut st = self.conn.prepare(
            "SELECT ts, duration_ms, ok, tcp_rows, udp_rows, attributed, error FROM snapshots WHERE session_id = ?1 ORDER BY ts",
        )?;
        let rows = st.query_map([session_id], |r| {
            Ok(SnapshotRow {
                ts: r.get(0)?,
                duration_ms: r.get(1)?,
                ok: r.get(2)?,
                tcp_rows: r.get::<_, i64>(3)? as u64,
                udp_rows: r.get::<_, i64>(4)? as u64,
                attributed: r.get::<_, i64>(5)? as u64,
                error: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    // ----- probes & findings -----

    pub fn save_probe(&self, p: &ProbeRecord) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO probes(id, session_id, started_at, finished_at, kind, target, ok, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                p.id,
                p.session_id,
                p.started_at,
                p.finished_at,
                p.report.kind(),
                p.report.target(),
                p.report.ok(),
                serde_json::to_string(p)?
            ],
        )?;
        Ok(())
    }

    /// Probes of a session, or standalone probes when `session_id` is None.
    pub fn probes(&self, session_id: Option<&str>) -> Result<Vec<ProbeRecord>> {
        let mut st = self.conn.prepare(
            "SELECT json FROM probes WHERE (session_id = ?1) OR (?1 IS NULL AND session_id IS NULL) ORDER BY started_at DESC",
        )?;
        let rows = st.query_map([session_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for j in rows {
            out.push(serde_json::from_str(&j?)?);
        }
        Ok(out)
    }

    pub fn save_findings(&mut self, session_id: &str, findings: &[Finding]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM findings WHERE session_id = ?1", [session_id])?;
        for f in findings {
            tx.execute(
                "INSERT INTO findings(session_id, id, json) VALUES (?1, ?2, ?3)",
                params![session_id, f.id, serde_json::to_string(f)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn findings(&self, session_id: &str) -> Result<Vec<Finding>> {
        let mut st = self
            .conn
            .prepare("SELECT json FROM findings WHERE session_id = ?1 ORDER BY rowid")?;
        let rows = st.query_map([session_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for j in rows {
            out.push(serde_json::from_str(&j?)?);
        }
        Ok(out)
    }

    // ----- settings -----

    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Size of the database file in bytes (0 for in-memory).
    pub fn file_size(&self) -> u64 {
        self.conn
            .path()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .unwrap_or(0)
    }
}

fn insert_events(tx: &rusqlite::Transaction<'_>, session_id: &str, events: &[Event]) -> Result<()> {
    let mut st = tx.prepare_cached(
        "INSERT INTO events(session_id, ts, kind, source, pid, endpoint_id, protocol, remote_addr, json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    for e in events {
        let ep = e.kind.endpoint();
        st.execute(params![
            session_id,
            e.ts,
            e.kind.name(),
            e.source.as_str(),
            e.kind.pid(),
            ep.map(|x| x.endpoint_id as i64),
            ep.map(|x| x.protocol.as_str()),
            ep.and_then(|x| x.remote_addr.map(|a| a.to_string())),
            serde_json::to_string(e)?
        ])?;
    }
    Ok(())
}

fn upsert_processes(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    procs: &[TrackedProcess],
) -> Result<()> {
    let mut st = tx.prepare_cached(
        "INSERT INTO processes(session_id, pid, created_key, name, path, reason, first_seen, last_seen, exited_at, json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(session_id, pid, created_key) DO UPDATE SET last_seen = excluded.last_seen,
           exited_at = excluded.exited_at, path = excluded.path, json = excluded.json",
    )?;
    for p in procs {
        let id = p.info.identity;
        st.execute(params![
            session_id,
            id.pid,
            id.created.map(|c| c as i64).unwrap_or(-1),
            p.info.name,
            p.info.path,
            serde_json::to_value(p.reason)?
                .as_str()
                .unwrap_or_default()
                .to_string(),
            p.first_seen,
            p.last_seen,
            p.exited_at,
            serde_json::to_string(p)?
        ])?;
    }
    Ok(())
}

/// Owner-only permissions on Unix. On Windows the file lives in the user's
/// `%LOCALAPPDATA%`, whose inherited ACL already limits access to the user,
/// SYSTEM and administrators.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// [`SessionSink`] writing into a shared store.
pub struct StoreSink {
    pub store: Arc<Mutex<Store>>,
    pub session_id: String,
}

impl SessionSink for StoreSink {
    fn write(&mut self, batch: &TickBatch) -> std::result::Result<(), String> {
        let mut s = self
            .store
            .lock()
            .map_err(|_| "store lock poisoned".to_string())?;
        s.write_batch(&self.session_id, batch)
            .map_err(|e| e.to_string())?;
        if batch.is_final {
            let end = batch
                .events
                .iter()
                .find(|e| matches!(e.kind, EventKind::SessionStopped { .. }))
                .map(|e| e.ts);
            if let Some(ts) = end {
                s.finish_session(
                    &self.session_id,
                    ts,
                    SessionStatus::Completed,
                    &batch.coverage,
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }
}
