//! Numbered schema migrations (`PRAGMA user_version`).

use crate::{Result, StoreError};
use rusqlite::Connection;

const MIGRATIONS: &[&str] = &[
    // 1: initial schema.
    r#"
    CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        schema INTEGER NOT NULL,
        title TEXT NOT NULL,
        started_at INTEGER NOT NULL,
        ended_at INTEGER,
        status TEXT NOT NULL,
        target_json TEXT NOT NULL,
        settings_json TEXT NOT NULL,
        coverage_json TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        app_version TEXT NOT NULL
    );
    CREATE TABLE processes (
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        pid INTEGER NOT NULL,
        created_key INTEGER NOT NULL,      -- FILETIME, or -1 if unknown
        name TEXT NOT NULL,
        path TEXT,
        reason TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        exited_at INTEGER,
        json TEXT NOT NULL,
        PRIMARY KEY (session_id, pid, created_key)
    );
    CREATE TABLE endpoints (
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        id INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        family TEXT NOT NULL,
        local_addr TEXT NOT NULL,
        local_port INTEGER NOT NULL,
        remote_addr TEXT,
        remote_port INTEGER,
        pid INTEGER NOT NULL,
        state TEXT,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        observations INTEGER NOT NULL,
        episodes INTEGER NOT NULL,
        present INTEGER NOT NULL,
        json TEXT NOT NULL,
        PRIMARY KEY (session_id, id)
    );
    CREATE INDEX endpoints_remote ON endpoints(session_id, remote_addr);
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        ts INTEGER NOT NULL,
        kind TEXT NOT NULL,
        source TEXT NOT NULL,
        pid INTEGER,
        endpoint_id INTEGER,
        protocol TEXT,
        remote_addr TEXT,
        json TEXT NOT NULL
    );
    CREATE INDEX events_session_ts ON events(session_id, ts);
    CREATE INDEX events_session_kind ON events(session_id, kind);
    CREATE TABLE snapshots (
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        ts INTEGER NOT NULL,
        duration_ms REAL NOT NULL,
        ok INTEGER NOT NULL,
        tcp_rows INTEGER NOT NULL,
        udp_rows INTEGER NOT NULL,
        attributed INTEGER NOT NULL,
        error TEXT
    );
    CREATE INDEX snapshots_session_ts ON snapshots(session_id, ts);
    CREATE TABLE probes (
        id TEXT PRIMARY KEY,
        session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
        started_at INTEGER NOT NULL,
        finished_at INTEGER NOT NULL,
        kind TEXT NOT NULL,
        target TEXT NOT NULL,
        ok INTEGER NOT NULL,
        json TEXT NOT NULL
    );
    CREATE TABLE findings (
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        id TEXT NOT NULL,
        json TEXT NOT NULL,
        PRIMARY KEY (session_id, id)
    );
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    "#,
];

pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

pub fn migrate(conn: &mut Connection) -> Result<()> {
    let current: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::TooNew {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as u32)?;
        tx.commit()?;
    }
    Ok(())
}
