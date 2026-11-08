use ni_collector::CollectorHandle;
use ni_core::session::{LiveStatus, SessionSettings};
use ni_report::ExportOptions;
use ni_storage::Store;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct Active {
    pub session_id: String,
    pub handle: CollectorHandle,
}

pub struct AppState {
    pub store: Arc<Mutex<Store>>,
    pub active: Mutex<Option<Active>>,
    pub live: Arc<Mutex<Option<LiveStatus>>>,
    pub icons: Mutex<HashMap<String, Option<String>>>,
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    pub session: SessionSettings,
    /// Delete completed sessions older than this many days at startup;
    /// 0 keeps everything.
    pub retention_days: u32,
    pub export: ExportOptions,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            session: SessionSettings::default(),
            retention_days: 30,
            export: ExportOptions::default(),
        }
    }
}

const SETTINGS_KEY: &str = "app.settings.v1";

impl AppState {
    pub fn open(dir: &Path) -> Result<Self, String> {
        let db_path = dir.join("ni.sqlite3");
        let store = Store::open(&db_path).map_err(|e| e.to_string())?;
        store.close_interrupted().map_err(|e| e.to_string())?;
        let st = Self {
            store: Arc::new(Mutex::new(store)),
            active: Mutex::new(None),
            live: Arc::new(Mutex::new(None)),
            icons: Mutex::new(HashMap::new()),
            data_dir: dir.to_path_buf(),
        };
        let settings = st.settings();
        if settings.retention_days > 0 {
            let cutoff = ni_core::time::now_ms() - settings.retention_days as i64 * 86_400_000;
            let _ = st.store.lock().map(|s| s.delete_older_than(cutoff));
        }
        Ok(st)
    }

    pub fn settings(&self) -> AppSettings {
        self.store
            .lock()
            .ok()
            .and_then(|s| s.setting(SETTINGS_KEY).ok().flatten())
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default()
    }

    pub fn save_settings(&self, s: &AppSettings) -> Result<(), String> {
        let j = serde_json::to_string(s).map_err(|e| e.to_string())?;
        self.store
            .lock()
            .map_err(|_| "store lock".to_string())?
            .set_setting(SETTINGS_KEY, &j)
            .map_err(|e| e.to_string())
    }

    pub fn active_id(&self) -> Option<String> {
        let mut g = self.active.lock().ok()?;
        // A collector thread that ended on its own (should not happen) is
        // cleared so a new session can start.
        if g.as_ref().map(|a| a.handle.is_finished()).unwrap_or(false) {
            *g = None;
        }
        g.as_ref().map(|a| a.session_id.clone())
    }

    pub fn stop_active(&self, reason: &str) -> Option<String> {
        let a = self.active.lock().ok()?.take()?;
        let id = a.session_id.clone();
        a.handle.stop(reason);
        Some(id)
    }
}
