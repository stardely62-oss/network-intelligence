use crate::state::{Active, AppSettings, AppState};
use base64::Engine;
use ni_collector::CollectorState;
use ni_core::endpoint::{EndpointRecord, TcpState};
use ni_core::event::{Event, EventKind};
use ni_core::finding::Finding;
use ni_core::probe::{ProbeRecord, ProbeReport};
use ni_core::process::{ProcessAccess, TargetSpec, TrackedProcess};
use ni_core::session::{
    LiveStatus, SessionMeta, SessionSettings, SessionStatus, SESSION_SCHEMA_VERSION,
};
use ni_core::source::{Coverage, DataSource};
use ni_core::time::now_ms;
use ni_diagnostics::RuleInfo;
use ni_probe::udp::Payload;
use ni_probe::Families;
use ni_report::ExportOptions;
use ni_storage::{AddressGroup, EventFilter, EventPage, SessionSummary, SnapshotRow, StoreSink};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};

type R<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> R<T> + Send + 'static) -> R<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(err)?
}

// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    version: String,
    platform: String,
    elevated: Option<bool>,
    data_dir: String,
    db_size: u64,
    provider: String,
    collector_available: bool,
    active_session: Option<String>,
}

#[tauri::command]
pub async fn app_info(state: State<'_, AppState>) -> R<AppInfo> {
    let db_size = state.store.lock().map(|s| s.file_size()).unwrap_or(0);
    let p = ni_windows::provider();
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        platform: std::env::consts::OS.into(),
        elevated: ni_windows::is_elevated(),
        data_dir: state.data_dir.display().to_string(),
        db_size,
        provider: p.name().into(),
        collector_available: p.name() != "unavailable",
        active_session: state.active_id(),
    })
}

// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRow {
    pid: u32,
    /// FILETIME as a decimal string: it does not fit a JS number exactly.
    created_key: Option<String>,
    created_at: Option<i64>,
    parent_pid: Option<u32>,
    name: String,
    path: Option<String>,
    access: ProcessAccess,
    threads: u32,
    tcp: u32,
    tcp_established: u32,
    tcp_listen: u32,
    tcp_syn_sent: u32,
    udp: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessList {
    ts: i64,
    processes: Vec<ProcessRow>,
    process_error: Option<String>,
    tcp_error: Option<String>,
    udp_error: Option<String>,
}

#[tauri::command]
pub async fn list_processes() -> R<ProcessList> {
    blocking(|| {
        let mut p = ni_windows::provider();
        let ts = now_ms();
        let procs = p.processes();
        let tcp = p.tcp();
        let udp = p.udp();
        let mut counts: HashMap<u32, [u32; 5]> = HashMap::new();
        if let Ok(rows) = &tcp {
            for r in rows {
                let c = counts.entry(r.pid).or_default();
                c[0] += 1;
                match r.state {
                    Some(TcpState::Established) => c[1] += 1,
                    Some(TcpState::Listen) => c[2] += 1,
                    Some(TcpState::SynSent) => c[3] += 1,
                    _ => {}
                }
            }
        }
        if let Ok(rows) = &udp {
            for r in rows {
                counts.entry(r.pid).or_default()[4] += 1;
            }
        }
        let process_error = procs.as_ref().err().map(|e| e.to_string());
        let processes = procs
            .unwrap_or_default()
            .into_iter()
            .map(|p| {
                let c = counts.get(&p.identity.pid).copied().unwrap_or_default();
                ProcessRow {
                    pid: p.identity.pid,
                    created_key: p.identity.created.map(|c| c.to_string()),
                    created_at: p.created_at,
                    parent_pid: p.parent_pid,
                    name: p.name,
                    path: p.path,
                    access: p.access,
                    threads: p.threads,
                    tcp: c[0],
                    tcp_established: c[1],
                    tcp_listen: c[2],
                    tcp_syn_sent: c[3],
                    udp: c[4],
                }
            })
            .collect();
        Ok(ProcessList {
            ts,
            processes,
            process_error,
            tcp_error: tcp.err().map(|e| e.to_string()),
            udp_error: udp.err().map(|e| e.to_string()),
        })
    })
    .await
}

/// Data URL of the executable's icon, cached per path.
#[tauri::command]
pub async fn process_icon(state: State<'_, AppState>, path: String) -> R<Option<String>> {
    let cached = state.icons.lock().map_err(err)?.get(&path).cloned();
    if let Some(v) = cached {
        return Ok(v);
    }
    let p = path.clone();
    let icon = blocking(move || {
        Ok(ni_windows::icon_png(&p).map(|b| {
            format!(
                "data:image/png;base64,{}",
                base64::engine::general_purpose::STANDARD.encode(b)
            )
        }))
    })
    .await?;
    let mut cache = state.icons.lock().map_err(err)?;
    if cache.len() > 2000 {
        cache.clear();
    }
    cache.insert(path, icon.clone());
    Ok(icon)
}

// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartRequest {
    pid: u32,
    created_key: Option<String>,
    settings: Option<SessionSettings>,
}

#[tauri::command]
pub async fn start_session(
    app: AppHandle,
    state: State<'_, AppState>,
    req: StartRequest,
) -> R<SessionMeta> {
    if let Some(id) = state.active_id() {
        return Err(format!(
            "Уже идёт запись сессии {id}. Остановите её перед началом новой."
        ));
    }
    let created: Option<u64> = match &req.created_key {
        Some(s) => Some(
            s.parse()
                .map_err(|_| "некорректный ключ процесса".to_string())?,
        ),
        None => None,
    };
    let pid = req.pid;
    let info = blocking(move || {
        let mut p = ni_windows::provider();
        let list = p.processes().map_err(err)?;
        let found = list.into_iter().find(|x| x.identity.pid == pid);
        match found {
            Some(x) if created.is_none() || x.identity.created == created => Ok(x),
            Some(_) => Err("PID уже принадлежит другому процессу (исходный процесс завершился). Обновите список.".to_string()),
            None => Err("Процесс уже завершился. Обновите список.".to_string()),
        }
    })
    .await?;

    let settings = req
        .settings
        .unwrap_or_else(|| state.settings().session)
        .clamped();
    let spec = TargetSpec {
        root: info.identity,
        name: info.name.clone(),
        path: info.path.clone(),
        include_children: settings.include_children,
        include_same_image: settings.include_same_image,
    };
    let id = uuid::Uuid::new_v4().to_string();
    let provider = ni_windows::provider();
    let meta = SessionMeta {
        id: id.clone(),
        schema: SESSION_SCHEMA_VERSION,
        title: format!("{} (PID {})", info.name, info.identity.pid),
        started_at: now_ms(),
        ended_at: None,
        status: SessionStatus::Recording,
        target: spec.clone(),
        settings: settings.clone(),
        coverage: Coverage {
            provider: provider.name().into(),
            poll_interval_ms: settings.poll_interval_ms,
            ..Default::default()
        },
        note: String::new(),
        app_version: env!("CARGO_PKG_VERSION").into(),
    };
    state
        .store
        .lock()
        .map_err(err)?
        .create_session(&meta)
        .map_err(err)?;

    let cs = CollectorState::new(id.clone(), provider.name(), spec, settings);
    let sink = StoreSink {
        store: state.store.clone(),
        session_id: id.clone(),
    };
    let live = state.live.clone();
    let handle = ni_collector::start(
        cs,
        provider,
        Box::new(sink),
        Box::new(move |s: LiveStatus| {
            if let Ok(mut g) = live.lock() {
                *g = Some(s.clone());
            }
            let _ = app.emit("live-status", s);
        }),
    )
    .map_err(err)?;
    *state.active.lock().map_err(err)? = Some(Active {
        session_id: id,
        handle,
    });
    Ok(meta)
}

#[tauri::command]
pub async fn stop_session(state: State<'_, AppState>) -> R<Option<SessionMeta>> {
    let store = state.store.clone();
    let Some(a) = state.active.lock().map_err(err)?.take() else {
        return Ok(None);
    };
    let id = a.session_id.clone();
    blocking(move || {
        a.handle.stop("user");
        store
            .lock()
            .map_err(err)?
            .session(&id)
            .map(Some)
            .map_err(err)
    })
    .await
}

#[tauri::command]
pub async fn live_status(state: State<'_, AppState>) -> R<Option<LiveStatus>> {
    let active = state.active_id();
    let live = state.live.lock().map_err(err)?.clone();
    Ok(live.filter(|l| Some(&l.session_id) == active.as_ref() || !l.running))
}

fn clean_text(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

#[tauri::command]
pub async fn add_marker(state: State<'_, AppState>, session_id: String, label: String) -> R<()> {
    let label = clean_text(&label, 200);
    let label = if label.is_empty() {
        "Маркер".to_string()
    } else {
        label
    };
    state
        .store
        .lock()
        .map_err(err)?
        .add_event(
            &session_id,
            &Event::new(now_ms(), DataSource::User, EventKind::UserMarker { label }),
        )
        .map_err(err)
}

#[tauri::command]
pub async fn set_note(state: State<'_, AppState>, session_id: String, note: String) -> R<()> {
    state
        .store
        .lock()
        .map_err(err)?
        .set_note(&session_id, &clean_text(&note, 10_000))
        .map_err(err)
}

#[tauri::command]
pub async fn rename_session(
    state: State<'_, AppState>,
    session_id: String,
    title: String,
) -> R<()> {
    let t = clean_text(&title, 200);
    if t.is_empty() {
        return Err("Название не может быть пустым".into());
    }
    state
        .store
        .lock()
        .map_err(err)?
        .rename_session(&session_id, &t)
        .map_err(err)
}

#[tauri::command]
pub async fn list_sessions(state: State<'_, AppState>) -> R<Vec<SessionSummary>> {
    let store = state.store.clone();
    blocking(move || store.lock().map_err(err)?.sessions().map_err(err)).await
}

#[tauri::command]
pub async fn get_session(state: State<'_, AppState>, session_id: String) -> R<SessionSummary> {
    let store = state.store.clone();
    blocking(move || {
        let s = store.lock().map_err(err)?;
        let meta = s.session(&session_id).map_err(err)?;
        Ok(SessionSummary {
            counts: s.counts(&session_id).map_err(err)?,
            meta,
        })
    })
    .await
}

#[tauri::command]
pub async fn delete_session(state: State<'_, AppState>, session_id: String) -> R<()> {
    if state.active_id().as_deref() == Some(session_id.as_str()) {
        return Err("Нельзя удалить сессию, которая сейчас записывается".into());
    }
    state
        .store
        .lock()
        .map_err(err)?
        .delete_session(&session_id)
        .map_err(err)
}

#[tauri::command]
pub async fn delete_all_history(state: State<'_, AppState>) -> R<()> {
    state.stop_active("history cleared");
    *state.live.lock().map_err(err)? = None;
    let store = state.store.clone();
    blocking(move || store.lock().map_err(err)?.delete_all().map_err(err)).await
}

#[tauri::command]
pub async fn session_groups(
    state: State<'_, AppState>,
    session_id: String,
) -> R<Vec<AddressGroup>> {
    let store = state.store.clone();
    blocking(move || {
        store
            .lock()
            .map_err(err)?
            .address_groups(&session_id)
            .map_err(err)
    })
    .await
}

#[tauri::command]
pub async fn session_endpoints(
    state: State<'_, AppState>,
    session_id: String,
) -> R<Vec<EndpointRecord>> {
    let store = state.store.clone();
    blocking(move || {
        store
            .lock()
            .map_err(err)?
            .endpoints(&session_id)
            .map_err(err)
    })
    .await
}

#[tauri::command]
pub async fn session_events(
    state: State<'_, AppState>,
    session_id: String,
    filter: EventFilter,
) -> R<EventPage> {
    let store = state.store.clone();
    blocking(move || {
        store
            .lock()
            .map_err(err)?
            .events(&session_id, &filter)
            .map_err(err)
    })
    .await
}

#[tauri::command]
pub async fn session_snapshots(
    state: State<'_, AppState>,
    session_id: String,
) -> R<Vec<SnapshotRow>> {
    let store = state.store.clone();
    blocking(move || {
        store
            .lock()
            .map_err(err)?
            .snapshots(&session_id)
            .map_err(err)
    })
    .await
}

#[tauri::command]
pub async fn session_processes(
    state: State<'_, AppState>,
    session_id: String,
) -> R<Vec<TrackedProcess>> {
    let store = state.store.clone();
    blocking(move || {
        store
            .lock()
            .map_err(err)?
            .processes(&session_id)
            .map_err(err)
    })
    .await
}

#[tauri::command]
pub async fn session_probes(
    state: State<'_, AppState>,
    session_id: Option<String>,
) -> R<Vec<ProbeRecord>> {
    let store = state.store.clone();
    blocking(move || {
        store
            .lock()
            .map_err(err)?
            .probes(session_id.as_deref())
            .map_err(err)
    })
    .await
}

// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRequest {
    kind: String,
    target: String,
    port: Option<u16>,
    ipv4: bool,
    ipv6: bool,
    timeout_ms: u64,
    payload: Option<PayloadSpec>,
    session_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum PayloadSpec {
    Empty,
    Text { value: String },
    DnsQuery { value: String },
    Stun,
}

#[tauri::command]
pub async fn run_probe(state: State<'_, AppState>, req: ProbeRequest) -> R<ProbeRecord> {
    let target = ni_probe::parse_target(&req.target).map_err(err)?;
    let fam = Families {
        ipv4: req.ipv4,
        ipv6: req.ipv6,
    };
    if !fam.ipv4 && !fam.ipv6 {
        return Err("Выберите хотя бы одно семейство адресов".into());
    }
    let timeout = Duration::from_millis(req.timeout_ms);
    let kind = req.kind.clone();
    let port = req.port;
    if kind != "dns" && port.unwrap_or(0) == 0 {
        return Err("Укажите порт 1–65535".into());
    }
    let payload = match req.payload {
        None | Some(PayloadSpec::Empty) => Payload::Empty,
        Some(PayloadSpec::Text { value }) => Payload::Text(value),
        Some(PayloadSpec::DnsQuery { value }) => {
            let n = ni_probe::parse_target(&value).map_err(err)?;
            match n {
                ni_probe::Target::Host(h) => Payload::DnsQuery(h),
                ni_probe::Target::Ip(_) => {
                    return Err("Для DNS-запроса укажите имя, а не IP".into())
                }
            }
        }
        Some(PayloadSpec::Stun) => Payload::StunBinding,
    };
    let session_id = req.session_id.filter(|s| !s.is_empty());
    let probe_id = uuid::Uuid::new_v4().to_string();
    let store = state.store.clone();
    let target_label = req.target.trim().to_string();

    if let Some(sid) = &session_id {
        let e = Event::new(
            now_ms(),
            DataSource::ActiveProbe,
            EventKind::ProbeStarted {
                probe_id: probe_id.clone(),
                kind: kind.clone(),
                target: target_label.clone(),
            },
        );
        let _ = store.lock().map_err(err)?.add_event(sid, &e);
    }

    let started_at = now_ms();
    let report: ProbeReport = blocking(move || {
        Ok(match kind.as_str() {
            "dns" => match &target {
                ni_probe::Target::Host(h) => ProbeReport::Dns(ni_probe::dns::resolve(h, timeout)),
                ni_probe::Target::Ip(_) => return Err("DNS-проверка требует имя хоста".into()),
            },
            "tcp" => ni_probe::tcp::probe(&target, port.unwrap_or(0), fam, timeout),
            "udp" => ni_probe::udp::probe(&target, port.unwrap_or(0), &payload, fam, timeout),
            _ => return Err("неизвестный тип проверки".into()),
        })
    })
    .await?;
    let rec = ProbeRecord {
        id: probe_id.clone(),
        session_id: session_id.clone(),
        started_at,
        finished_at: now_ms(),
        report,
    };
    let mut s = store.lock().map_err(err)?;
    s.save_probe(&rec).map_err(err)?;
    if let Some(sid) = &session_id {
        let e = Event::new(
            rec.finished_at,
            DataSource::ActiveProbe,
            EventKind::ProbeFinished {
                probe_id,
                kind: rec.report.kind().into(),
                target: rec.report.target(),
                summary: rec.report.summary(),
                ok: rec.report.ok(),
            },
        );
        let _ = s.add_event(sid, &e);
    }
    Ok(rec)
}

#[tauri::command]
pub async fn analyze_session(state: State<'_, AppState>, session_id: String) -> R<Vec<Finding>> {
    let store = state.store.clone();
    blocking(move || {
        let mut s = store.lock().map_err(err)?;
        let meta = s.session(&session_id).map_err(err)?;
        let endpoints = s.endpoints(&session_id).map_err(err)?;
        let probes = s.probes(Some(&session_id)).map_err(err)?;
        let duration = meta.ended_at.unwrap_or_else(now_ms) - meta.started_at;
        let findings = ni_diagnostics::evaluate(&ni_diagnostics::SessionEvidence {
            endpoints: &endpoints,
            probes: &probes,
            coverage: &meta.coverage,
            duration_ms: duration,
        });
        s.save_findings(&session_id, &findings).map_err(err)?;
        Ok(findings)
    })
    .await
}

#[tauri::command]
pub async fn session_findings(state: State<'_, AppState>, session_id: String) -> R<Vec<Finding>> {
    state
        .store
        .lock()
        .map_err(err)?
        .findings(&session_id)
        .map_err(err)
}

#[tauri::command]
pub async fn rule_catalog() -> R<Vec<RuleInfo>> {
    Ok(ni_diagnostics::catalog())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    path: String,
    bytes: u64,
}

/// Writes the report to the path the user picked in the native save dialog.
#[tauri::command]
pub async fn export_session(
    state: State<'_, AppState>,
    session_id: String,
    options: ExportOptions,
    path: String,
) -> R<ExportResult> {
    if !path.to_ascii_lowercase().ends_with(".json") {
        return Err("Файл отчёта должен иметь расширение .json".into());
    }
    let store = state.store.clone();
    blocking(move || {
        let report = {
            let s = store.lock().map_err(err)?;
            ni_report::build(
                &s,
                &session_id,
                options,
                concat!("Network Intelligence ", env!("CARGO_PKG_VERSION")),
            )
            .map_err(err)?
        };
        let json = ni_report::to_json(&report).map_err(err)?;
        std::fs::write(&path, json.as_bytes()).map_err(err)?;
        Ok(ExportResult {
            path,
            bytes: json.len() as u64,
        })
    })
    .await
}

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> R<AppSettings> {
    Ok(state.settings())
}

#[tauri::command]
pub async fn set_settings(state: State<'_, AppState>, settings: AppSettings) -> R<AppSettings> {
    let mut s = settings;
    s.session = s.session.clamped();
    s.retention_days = s.retention_days.min(3650);
    state.save_settings(&s)?;
    Ok(s)
}
