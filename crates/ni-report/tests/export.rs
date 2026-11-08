use ni_core::process::{ProcessIdentity, TargetSpec};
use ni_core::session::{SessionMeta, SessionSettings, SessionStatus, SESSION_SCHEMA_VERSION};
use ni_core::source::Coverage;
use ni_report::{build, to_json, ExportOptions, Report, REPORT_FORMAT, REPORT_SCHEMA};
use ni_storage::Store;

fn store_with_session() -> Store {
    let s = Store::open_in_memory().unwrap();
    s.create_session(&SessionMeta {
        id: "s".into(),
        schema: SESSION_SCHEMA_VERSION,
        title: "Discord.exe".into(),
        started_at: 1,
        ended_at: Some(2),
        status: SessionStatus::Completed,
        target: TargetSpec {
            root: ProcessIdentity {
                pid: 1,
                created: Some(1),
            },
            name: "Discord.exe".into(),
            path: Some(r"C:\Users\alice\AppData\Local\Discord\Discord.exe".into()),
            include_children: true,
            include_same_image: true,
        },
        settings: SessionSettings::default(),
        coverage: Coverage::default(),
        note: "секретная заметка".into(),
        app_version: "0.1.0".into(),
    })
    .unwrap();
    s
}

#[test]
fn report_is_versioned_and_redacted_by_default() {
    let s = store_with_session();
    let r = build(&s, "s", ExportOptions::default(), "test").unwrap();
    let j = to_json(&r).unwrap();
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert_eq!(v["format"], REPORT_FORMAT);
    assert_eq!(v["schema"], REPORT_SCHEMA);
    assert!(!j.contains("alice"), "user name leaked");
    assert!(!j.contains("секретная"), "note leaked");
    assert!(v["rules"].as_array().unwrap().len() >= 8);
    assert!(!v["disclaimer"].as_array().unwrap().is_empty());
}

#[test]
fn unredacted_report_roundtrips() {
    let s = store_with_session();
    let o = ExportOptions {
        redact_private_ips: false,
        redact_local_addresses: false,
        redact_paths: false,
        include_notes: true,
        include_events: true,
    };
    let r = build(&s, "s", o, "test").unwrap();
    let j = to_json(&r).unwrap();
    let back: Report = serde_json::from_str(&j).unwrap();
    assert_eq!(back.session.note, "секретная заметка");
    assert_eq!(
        back.session.target.path.as_deref(),
        Some(r"C:\Users\alice\AppData\Local\Discord\Discord.exe")
    );
}

#[test]
fn missing_session_is_an_error() {
    let s = store_with_session();
    assert!(build(&s, "nope", ExportOptions::default(), "test").is_err());
}
