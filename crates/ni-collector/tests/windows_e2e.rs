//! End-to-end on real Windows: the collector, with the real IP Helper
//! provider, observes this test process and a child process.
#![cfg(windows)]

use ni_collector::CollectorState;
use ni_core::endpoint::TcpState;
use ni_core::event::EventKind;
use ni_core::process::TargetSpec;
use ni_core::session::SessionSettings;
use ni_core::time::now_ms;
use std::net::{TcpListener, TcpStream};

fn own_spec() -> TargetSpec {
    let me = std::process::id();
    let mut prov = ni_windows::provider();
    let p = prov
        .processes()
        .unwrap()
        .into_iter()
        .find(|p| p.identity.pid == me)
        .unwrap();
    TargetSpec {
        root: p.identity,
        name: p.name,
        path: p.path,
        include_children: true,
        include_same_image: false,
    }
}

#[test]
fn observes_own_connection_lifecycle() {
    let mut prov = ni_windows::provider();
    let mut st = CollectorState::new(
        "e2e".into(),
        prov.name(),
        own_spec(),
        SessionSettings::default(),
    );
    st.tick(now_ms(), prov.as_mut());

    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (srv, _) = l.accept().unwrap();
    let cport = c.local_addr().unwrap().port();

    let b = st.tick(now_ms(), prov.as_mut());
    let appeared = b.events.iter().any(|e| {
        matches!(&e.kind,
        EventKind::EndpointAppeared { endpoint, state: Some(TcpState::Established), .. }
            if endpoint.local_port == cport && endpoint.remote_port == Some(port))
    });
    assert!(appeared, "client endpoint not observed: {:#?}", b.events);

    drop(c);
    drop(srv);
    drop(l);
    // The client side may linger in FIN_WAIT/TIME_WAIT; poll a few times.
    let mut gone_or_changed = false;
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let b = st.tick(now_ms(), prov.as_mut());
        if b.events.iter().any(|e| match &e.kind {
            EventKind::EndpointDisappeared { endpoint, .. }
            | EventKind::EndpointStateChanged { endpoint, .. } => endpoint.local_port == cport,
            _ => false,
        }) {
            gone_or_changed = true;
            break;
        }
    }
    assert!(
        gone_or_changed,
        "closing the socket was not reflected in later snapshots"
    );
}

#[test]
fn child_process_exit_is_observed() {
    let mut child = std::process::Command::new("cmd.exe")
        .args(["/C", "ping", "-n", "2", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let cpid = child.id();
    let mut prov = ni_windows::provider();
    let mut st = CollectorState::new(
        "e2e".into(),
        prov.name(),
        own_spec(),
        SessionSettings::default(),
    );
    let b = st.tick(now_ms(), prov.as_mut());
    assert!(
        b.events.iter().any(|e| matches!(&e.kind, EventKind::ProcessTracked { identity, .. } if identity.pid == cpid)),
        "child not tracked"
    );
    child.wait().unwrap();
    let b = st.tick(now_ms(), prov.as_mut());
    assert!(b.events.iter().any(
        |e| matches!(&e.kind, EventKind::ProcessExited { identity, .. } if identity.pid == cpid)
    ));
}
