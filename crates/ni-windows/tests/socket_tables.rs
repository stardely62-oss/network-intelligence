//! Real IP Helper tables on Windows: sockets opened by this test process
//! must appear with the right owner PID, ports, family and state.
#![cfg(windows)]

use ni_core::addr::Family;
use ni_core::endpoint::{Protocol, TcpState};
use std::net::{TcpListener, TcpStream, UdpSocket};

fn me() -> u32 {
    std::process::id()
}

#[test]
fn tcp_ipv4_listener_and_established_pair_are_listed() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (_s, _) = l.accept().unwrap();
    let cport = c.local_addr().unwrap().port();

    let rows = ni_windows::tcp_table().expect("tcp table");
    let mine: Vec<_> = rows.iter().filter(|r| r.pid == me()).collect();
    assert!(
        mine.iter().any(|r| r.local_port == port
            && r.state == Some(TcpState::Listen)
            && r.remote_addr.is_none()),
        "listener missing: {mine:#?}"
    );
    let client = mine
        .iter()
        .find(|r| r.local_port == cport && r.remote_port == Some(port))
        .unwrap_or_else(|| panic!("client side missing: {mine:#?}"));
    assert_eq!(client.state, Some(TcpState::Established));
    assert_eq!(client.socket_family, Family::Ipv4);
    assert_eq!(client.remote_addr, Some("127.0.0.1".parse().unwrap()));
    assert_eq!(client.protocol, Protocol::Tcp);
}

#[test]
fn tcp_ipv6_loopback_is_listed() {
    let Ok(l) = TcpListener::bind("[::1]:0") else {
        eprintln!("IPv6 loopback unavailable on this machine; skipped");
        return;
    };
    let port = l.local_addr().unwrap().port();
    let c = TcpStream::connect(("::1", port)).unwrap();
    let (_s, _) = l.accept().unwrap();
    let cport = c.local_addr().unwrap().port();
    let rows = ni_windows::tcp_table().unwrap();
    let r = rows
        .iter()
        .find(|r| r.pid == me() && r.local_port == cport)
        .expect("ipv6 client row");
    assert_eq!(r.socket_family, Family::Ipv6);
    assert_eq!(r.remote_addr, Some("::1".parse().unwrap()));
    assert_eq!(r.state, Some(TcpState::Established));
}

#[test]
fn udp_bindings_are_local_only() {
    let s4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let p4 = s4.local_addr().unwrap().port();
    let s6 = UdpSocket::bind("[::1]:0").ok();
    let rows = ni_windows::udp_table().expect("udp table");
    let r = rows
        .iter()
        .find(|r| r.pid == me() && r.local_port == p4)
        .expect("udp v4 row");
    assert_eq!(r.protocol, Protocol::Udp);
    assert_eq!(r.remote_addr, None);
    assert_eq!(r.state, None);
    if let Some(s6) = s6 {
        let p6 = s6.local_addr().unwrap().port();
        let r = rows
            .iter()
            .find(|r| r.pid == me() && r.local_port == p6)
            .expect("udp v6 row");
        assert_eq!(r.socket_family, Family::Ipv6);
    }
}

#[test]
fn closed_socket_disappears_from_next_table() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    assert!(ni_windows::tcp_table()
        .unwrap()
        .iter()
        .any(|r| r.pid == me() && r.local_port == port));
    drop(l);
    assert!(!ni_windows::tcp_table()
        .unwrap()
        .iter()
        .any(|r| r.pid == me() && r.local_port == port && r.state == Some(TcpState::Listen)));
}

#[test]
fn provider_reports_name_and_elevation_is_known() {
    let mut p = ni_windows::provider();
    assert_eq!(p.name(), "windows-iphlpapi-toolhelp");
    assert!(!p.processes().unwrap().is_empty());
    assert!(ni_windows::is_elevated().is_some());
}
