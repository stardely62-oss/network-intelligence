//! Local TCP/UDP test servers. Everything binds to loopback only.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::thread;

/// TCP server that accepts connections and echoes data until EOF.
pub fn tcp_echo(bind: &str) -> SocketAddr {
    let l = TcpListener::bind(bind).expect("bind tcp");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            thread::spawn(move || {
                let mut s = s;
                let mut b = [0u8; 1024];
                while let Ok(n) = s.read(&mut b) {
                    if n == 0 || s.write_all(&b[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A loopback port that was just free: bound, then released.
pub fn closed_tcp_port(bind: &str) -> SocketAddr {
    let l = TcpListener::bind(bind).unwrap();
    l.local_addr().unwrap()
}

pub fn closed_udp_port(bind: &str) -> SocketAddr {
    UdpSocket::bind(bind).unwrap().local_addr().unwrap()
}

/// UDP server that answers every datagram with "pong:" + payload.
pub fn udp_echo(bind: &str) -> SocketAddr {
    let s = UdpSocket::bind(bind).expect("bind udp");
    let addr = s.local_addr().unwrap();
    thread::spawn(move || {
        let mut b = [0u8; 2048];
        while let Ok((n, peer)) = s.recv_from(&mut b) {
            let mut out = b"pong:".to_vec();
            out.extend_from_slice(&b[..n]);
            let _ = s.send_to(&out, peer);
        }
    });
    addr
}

/// UDP socket that is bound (so no ICMP unreachable) but never answers.
/// Kept alive by returning it.
pub fn udp_silent(bind: &str) -> UdpSocket {
    UdpSocket::bind(bind).expect("bind udp")
}

/// A TCP listener with backlog 0 that never accepts. Once its queue is
/// full, further handshakes do not complete (Linux drops the SYN; Windows
/// usually answers with RST).
pub fn tcp_never_accepting() -> (socket2::Socket, SocketAddr) {
    use socket2::{Domain, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    s.bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    s.listen(0).unwrap();
    let addr = s.local_addr().unwrap().as_socket().unwrap();
    (s, addr)
}
