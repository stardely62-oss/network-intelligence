//! Manual test server for trying Network Intelligence locally:
//!   cargo run -p ni-probe --example test_server
//! TCP echo on 127.0.0.1:47001, UDP echo on 127.0.0.1:47002, silent UDP on
//! 127.0.0.1:47003. Loopback only.
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};

fn main() {
    let tcp = TcpListener::bind("127.0.0.1:47001").expect("tcp 47001");
    let udp = UdpSocket::bind("127.0.0.1:47002").expect("udp 47002");
    let _silent = UdpSocket::bind("127.0.0.1:47003").expect("udp 47003");
    println!("TCP echo 127.0.0.1:47001, UDP echo 127.0.0.1:47002, UDP silent 127.0.0.1:47003; Ctrl+C to stop");
    std::thread::spawn(move || {
        let mut b = [0u8; 2048];
        while let Ok((n, p)) = udp.recv_from(&mut b) {
            let _ = udp.send_to(&b[..n], p);
        }
    });
    for s in tcp.incoming().flatten() {
        std::thread::spawn(move || {
            let mut s = s;
            let mut b = [0u8; 1024];
            while let Ok(n) = s.read(&mut b) {
                if n == 0 || s.write_all(&b[..n]).is_err() {
                    break;
                }
            }
        });
    }
}
