//! Decoding of IP Helper table fields.
//!
//! IP Helper stores IPv4 addresses and ports in network byte order inside
//! `DWORD`s. Decoding works on the in-memory bytes (`to_ne_bytes`), which is
//! correct regardless of host endianness.

use ni_core::addr::Family;
use ni_core::endpoint::{Protocol, SocketRow, TcpState};
use ni_core::time::{plausible_filetime, UnixMs};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `dwLocalAddr` / `dwRemoteAddr` → IPv4 address.
pub fn ipv4_from_dword(dw: u32) -> Ipv4Addr {
    Ipv4Addr::from(dw.to_ne_bytes())
}

/// `dwLocalPort` / `dwRemotePort` → port (only the low-address two bytes
/// are meaningful, in network order).
pub fn port_from_dword(dw: u32) -> u16 {
    let b = dw.to_ne_bytes();
    u16::from_be_bytes([b[0], b[1]])
}

pub fn ipv6_from_bytes(b: [u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(b)
}

/// Raw fields of a TCP row in decoded form, before normalisation.
#[allow(clippy::too_many_arguments)]
pub fn tcp_row(
    family: Family,
    local: IpAddr,
    local_port_dw: u32,
    remote: IpAddr,
    remote_port_dw: u32,
    state: u32,
    pid: u32,
    create_ts: i64,
    now: UnixMs,
) -> SocketRow {
    SocketRow {
        protocol: Protocol::Tcp,
        socket_family: family,
        local_addr: local,
        local_port: port_from_dword(local_port_dw),
        remote_addr: Some(remote),
        remote_port: Some(port_from_dword(remote_port_dw)),
        pid,
        state: Some(TcpState::from_mib(state)),
        socket_created_at: plausible_filetime(create_ts as u64, now),
    }
    .normalized()
}

pub fn udp_row(
    family: Family,
    local: IpAddr,
    local_port_dw: u32,
    pid: u32,
    create_ts: i64,
    now: UnixMs,
) -> SocketRow {
    SocketRow {
        protocol: Protocol::Udp,
        socket_family: family,
        local_addr: local,
        local_port: port_from_dword(local_port_dw),
        remote_addr: None,
        remote_port: None,
        pid,
        state: None,
        socket_created_at: plausible_filetime(create_ts as u64, now),
    }
    .normalized()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_network_order_fields() {
        // 192.168.1.10 laid out in memory as it is in MIB_TCPROW.
        let dw = u32::from_ne_bytes([192, 168, 1, 10]);
        assert_eq!(ipv4_from_dword(dw), Ipv4Addr::new(192, 168, 1, 10));
        // Port 443 = 0x01BB, stored as bytes [0x01, 0xBB, 0, 0].
        let p = u32::from_ne_bytes([0x01, 0xBB, 0, 0]);
        assert_eq!(port_from_dword(p), 443);
        // Garbage in the upper bytes is ignored.
        let p = u32::from_ne_bytes([0xC3, 0x50, 0xAA, 0xBB]);
        assert_eq!(port_from_dword(p), 50000);
    }

    #[test]
    fn listener_and_mapped_rows_are_normalised() {
        let now = 1_800_000_000_000;
        let r = tcp_row(
            Family::Ipv6,
            IpAddr::V6("::".parse().unwrap()),
            u32::from_ne_bytes([0x1F, 0x90, 0, 0]),
            IpAddr::V6("::".parse().unwrap()),
            0,
            2,
            9,
            0,
            now,
        );
        assert_eq!(r.local_port, 8080);
        assert_eq!(r.remote_addr, None);
        assert_eq!(r.state, Some(TcpState::Listen));
        assert_eq!(r.socket_created_at, None);

        let r = tcp_row(
            Family::Ipv6,
            IpAddr::V6("::ffff:10.0.0.5".parse().unwrap()),
            0,
            IpAddr::V6("::ffff:203.0.113.9".parse().unwrap()),
            u32::from_ne_bytes([0x01, 0xBB, 0, 0]),
            5,
            9,
            0,
            now,
        );
        assert_eq!(r.remote_addr, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(r.socket_family, Family::Ipv6);

        let u = udp_row(
            Family::Ipv4,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            u32::from_ne_bytes([0x14, 0xE9, 0, 0]),
            3,
            0,
            now,
        );
        assert_eq!(u.local_port, 5353);
        assert_eq!(u.remote_addr, None);
        assert_eq!(u.state, None);
    }
}
