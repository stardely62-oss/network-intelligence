//! Address normalisation and classification.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn of(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
        }
    }
}

/// What kind of network an address belongs to. Used for display, for
/// redaction in exports and to avoid treating local traffic as remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    Unspecified,
    Loopback,
    /// RFC 1918 / RFC 4193 (ULA).
    Private,
    /// RFC 6598 carrier-grade NAT (100.64.0.0/10).
    SharedCgnat,
    LinkLocal,
    Multicast,
    Broadcast,
    /// RFC 5737 / RFC 3849 documentation ranges.
    Documentation,
    Global,
}

impl Scope {
    /// Addresses that identify the user's own machine or network and are
    /// redacted by default in exports.
    pub fn is_sensitive(self) -> bool {
        matches!(
            self,
            Scope::Loopback | Scope::Private | Scope::SharedCgnat | Scope::LinkLocal
        )
    }
    pub fn is_remote_internet(self) -> bool {
        matches!(self, Scope::Global)
    }
}

/// Canonical form of an address as it is stored and compared:
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) become plain IPv4, so the
/// same peer reached through a dual-stack socket is grouped with its IPv4
/// observations. The original family of the socket is kept separately by
/// the caller where it matters.
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

pub fn scope(ip: &IpAddr) -> Scope {
    match normalize(*ip) {
        IpAddr::V4(v4) => scope_v4(v4),
        IpAddr::V6(v6) => scope_v6(v6),
    }
}

fn scope_v4(ip: Ipv4Addr) -> Scope {
    let o = ip.octets();
    if ip.is_unspecified() {
        Scope::Unspecified
    } else if ip.is_loopback() {
        Scope::Loopback
    } else if ip.is_private() {
        Scope::Private
    } else if o[0] == 100 && (o[1] & 0xC0) == 64 {
        Scope::SharedCgnat
    } else if ip.is_link_local() {
        Scope::LinkLocal
    } else if ip.is_multicast() {
        Scope::Multicast
    } else if ip.is_broadcast() {
        Scope::Broadcast
    } else if ip.is_documentation() {
        Scope::Documentation
    } else {
        Scope::Global
    }
}

fn scope_v6(ip: Ipv6Addr) -> Scope {
    let s = ip.segments();
    if ip.is_unspecified() {
        Scope::Unspecified
    } else if ip.is_loopback() {
        Scope::Loopback
    } else if (s[0] & 0xfe00) == 0xfc00 {
        Scope::Private
    } else if (s[0] & 0xffc0) == 0xfe80 {
        Scope::LinkLocal
    } else if ip.is_multicast() {
        Scope::Multicast
    } else if s[0] == 0x2001 && s[1] == 0x0db8 {
        Scope::Documentation
    } else {
        Scope::Global
    }
}

/// Parses user input as a single IP address (with optional brackets for
/// IPv6). Ranges and CIDR blocks are rejected on purpose: active probes are
/// only run against explicitly chosen single targets.
pub fn parse_single_ip(s: &str) -> Option<IpAddr> {
    let t = s.trim().trim_start_matches('[').trim_end_matches(']');
    if t.contains('/') || t.contains('-') && !t.contains(':') {
        return None;
    }
    t.parse::<IpAddr>().ok().map(normalize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn mapped_ipv6_becomes_ipv4() {
        assert_eq!(normalize(ip("::ffff:192.0.2.10")), ip("192.0.2.10"));
        assert_eq!(normalize(ip("2001:db8::1")), ip("2001:db8::1"));
        assert_eq!(normalize(ip("10.0.0.1")), ip("10.0.0.1"));
        // IPv4-compatible (deprecated) is NOT mapped and stays IPv6.
        assert_eq!(Family::of(&normalize(ip("::1"))), Family::Ipv6);
    }

    #[test]
    fn scopes() {
        assert_eq!(scope(&ip("0.0.0.0")), Scope::Unspecified);
        assert_eq!(scope(&ip("127.0.0.1")), Scope::Loopback);
        assert_eq!(scope(&ip("::1")), Scope::Loopback);
        assert_eq!(scope(&ip("192.168.1.1")), Scope::Private);
        assert_eq!(scope(&ip("172.16.5.4")), Scope::Private);
        assert_eq!(scope(&ip("100.64.1.1")), Scope::SharedCgnat);
        assert_eq!(scope(&ip("100.128.0.1")), Scope::Global);
        assert_eq!(scope(&ip("169.254.1.1")), Scope::LinkLocal);
        assert_eq!(scope(&ip("fe80::1")), Scope::LinkLocal);
        assert_eq!(scope(&ip("fd12:3456::1")), Scope::Private);
        assert_eq!(scope(&ip("224.0.0.251")), Scope::Multicast);
        assert_eq!(scope(&ip("ff02::fb")), Scope::Multicast);
        assert_eq!(scope(&ip("192.0.2.1")), Scope::Documentation);
        assert_eq!(scope(&ip("2001:db8::5")), Scope::Documentation);
        assert_eq!(scope(&ip("162.159.130.234")), Scope::Global);
        assert_eq!(scope(&ip("2606:4700::6810:1")), Scope::Global);
        assert_eq!(scope(&ip("::ffff:10.1.2.3")), Scope::Private);
        assert!(Scope::Private.is_sensitive());
        assert!(!Scope::Global.is_sensitive());
    }

    #[test]
    fn single_ip_parsing_rejects_ranges() {
        assert_eq!(parse_single_ip(" 1.2.3.4 "), Some(ip("1.2.3.4")));
        assert_eq!(parse_single_ip("[2001:db8::1]"), Some(ip("2001:db8::1")));
        assert_eq!(parse_single_ip("1.2.3.0/24"), None);
        assert_eq!(parse_single_ip("1.2.3.1-1.2.3.9"), None);
        assert_eq!(parse_single_ip("example.com"), None);
    }
}
