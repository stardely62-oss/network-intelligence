//! Active checks performed by Network Intelligence itself.
//!
//! They run only on explicit user action, against one explicitly chosen
//! host or IP and port — never against ranges. Results are labelled
//! `active_probe` and say nothing about whether the analysed application
//! itself managed to connect.

pub mod dns;
pub mod errors;
pub mod tcp;
pub mod udp;

use ni_core::addr::{self, Family};
use std::net::IpAddr;
use std::time::Duration;

/// Upper bound of addresses tried per family for one probe.
pub const MAX_ADDRS_PER_FAMILY: usize = 8;
pub const MIN_TIMEOUT: Duration = Duration::from_millis(100);
pub const MAX_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(IpAddr),
    Host(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    #[error("пустая цель")]
    Empty,
    #[error("диапазоны и подсети не поддерживаются: укажите один адрес или имя")]
    Range,
    #[error("недопустимое имя хоста")]
    BadHost,
}

/// Parses a single host name or IP address.
pub fn parse_target(s: &str) -> Result<Target, TargetError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(TargetError::Empty);
    }
    if t.contains('/') || t.contains('*') || t.contains(',') || t.contains(' ') {
        return Err(TargetError::Range);
    }
    if let Some(ip) = addr::parse_single_ip(t) {
        return Ok(Target::Ip(ip));
    }
    let host = t.trim_end_matches('.').to_ascii_lowercase();
    let ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    // "1.2.3.4-1.2.3.9" style input would otherwise pass as a host name.
    let numeric = host
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == '-');
    if numeric && host.contains('-') {
        return Err(TargetError::Range);
    }
    if !ok || numeric {
        return Err(TargetError::BadHost);
    }
    Ok(Target::Host(host))
}

/// Which address families to probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Families {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl Families {
    pub const BOTH: Families = Families {
        ipv4: true,
        ipv6: true,
    };
    pub fn allows(&self, ip: &IpAddr) -> bool {
        match Family::of(ip) {
            Family::Ipv4 => self.ipv4,
            Family::Ipv6 => self.ipv6,
        }
    }
}

pub fn clamp_timeout(t: Duration) -> Duration {
    t.clamp(MIN_TIMEOUT, MAX_TIMEOUT)
}

/// Picks the addresses to try: the given IP, or the resolved ones (IPv4
/// first, then IPv6), limited per family.
pub fn select_addrs(ipv4: &[IpAddr], ipv6: &[IpAddr], fam: Families) -> Vec<IpAddr> {
    let mut v = Vec::new();
    if fam.ipv4 {
        v.extend(ipv4.iter().take(MAX_ADDRS_PER_FAMILY));
    }
    if fam.ipv6 {
        v.extend(ipv6.iter().take(MAX_ADDRS_PER_FAMILY));
    }
    v
}

pub(crate) fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(
            parse_target("1.1.1.1"),
            Ok(Target::Ip("1.1.1.1".parse().unwrap()))
        );
        assert_eq!(
            parse_target("[2606:4700::1111]"),
            Ok(Target::Ip("2606:4700::1111".parse().unwrap()))
        );
        assert_eq!(
            parse_target("Discord.com."),
            Ok(Target::Host("discord.com".into()))
        );
        assert_eq!(
            parse_target("_srv.example.org"),
            Ok(Target::Host("_srv.example.org".into()))
        );
        assert_eq!(parse_target(""), Err(TargetError::Empty));
        assert_eq!(parse_target("10.0.0.0/8"), Err(TargetError::Range));
        assert_eq!(parse_target("10.0.0.1-10.0.0.9"), Err(TargetError::Range));
        assert_eq!(parse_target("a b"), Err(TargetError::Range));
        assert_eq!(parse_target("*.example.com"), Err(TargetError::Range));
        assert_eq!(parse_target("-bad.com"), Err(TargetError::BadHost));
        assert_eq!(parse_target("1.2.3"), Err(TargetError::BadHost));
    }

    #[test]
    fn address_selection_respects_family_and_limit() {
        let v4: Vec<IpAddr> = (1..=10)
            .map(|i| format!("192.0.2.{i}").parse().unwrap())
            .collect();
        let v6: Vec<IpAddr> = vec!["2001:db8::1".parse().unwrap()];
        assert_eq!(
            select_addrs(&v4, &v6, Families::BOTH).len(),
            MAX_ADDRS_PER_FAMILY + 1
        );
        assert_eq!(
            select_addrs(
                &v4,
                &v6,
                Families {
                    ipv4: false,
                    ipv6: true
                }
            ),
            v6
        );
        assert!(select_addrs(
            &v4,
            &v6,
            Families {
                ipv4: false,
                ipv6: false
            }
        )
        .is_empty());
    }
}
