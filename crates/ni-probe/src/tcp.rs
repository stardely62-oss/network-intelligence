//! TCP connect probe: one handshake per address, measured, then closed
//! without sending data.

use crate::errors::{self, ErrorClass};
use crate::{dns, ms, select_addrs, Families, Target};
use ni_core::addr::Family;
use ni_core::probe::{ProbeReport, TcpAttempt, TcpOutcome};
use ni_core::time::now_ms;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub fn connect_once(addr: IpAddr, port: u16, timeout: Duration) -> TcpAttempt {
    let timeout = crate::clamp_timeout(timeout);
    let started_at = now_ms();
    let start = Instant::now();
    let sa = SocketAddr::new(addr, port);
    let outcome = match TcpStream::connect_timeout(&sa, timeout) {
        Ok(s) => {
            let elapsed_ms = ms(start.elapsed());
            let local = s.local_addr().map(|a| a.to_string()).unwrap_or_default();
            let _ = s.shutdown(std::net::Shutdown::Both);
            TcpOutcome::Connected { elapsed_ms, local }
        }
        Err(e) => {
            let elapsed_ms = ms(start.elapsed());
            match errors::classify(&e) {
                ErrorClass::Refused => TcpOutcome::Refused {
                    elapsed_ms,
                    error: errors::os_error(&e),
                },
                ErrorClass::TimedOut => TcpOutcome::TimedOut {
                    timeout_ms: timeout.as_millis() as u64,
                },
                ErrorClass::Unreachable => TcpOutcome::Unreachable {
                    elapsed_ms,
                    error: errors::os_error(&e),
                },
                _ => TcpOutcome::Failed {
                    elapsed_ms,
                    error: errors::os_error(&e),
                },
            }
        }
    };
    TcpAttempt {
        addr,
        family: Family::of(&addr),
        port,
        started_at,
        outcome,
    }
}

/// Resolves `target` if needed and tries every selected address in turn.
pub fn probe(target: &Target, port: u16, fam: Families, timeout: Duration) -> ProbeReport {
    let (label, dns, addrs) = match target {
        Target::Ip(ip) => (
            ip.to_string(),
            None,
            if fam.allows(ip) { vec![*ip] } else { vec![] },
        ),
        Target::Host(h) => {
            let r = dns::resolve(h, timeout);
            let addrs = match &r.outcome {
                ni_core::probe::DnsOutcome::Resolved { ipv4, ipv6 } => {
                    select_addrs(ipv4, ipv6, fam)
                }
                _ => vec![],
            };
            (h.clone(), Some(r), addrs)
        }
    };
    let attempts = addrs
        .into_iter()
        .map(|a| connect_once(a, port, timeout))
        .collect();
    ProbeReport::Tcp {
        target: format!("{label}:{port}"),
        dns,
        attempts,
    }
}
