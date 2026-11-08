//! Name resolution through the system resolver (`getaddrinfo`).
//!
//! The answer may come from the OS cache, the hosts file, or any DNS /
//! DNS-over-HTTPS configured in Windows. This probe therefore tells what the
//! system resolver returns to applications, not what a specific DNS server
//! answered.

use crate::{errors, ms};
use ni_core::addr::{normalize, Family};
use ni_core::probe::{DnsOutcome, DnsResult};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub fn resolve(name: &str, timeout: Duration) -> DnsResult {
    let timeout = crate::clamp_timeout(timeout);
    let start = Instant::now();
    let (tx, rx) = mpsc::channel();
    let host = name.to_string();
    // getaddrinfo cannot be cancelled. On timeout the thread finishes in the
    // background and its result is dropped.
    let spawned = std::thread::Builder::new()
        .name("ni-dns".into())
        .spawn(move || {
            let r = (host.as_str(), 0u16)
                .to_socket_addrs()
                .map(|it| it.map(|sa| normalize(sa.ip())).collect::<Vec<_>>());
            let _ = tx.send(r);
        });
    let outcome = match spawned {
        Err(e) => DnsOutcome::Failed {
            error: errors::os_error(&e),
        },
        Ok(_) => match rx.recv_timeout(timeout) {
            Ok(Ok(addrs)) => {
                let mut ipv4: Vec<IpAddr> = Vec::new();
                let mut ipv6: Vec<IpAddr> = Vec::new();
                for a in addrs {
                    let v = if Family::of(&a) == Family::Ipv4 {
                        &mut ipv4
                    } else {
                        &mut ipv6
                    };
                    if !v.contains(&a) {
                        v.push(a);
                    }
                }
                DnsOutcome::Resolved { ipv4, ipv6 }
            }
            Ok(Err(e)) => DnsOutcome::Failed {
                error: errors::os_error(&e),
            },
            Err(_) => DnsOutcome::TimedOut {
                timeout_ms: timeout.as_millis() as u64,
            },
        },
    };
    DnsResult {
        name: name.to_string(),
        resolver: "system".into(),
        elapsed_ms: ms(start.elapsed()),
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_localhost_without_network() {
        let r = resolve("localhost", Duration::from_secs(5));
        match r.outcome {
            DnsOutcome::Resolved { ipv4, ipv6 } => {
                assert!(
                    ipv4.iter().chain(ipv6.iter()).all(|a| a.is_loopback()),
                    "localhost must resolve to loopback only: {ipv4:?} {ipv6:?}"
                );
                assert!(!(ipv4.is_empty() && ipv6.is_empty()));
            }
            o => panic!("localhost did not resolve: {o:?}"),
        }
        assert_eq!(r.resolver, "system");
    }

    #[test]
    fn invalid_reserved_name_fails() {
        // RFC 6761: .invalid never resolves.
        let r = resolve("does-not-exist.invalid", Duration::from_secs(10));
        assert!(
            matches!(
                r.outcome,
                DnsOutcome::Failed { .. } | DnsOutcome::TimedOut { .. }
            ),
            "{:?}",
            r.outcome
        );
    }
}
