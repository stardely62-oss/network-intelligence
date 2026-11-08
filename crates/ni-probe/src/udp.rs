//! UDP request/response probe.
//!
//! A missing reply is reported as `noReply` and nothing more: many UDP
//! services ignore datagrams they do not expect, so silence is not evidence
//! of filtering. Payloads are chosen from fixed presets so the probe sends
//! well-formed requests (DNS query, STUN binding request) or the user's own
//! short text.

use crate::errors::{self, ErrorClass};
use crate::{dns, ms, select_addrs, Families, Target};
use ni_core::addr::Family;
use ni_core::probe::{ProbeReport, UdpAttempt, UdpOutcome};
use ni_core::time::now_ms;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub const MAX_TEXT_PAYLOAD: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Empty,
    Text(String),
    /// DNS query (type A, recursion desired) for the given name.
    DnsQuery(String),
    /// RFC 5389 STUN Binding Request.
    StunBinding,
}

impl Payload {
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Payload::Empty => Vec::new(),
            Payload::Text(t) => t
                .as_bytes()
                .iter()
                .take(MAX_TEXT_PAYLOAD)
                .copied()
                .collect(),
            Payload::DnsQuery(name) => dns_query(name, txid()),
            Payload::StunBinding => {
                let mut v = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
                let t = txid();
                for i in 0..6u16 {
                    v.extend_from_slice(&(t.wrapping_mul(i + 1)).to_be_bytes());
                }
                v
            }
        }
    }
}

fn txid() -> u16 {
    (now_ms() as u64 ^ std::process::id() as u64) as u16
}

/// Minimal DNS query message (RFC 1035 §4.1) for `name`, QTYPE A, QCLASS IN.
pub fn dns_query(name: &str, id: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + name.len());
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        let l = &label.as_bytes()[..label.len().min(63)];
        v.push(l.len() as u8);
        v.extend_from_slice(l);
    }
    v.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);
    v
}

pub fn send_once(addr: IpAddr, port: u16, payload: &[u8], timeout: Duration) -> UdpAttempt {
    let timeout = crate::clamp_timeout(timeout);
    let started_at = now_ms();
    let mk = |outcome| UdpAttempt {
        addr,
        family: Family::of(&addr),
        port,
        payload_len: payload.len(),
        started_at,
        outcome,
    };
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => {
            return mk(UdpOutcome::Failed {
                error: errors::os_error(&e),
            })
        }
    };
    // A connected UDP socket receives ICMP port-unreachable as an error.
    if let Err(e) = sock.connect(SocketAddr::new(addr, port)) {
        return mk(UdpOutcome::Failed {
            error: errors::os_error(&e),
        });
    }
    if let Err(e) = sock.set_read_timeout(Some(timeout)) {
        return mk(UdpOutcome::Failed {
            error: errors::os_error(&e),
        });
    }
    let start = Instant::now();
    if let Err(e) = sock.send(payload) {
        return mk(match errors::classify(&e) {
            ErrorClass::Reset | ErrorClass::Refused => UdpOutcome::PortUnreachable {
                elapsed_ms: ms(start.elapsed()),
                error: errors::os_error(&e),
            },
            _ => UdpOutcome::Failed {
                error: errors::os_error(&e),
            },
        });
    }
    let mut buf = [0u8; 2048];
    let deadline = start + timeout;
    loop {
        match sock.recv(&mut buf) {
            Ok(n) => {
                return mk(UdpOutcome::Reply {
                    elapsed_ms: ms(start.elapsed()),
                    bytes: n,
                })
            }
            Err(e) => match errors::classify(&e) {
                ErrorClass::WouldBlock | ErrorClass::TimedOut => {
                    return mk(UdpOutcome::NoReply {
                        timeout_ms: timeout.as_millis() as u64,
                    })
                }
                ErrorClass::Reset | ErrorClass::Refused => {
                    return mk(UdpOutcome::PortUnreachable {
                        elapsed_ms: ms(start.elapsed()),
                        error: errors::os_error(&e),
                    })
                }
                _ if e.kind() == std::io::ErrorKind::Interrupted && Instant::now() < deadline => {
                    continue
                }
                _ => {
                    return mk(UdpOutcome::Failed {
                        error: errors::os_error(&e),
                    })
                }
            },
        }
    }
}

pub fn probe(
    target: &Target,
    port: u16,
    payload: &Payload,
    fam: Families,
    timeout: Duration,
) -> ProbeReport {
    let bytes = payload.bytes();
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
        .map(|a| send_once(a, port, &bytes, timeout))
        .collect();
    ProbeReport::Udp {
        target: format!("{label}:{port}"),
        dns,
        attempts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_encoding() {
        let q = dns_query("example.com", 0xABCD);
        assert_eq!(&q[..4], &[0xAB, 0xCD, 0x01, 0x00]);
        assert_eq!(&q[4..6], &[0, 1]); // QDCOUNT
        assert_eq!(&q[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
    }

    #[test]
    fn stun_binding_is_20_bytes_with_cookie() {
        let b = Payload::StunBinding.bytes();
        assert_eq!(b.len(), 20);
        assert_eq!(&b[..2], &[0, 1]);
        assert_eq!(&b[4..8], &[0x21, 0x12, 0xA4, 0x42]);
    }

    #[test]
    fn text_payload_is_capped() {
        assert_eq!(
            Payload::Text("x".repeat(2000)).bytes().len(),
            MAX_TEXT_PAYLOAD
        );
    }
}
