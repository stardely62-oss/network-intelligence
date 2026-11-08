//! Result models of active probes (performed by Network Intelligence itself,
//! never attributed to the analysed application).

use crate::addr::Family;
use crate::time::UnixMs;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const PROBE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OsError {
    /// Raw OS error code (WinSock `WSAE*` on Windows, errno elsewhere).
    pub code: Option<i32>,
    /// Symbolic name when known (e.g. `WSAECONNREFUSED`).
    pub name: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum TcpOutcome {
    /// The three-way handshake completed.
    Connected {
        elapsed_ms: f64,
        local: String,
    },
    /// The peer (or a device on the path) answered with RST.
    Refused {
        elapsed_ms: f64,
        error: OsError,
    },
    /// No answer within the probe's own timeout.
    TimedOut {
        timeout_ms: u64,
    },
    /// Network/host unreachable reported locally or by ICMP.
    Unreachable {
        elapsed_ms: f64,
        error: OsError,
    },
    Failed {
        elapsed_ms: f64,
        error: OsError,
    },
}

impl TcpOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            TcpOutcome::Connected { .. } => "connected",
            TcpOutcome::Refused { .. } => "refused",
            TcpOutcome::TimedOut { .. } => "timedOut",
            TcpOutcome::Unreachable { .. } => "unreachable",
            TcpOutcome::Failed { .. } => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpAttempt {
    pub addr: IpAddr,
    pub family: Family,
    pub port: u16,
    pub started_at: UnixMs,
    pub outcome: TcpOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum DnsOutcome {
    Resolved {
        ipv4: Vec<IpAddr>,
        ipv6: Vec<IpAddr>,
    },
    /// The resolver answered but returned an error (e.g. no such host).
    Failed {
        error: OsError,
    },
    TimedOut {
        timeout_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsResult {
    pub name: String,
    /// Always `system` in 0.1: `getaddrinfo` through the OS resolver, which
    /// may answer from its cache, the hosts file or any configured DNS/DoH.
    pub resolver: String,
    pub elapsed_ms: f64,
    pub outcome: DnsOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum UdpOutcome {
    Reply {
        elapsed_ms: f64,
        bytes: usize,
    },
    /// No datagram within the timeout. This alone proves nothing: many
    /// services never answer unsolicited or malformed datagrams.
    NoReply {
        timeout_ms: u64,
    },
    /// An ICMP port unreachable was reported back (`WSAECONNRESET` on a
    /// connected Windows UDP socket, `ECONNREFUSED` elsewhere).
    PortUnreachable {
        elapsed_ms: f64,
        error: OsError,
    },
    Failed {
        error: OsError,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpAttempt {
    pub addr: IpAddr,
    pub family: Family,
    pub port: u16,
    pub payload_len: usize,
    pub started_at: UnixMs,
    pub outcome: UdpOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ProbeReport {
    Dns(DnsResult),
    Tcp {
        target: String,
        dns: Option<DnsResult>,
        attempts: Vec<TcpAttempt>,
    },
    Udp {
        target: String,
        dns: Option<DnsResult>,
        attempts: Vec<UdpAttempt>,
    },
}

impl ProbeReport {
    pub fn kind(&self) -> &'static str {
        match self {
            ProbeReport::Dns(_) => "dns",
            ProbeReport::Tcp { .. } => "tcp",
            ProbeReport::Udp { .. } => "udp",
        }
    }
    pub fn target(&self) -> String {
        match self {
            ProbeReport::Dns(d) => d.name.clone(),
            ProbeReport::Tcp { target, .. } | ProbeReport::Udp { target, .. } => target.clone(),
        }
    }
    /// One-line factual summary for the timeline.
    pub fn summary(&self) -> String {
        match self {
            ProbeReport::Dns(d) => match &d.outcome {
                DnsOutcome::Resolved { ipv4, ipv6 } => {
                    format!(
                        "resolved: {} IPv4, {} IPv6 ({:.0} ms)",
                        ipv4.len(),
                        ipv6.len(),
                        d.elapsed_ms
                    )
                }
                DnsOutcome::Failed { error } => format!("resolver error: {}", error.message),
                DnsOutcome::TimedOut { timeout_ms } => format!("no answer within {timeout_ms} ms"),
            },
            ProbeReport::Tcp { attempts, dns, .. } => {
                if attempts.is_empty() {
                    return dns_failure(dns);
                }
                count_by(attempts.iter().map(|a| a.outcome.label()))
            }
            ProbeReport::Udp { attempts, dns, .. } => {
                if attempts.is_empty() {
                    return dns_failure(dns);
                }
                count_by(attempts.iter().map(|a| match a.outcome {
                    UdpOutcome::Reply { .. } => "reply",
                    UdpOutcome::NoReply { .. } => "noReply",
                    UdpOutcome::PortUnreachable { .. } => "portUnreachable",
                    UdpOutcome::Failed { .. } => "failed",
                }))
            }
        }
    }
    pub fn ok(&self) -> bool {
        match self {
            ProbeReport::Dns(d) => matches!(d.outcome, DnsOutcome::Resolved { .. }),
            ProbeReport::Tcp { attempts, .. } => attempts
                .iter()
                .any(|a| matches!(a.outcome, TcpOutcome::Connected { .. })),
            ProbeReport::Udp { attempts, .. } => attempts
                .iter()
                .any(|a| matches!(a.outcome, UdpOutcome::Reply { .. })),
        }
    }
}

fn dns_failure(dns: &Option<DnsResult>) -> String {
    match dns {
        Some(d) => format!(
            "no addresses to probe ({})",
            ProbeReport::Dns(d.clone()).summary()
        ),
        None => "no addresses to probe".into(),
    }
}

fn count_by<'a>(it: impl Iterator<Item = &'a str>) -> String {
    let mut v: Vec<(&str, usize)> = Vec::new();
    for l in it {
        match v.iter_mut().find(|(k, _)| *k == l) {
            Some((_, n)) => *n += 1,
            None => v.push((l, 1)),
        }
    }
    v.iter()
        .map(|(k, n)| format!("{k}: {n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRecord {
    pub id: String,
    pub session_id: Option<String>,
    pub started_at: UnixMs,
    pub finished_at: UnixMs,
    pub report: ProbeReport,
}
