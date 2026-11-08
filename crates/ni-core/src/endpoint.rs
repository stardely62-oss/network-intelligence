//! Socket table rows and correlated endpoint records.

use crate::addr::{self, Family, Scope};
use crate::process::ProcessIdentity;
use crate::source::DataSource;
use crate::time::UnixMs;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// TCP states as reported by `MIB_TCP_STATE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl TcpState {
    /// Maps a raw `MIB_TCP_STATE` value (1..=12).
    pub fn from_mib(v: u32) -> Self {
        match v {
            1 => TcpState::Closed,
            2 => TcpState::Listen,
            3 => TcpState::SynSent,
            4 => TcpState::SynRcvd,
            5 => TcpState::Established,
            6 => TcpState::FinWait1,
            7 => TcpState::FinWait2,
            8 => TcpState::CloseWait,
            9 => TcpState::Closing,
            10 => TcpState::LastAck,
            11 => TcpState::TimeWait,
            12 => TcpState::DeleteTcb,
            _ => TcpState::Unknown,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynRcvd => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::DeleteTcb => "DELETE_TCB",
            TcpState::Unknown => "UNKNOWN",
        }
    }
    /// The connection completed its handshake at some point.
    pub fn implies_handshake_completed(self) -> bool {
        matches!(
            self,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck
        )
    }
}

/// One row of a system socket table, as read from the OS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SocketRow {
    pub protocol: Protocol,
    /// Family of the socket table the row came from (an IPv4-mapped peer on
    /// an IPv6 socket keeps `ipv6` here while its address is normalised).
    pub socket_family: Family,
    pub local_addr: IpAddr,
    pub local_port: u16,
    /// `None` for UDP rows and for TCP listeners (remote 0.0.0.0:0 / [::]:0).
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub pid: u32,
    /// TCP only.
    pub state: Option<TcpState>,
    /// Raw socket creation timestamp from the `*_OWNER_MODULE` tables,
    /// converted to Unix ms only if plausible.
    pub socket_created_at: Option<UnixMs>,
}

impl SocketRow {
    /// Normalises addresses (IPv4-mapped → IPv4, unspecified remote → None).
    pub fn normalized(mut self) -> Self {
        self.local_addr = addr::normalize(self.local_addr);
        if let Some(r) = self.remote_addr {
            let r = addr::normalize(r);
            if r.is_unspecified() && self.remote_port.unwrap_or(0) == 0 {
                self.remote_addr = None;
                self.remote_port = None;
            } else {
                self.remote_addr = Some(r);
            }
        }
        if self.protocol == Protocol::Udp {
            self.state = None;
        }
        self
    }
}

/// Identity of an endpoint inside a session. Two observations with the same
/// key in consecutive snapshots are treated as the same socket.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointKey {
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub process: ProcessIdentity,
}

/// How much the observation itself can be trusted (not the cause of a
/// problem — see `finding::Confidence` for that).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ObservationConfidence {
    /// Read from the OS socket table with a process identity that includes
    /// the creation time.
    High,
    /// Read from the OS, but the owning process identity is PID-only
    /// (creation time unavailable), so PID reuse cannot be excluded.
    Medium,
}

/// Correlated view of an endpoint across the snapshots of a session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointRecord {
    /// Sequential id within the session.
    pub id: u64,
    pub key: EndpointKey,
    pub socket_family: Family,
    pub remote_family: Option<Family>,
    pub remote_scope: Option<Scope>,
    pub state: Option<TcpState>,
    /// Distinct TCP states seen, in order of first appearance.
    pub states_seen: Vec<TcpState>,
    pub first_seen: UnixMs,
    pub last_seen: UnixMs,
    /// Number of snapshots in which the endpoint was present.
    pub observations: u64,
    /// Number of separate presence intervals (an endpoint that disappears
    /// and reappears with the same key counts twice).
    pub episodes: u32,
    pub present: bool,
    /// Time of the first snapshot in which the endpoint was missing after its
    /// last presence. The socket closed somewhere in `(last_seen, gone_at]`.
    pub gone_at: Option<UnixMs>,
    pub socket_created_at: Option<UnixMs>,
    pub source: DataSource,
    pub confidence: ObservationConfidence,
    /// Consecutive snapshots in the current state, used by diagnostics (e.g.
    /// a socket stuck in SYN_SENT).
    pub snapshots_in_state: u64,
    /// When the current state was first observed.
    pub state_since: UnixMs,
}
