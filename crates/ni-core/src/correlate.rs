//! Turns consecutive socket-table snapshots into endpoint records and
//! timeline events.
//!
//! The correlator only states what the snapshots show: an endpoint appeared
//! in a snapshot, changed state between two snapshots, or was missing from a
//! snapshot. It does not invent close times or intermediate states.

use crate::addr::{self, Family};
use crate::endpoint::{EndpointKey, EndpointRecord, ObservationConfidence, Protocol, SocketRow};
use crate::event::{EndpointRef, Event, EventKind};
use crate::process::ProcessIdentity;
use crate::source::DataSource;
use crate::time::UnixMs;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct Correlator {
    next_id: u64,
    by_key: HashMap<EndpointKey, u64>,
    records: HashMap<u64, EndpointRecord>,
}

/// Result of ingesting one snapshot.
#[derive(Debug, Default)]
pub struct IngestResult {
    pub events: Vec<Event>,
    /// Ids of records that changed (new, state change, disappeared, or just
    /// observed again) and should be persisted.
    pub touched: Vec<u64>,
}

impl Correlator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> impl Iterator<Item = &EndpointRecord> {
        self.records.values()
    }

    pub fn get(&self, id: u64) -> Option<&EndpointRecord> {
        self.records.get(&id)
    }

    /// Ingests one snapshot. `rows` must already be filtered to the tracked
    /// processes; `owner` resolves a row's PID to the tracked identity.
    ///
    /// `protocols` lists the tables that were successfully read in this
    /// snapshot. Endpoints of a protocol whose table failed are left as they
    /// were instead of being reported as disappeared.
    pub fn ingest(
        &mut self,
        ts: UnixMs,
        rows: &[(SocketRow, ProcessIdentity)],
        protocols: &[Protocol],
    ) -> IngestResult {
        let mut res = IngestResult::default();
        let mut seen: HashSet<u64> = HashSet::new();

        for (row, ident) in rows {
            let row = row.clone().normalized();
            let key = EndpointKey {
                protocol: row.protocol,
                local_addr: row.local_addr,
                local_port: row.local_port,
                remote_addr: row.remote_addr,
                remote_port: row.remote_port,
                process: *ident,
            };
            // Several rows can map to one key (e.g. the same UDP port bound
            // on a dual-stack socket listed twice); count it once.
            if let Some(&id) = self.by_key.get(&key) {
                if !seen.insert(id) {
                    continue;
                }
                let rec = self.records.get_mut(&id).expect("indexed");
                let eref = endpoint_ref(rec);
                if !rec.present {
                    rec.present = true;
                    rec.episodes += 1;
                    rec.gone_at = None;
                    rec.state = row.state;
                    rec.state_since = ts;
                    rec.snapshots_in_state = 1;
                    if let Some(s) = row.state {
                        push_state(&mut rec.states_seen, s);
                    }
                    if row.socket_created_at.is_some() {
                        rec.socket_created_at = row.socket_created_at;
                    }
                    res.events.push(Event::new(
                        ts,
                        DataSource::ObservedProcess,
                        EventKind::EndpointAppeared {
                            endpoint: eref,
                            state: row.state,
                            episode: rec.episodes,
                            socket_created_at: rec.socket_created_at,
                        },
                    ));
                } else if row.state != rec.state {
                    if let (Some(from), Some(to)) = (rec.state, row.state) {
                        res.events.push(Event::new(
                            ts,
                            DataSource::ObservedProcess,
                            EventKind::EndpointStateChanged {
                                endpoint: eref,
                                from,
                                to,
                            },
                        ));
                        push_state(&mut rec.states_seen, to);
                    }
                    rec.state = row.state;
                    rec.state_since = ts;
                    rec.snapshots_in_state = 1;
                } else {
                    rec.snapshots_in_state += 1;
                }
                rec.last_seen = ts;
                rec.observations += 1;
                res.touched.push(id);
            } else {
                self.next_id += 1;
                let id = self.next_id;
                let rec = EndpointRecord {
                    id,
                    socket_family: row.socket_family,
                    remote_family: row.remote_addr.map(|a| Family::of(&a)),
                    remote_scope: row.remote_addr.map(|a| addr::scope(&a)),
                    state: row.state,
                    states_seen: row.state.into_iter().collect(),
                    first_seen: ts,
                    last_seen: ts,
                    observations: 1,
                    episodes: 1,
                    present: true,
                    gone_at: None,
                    socket_created_at: row.socket_created_at,
                    source: DataSource::ObservedProcess,
                    confidence: if ident.is_pid_only() {
                        ObservationConfidence::Medium
                    } else {
                        ObservationConfidence::High
                    },
                    snapshots_in_state: 1,
                    state_since: ts,
                    key: key.clone(),
                };
                res.events.push(Event::new(
                    ts,
                    DataSource::ObservedProcess,
                    EventKind::EndpointAppeared {
                        endpoint: endpoint_ref(&rec),
                        state: row.state,
                        episode: 1,
                        socket_created_at: row.socket_created_at,
                    },
                ));
                self.by_key.insert(key, id);
                self.records.insert(id, rec);
                seen.insert(id);
                res.touched.push(id);
            }
        }

        // Disappearances, only for protocols whose table was read.
        let mut gone: Vec<u64> = self
            .records
            .values()
            .filter(|r| r.present && !seen.contains(&r.id) && protocols.contains(&r.key.protocol))
            .map(|r| r.id)
            .collect();
        gone.sort_unstable();
        for id in gone {
            let rec = self.records.get_mut(&id).expect("present");
            rec.present = false;
            rec.gone_at = Some(ts);
            res.events.push(Event::new(
                ts,
                DataSource::ObservedProcess,
                EventKind::EndpointDisappeared {
                    endpoint: endpoint_ref(rec),
                    last_seen: rec.last_seen,
                    last_state: rec.state,
                },
            ));
            res.touched.push(id);
        }
        res
    }
}

fn push_state(v: &mut Vec<crate::endpoint::TcpState>, s: crate::endpoint::TcpState) {
    if !v.contains(&s) {
        v.push(s);
    }
}

pub fn endpoint_ref(r: &EndpointRecord) -> EndpointRef {
    EndpointRef {
        endpoint_id: r.id,
        protocol: r.key.protocol,
        pid: r.key.process.pid,
        local_addr: r.key.local_addr,
        local_port: r.key.local_port,
        remote_addr: r.key.remote_addr,
        remote_port: r.key.remote_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::TcpState;
    use std::net::IpAddr;

    const P: ProcessIdentity = ProcessIdentity {
        pid: 42,
        created: Some(7),
    };
    const BOTH: &[Protocol] = &[Protocol::Tcp, Protocol::Udp];

    fn tcp(remote: &str, rport: u16, lport: u16, state: TcpState) -> SocketRow {
        let r: IpAddr = remote.parse().unwrap();
        SocketRow {
            protocol: Protocol::Tcp,
            socket_family: Family::of(&r),
            local_addr: if r.is_ipv4() {
                "10.0.0.2".parse().unwrap()
            } else {
                "2001:db8::2".parse().unwrap()
            },
            local_port: lport,
            remote_addr: Some(r),
            remote_port: Some(rport),
            pid: P.pid,
            state: Some(state),
            socket_created_at: None,
        }
    }

    fn names(r: &IngestResult) -> Vec<&'static str> {
        r.events.iter().map(|e| e.kind.name()).collect()
    }

    #[test]
    fn lifecycle_appear_change_disappear_reappear() {
        let mut c = Correlator::new();
        let syn = tcp("203.0.113.5", 443, 50001, TcpState::SynSent);
        let est = tcp("203.0.113.5", 443, 50001, TcpState::Established);

        let r = c.ingest(1000, &[(syn.clone(), P)], BOTH);
        assert_eq!(names(&r), ["endpoint_appeared"]);
        let r = c.ingest(2000, &[(syn, P)], BOTH);
        assert!(r.events.is_empty());
        let r = c.ingest(3000, &[(est.clone(), P)], BOTH);
        assert_eq!(names(&r), ["endpoint_state_changed"]);
        let r = c.ingest(4000, &[], BOTH);
        assert_eq!(names(&r), ["endpoint_disappeared"]);
        match &r.events[0].kind {
            EventKind::EndpointDisappeared {
                last_seen,
                last_state,
                ..
            } => {
                assert_eq!(*last_seen, 3000);
                assert_eq!(*last_state, Some(TcpState::Established));
            }
            _ => unreachable!(),
        }
        let rec = c.records().next().unwrap();
        assert_eq!(rec.observations, 3);
        assert_eq!(rec.gone_at, Some(4000));
        assert_eq!(
            rec.states_seen,
            vec![TcpState::SynSent, TcpState::Established]
        );

        // Same 5-tuple again later: a new episode of the same record.
        let r = c.ingest(9000, &[(est, P)], BOTH);
        assert!(matches!(
            r.events[0].kind,
            EventKind::EndpointAppeared { episode: 2, .. }
        ));
        assert_eq!(c.records().count(), 1);
    }

    #[test]
    fn failed_table_does_not_fake_disappearance() {
        let mut c = Correlator::new();
        c.ingest(
            1,
            &[(tcp("203.0.113.5", 443, 1, TcpState::Established), P)],
            BOTH,
        );
        // TCP table could not be read in this snapshot.
        let r = c.ingest(2, &[], &[Protocol::Udp]);
        assert!(r.events.is_empty());
        assert!(c.records().next().unwrap().present);
    }

    #[test]
    fn mapped_ipv6_and_v4_group_by_same_remote() {
        let mut c = Correlator::new();
        let mut mapped = tcp("::ffff:198.51.100.7", 443, 2, TcpState::Established);
        mapped.local_addr = "::ffff:10.0.0.2".parse().unwrap();
        c.ingest(1, &[(mapped, P)], BOTH);
        let rec = c.records().next().unwrap();
        assert_eq!(rec.key.remote_addr, Some("198.51.100.7".parse().unwrap()));
        assert_eq!(rec.socket_family, Family::Ipv6);
        assert_eq!(rec.remote_family, Some(Family::Ipv4));
    }

    #[test]
    fn same_tuple_different_process_identity_is_separate() {
        let mut c = Correlator::new();
        let row = tcp("203.0.113.5", 443, 50001, TcpState::Established);
        c.ingest(1, &[(row.clone(), P)], BOTH);
        let reused = ProcessIdentity {
            pid: 42,
            created: Some(99),
        };
        let r = c.ingest(2, &[(row, reused)], BOTH);
        assert_eq!(names(&r), ["endpoint_appeared", "endpoint_disappeared"]);
        assert_eq!(c.records().count(), 2);
    }

    #[test]
    fn udp_listener_has_no_remote_and_no_state() {
        let mut c = Correlator::new();
        let row = SocketRow {
            protocol: Protocol::Udp,
            socket_family: Family::Ipv4,
            local_addr: "0.0.0.0".parse().unwrap(),
            local_port: 5353,
            remote_addr: None,
            remote_port: None,
            pid: 42,
            state: Some(TcpState::Established), // must be dropped
            socket_created_at: None,
        };
        c.ingest(1, &[(row.clone(), P), (row, P)], BOTH);
        let rec = c.records().next().unwrap();
        assert_eq!(c.records().count(), 1);
        assert_eq!(
            rec.observations, 1,
            "duplicate rows count once per snapshot"
        );
        assert_eq!(rec.state, None);
        assert_eq!(rec.key.remote_addr, None);
    }

    #[test]
    fn tcp_listener_remote_is_none_and_pid_only_lowers_confidence() {
        let mut c = Correlator::new();
        let mut row = tcp("0.0.0.0", 0, 8080, TcpState::Listen);
        row.local_addr = "0.0.0.0".parse().unwrap();
        let pid_only = ProcessIdentity {
            pid: 42,
            created: None,
        };
        c.ingest(1, &[(row, pid_only)], BOTH);
        let rec = c.records().next().unwrap();
        assert_eq!(rec.key.remote_addr, None);
        assert_eq!(rec.confidence, ObservationConfidence::Medium);
    }
}
