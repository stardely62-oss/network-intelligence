//! Process identity and the set of processes a session follows.
//!
//! Windows reuses PIDs. A process is therefore identified by its PID *and*
//! its creation time (FILETIME). When the creation time cannot be read (no
//! access to the process), the identity is PID-only and this is reported as
//! reduced confidence instead of being hidden.

use crate::time::UnixMs;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessIdentity {
    pub pid: u32,
    /// Raw FILETIME of process creation (100-ns ticks since 1601), if known.
    pub created: Option<u64>,
}

impl ProcessIdentity {
    pub fn is_pid_only(&self) -> bool {
        self.created.is_none()
    }
    /// Whether `other` may be the same process. Two known creation times
    /// must match exactly; an unknown one matches by PID only.
    pub fn same_process(&self, other: &ProcessIdentity) -> bool {
        self.pid == other.pid
            && match (self.created, other.created) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProcessAccess {
    /// Image path and creation time were read.
    Full,
    /// The process could not be opened (typically a protected or system
    /// process while running without elevation).
    Denied,
    /// Pseudo-processes (System Idle, System) without an image path.
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub identity: ProcessIdentity,
    pub parent_pid: Option<u32>,
    /// Executable file name from the process snapshot (always available).
    pub name: String,
    /// Full image path, if the process could be opened.
    pub path: Option<String>,
    pub access: ProcessAccess,
    pub threads: u32,
    /// Process creation time in Unix ms, derived from `identity.created`.
    pub created_at: Option<UnixMs>,
}

impl ProcessInfo {
    fn image_key(&self) -> String {
        self.path
            .as_deref()
            .unwrap_or(&self.name)
            .to_ascii_lowercase()
    }
}

/// What the user selected to analyse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetSpec {
    pub root: ProcessIdentity,
    pub name: String,
    pub path: Option<String>,
    /// Follow processes whose parent is a tracked process.
    pub include_children: bool,
    /// Also follow every process with the same executable (path if known,
    /// else file name). Useful for multi-process apps like browsers and
    /// Electron applications, and to follow restarts of the application.
    pub include_same_image: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrackReason {
    Root,
    Child,
    SameImage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrackedProcess {
    pub info: ProcessInfo,
    pub reason: TrackReason,
    pub first_seen: UnixMs,
    pub last_seen: UnixMs,
    /// First snapshot in which the process was missing.
    pub exited_at: Option<UnixMs>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackerChange {
    Tracked(TrackedProcess),
    /// The process disappeared from the process list.
    Exited {
        identity: ProcessIdentity,
        last_seen: UnixMs,
        gone_at: UnixMs,
    },
    /// A process with the same PID but a different creation time appeared:
    /// the old process exited and the PID was reused by another one, which
    /// is not merged with it.
    PidReused {
        old: ProcessIdentity,
        new: ProcessIdentity,
        new_name: String,
    },
}

/// Decides, per snapshot, which processes belong to the analysed target.
#[derive(Debug, Clone)]
pub struct TargetTracker {
    spec: TargetSpec,
    /// Alive tracked processes by PID.
    alive: HashMap<u32, TrackedProcess>,
    /// Every identity ever tracked (alive or not), in tracking order.
    history: Vec<TrackedProcess>,
    root_seen: bool,
}

impl TargetTracker {
    pub fn new(spec: TargetSpec) -> Self {
        Self {
            spec,
            alive: HashMap::new(),
            history: Vec::new(),
            root_seen: false,
        }
    }

    pub fn spec(&self) -> &TargetSpec {
        &self.spec
    }

    /// Currently alive tracked processes.
    pub fn alive(&self) -> impl Iterator<Item = &TrackedProcess> {
        self.alive.values()
    }

    pub fn history(&self) -> &[TrackedProcess] {
        &self.history
    }

    /// Identity of the tracked process currently owning `pid`, if any.
    pub fn owner(&self, pid: u32) -> Option<ProcessIdentity> {
        self.alive.get(&pid).map(|p| p.info.identity)
    }

    fn image_matches(&self, p: &ProcessInfo) -> bool {
        let want = self
            .spec
            .path
            .as_deref()
            .unwrap_or(&self.spec.name)
            .to_ascii_lowercase();
        // A path is only compared with a path; without one fall back to the
        // file name so restarts of a process we cannot open are still seen.
        match (&self.spec.path, &p.path) {
            (Some(_), Some(_)) => p.image_key() == want,
            _ => p.name.eq_ignore_ascii_case(&self.spec.name),
        }
    }

    /// Applies a fresh process list. Returns the changes in a deterministic
    /// order (exits first, then new processes by PID).
    pub fn update(&mut self, now: UnixMs, procs: &[ProcessInfo]) -> Vec<TrackerChange> {
        let mut out = Vec::new();
        let by_pid: HashMap<u32, &ProcessInfo> =
            procs.iter().map(|p| (p.identity.pid, p)).collect();

        // 1. Exits and PID reuse.
        let mut pids: Vec<u32> = self.alive.keys().copied().collect();
        pids.sort_unstable();
        for pid in pids {
            let tracked = &self.alive[&pid];
            let ident = tracked.info.identity;
            match by_pid.get(&pid) {
                Some(cur) if ident.same_process(&cur.identity) && name_consistent(tracked, cur) => {
                    let t = self.alive.get_mut(&pid).expect("present");
                    t.last_seen = now;
                    // Fill in a path that became readable later.
                    if t.info.path.is_none() && cur.path.is_some() && ident.created.is_some() {
                        t.info.path = cur.path.clone();
                    }
                }
                Some(cur) => {
                    self.alive.remove(&pid);
                    self.mark_exited(ident, now);
                    out.push(TrackerChange::PidReused {
                        old: ident,
                        new: cur.identity,
                        new_name: cur.name.clone(),
                    });
                }
                None => {
                    let t = self.alive.remove(&pid).expect("present");
                    self.mark_exited(ident, now);
                    out.push(TrackerChange::Exited {
                        identity: ident,
                        last_seen: t.last_seen,
                        gone_at: now,
                    });
                }
            }
        }

        // 2. New processes. Iterate until no more children are added so a
        // grandchild seen in the same snapshot as its parent is included.
        let ever: HashSet<ProcessIdentity> = self.history.iter().map(|t| t.info.identity).collect();
        let mut sorted: Vec<&ProcessInfo> = procs.iter().collect();
        sorted.sort_by_key(|p| p.identity.pid);
        loop {
            let mut added = false;
            for p in &sorted {
                if self.alive.contains_key(&p.identity.pid)
                    || ever.contains(&p.identity) && !p.identity.is_pid_only()
                {
                    continue;
                }
                let reason = if !self.root_seen
                    && p.identity.same_process(&self.spec.root)
                    && p.identity.pid == self.spec.root.pid
                {
                    Some(TrackReason::Root)
                } else if self.spec.include_children && self.is_child_of_tracked(p) {
                    Some(TrackReason::Child)
                } else if self.spec.include_same_image && self.image_matches(p) {
                    Some(TrackReason::SameImage)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    if reason == TrackReason::Root {
                        self.root_seen = true;
                    }
                    let t = TrackedProcess {
                        info: (*p).clone(),
                        reason,
                        first_seen: now,
                        last_seen: now,
                        exited_at: None,
                    };
                    self.alive.insert(p.identity.pid, t.clone());
                    self.history.push(t.clone());
                    out.push(TrackerChange::Tracked(t));
                    added = true;
                }
            }
            if !added {
                break;
            }
        }
        // The root is only matched in the first snapshot that contains it;
        // if it was already gone at session start, do not keep looking for a
        // future process that happens to receive the same PID.
        self.root_seen = true;
        out
    }

    fn is_child_of_tracked(&self, p: &ProcessInfo) -> bool {
        let Some(ppid) = p.parent_pid else {
            return false;
        };
        let Some(parent) = self.alive.get(&ppid) else {
            return false;
        };
        // The parent PID recorded by Windows is not updated when the parent
        // exits, so a process whose "parent" PID was reused would look like
        // a child. A real child cannot be older than its parent.
        match (p.identity.created, parent.info.identity.created) {
            (Some(child), Some(par)) => child >= par,
            _ => true,
        }
    }

    fn mark_exited(&mut self, ident: ProcessIdentity, now: UnixMs) {
        if let Some(h) = self
            .history
            .iter_mut()
            .rev()
            .find(|h| h.info.identity == ident && h.exited_at.is_none())
        {
            h.exited_at = Some(now);
        }
    }
}

/// For PID-only identities, a changed executable name is the only sign of
/// PID reuse we have.
fn name_consistent(t: &TrackedProcess, cur: &ProcessInfo) -> bool {
    !t.info.identity.is_pid_only() || t.info.name.eq_ignore_ascii_case(&cur.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, created: Option<u64>, ppid: Option<u32>, name: &str) -> ProcessInfo {
        ProcessInfo {
            identity: ProcessIdentity { pid, created },
            parent_pid: ppid,
            name: name.into(),
            path: created.map(|_| format!("C:\\Apps\\{name}")),
            access: if created.is_some() {
                ProcessAccess::Full
            } else {
                ProcessAccess::Denied
            },
            threads: 1,
            created_at: None,
        }
    }

    fn spec(root: &ProcessInfo, children: bool, same: bool) -> TargetSpec {
        TargetSpec {
            root: root.identity,
            name: root.name.clone(),
            path: root.path.clone(),
            include_children: children,
            include_same_image: same,
        }
    }

    #[test]
    fn identity_matching() {
        let a = ProcessIdentity {
            pid: 10,
            created: Some(1),
        };
        let b = ProcessIdentity {
            pid: 10,
            created: Some(2),
        };
        let c = ProcessIdentity {
            pid: 10,
            created: None,
        };
        assert!(a.same_process(&a));
        assert!(!a.same_process(&b));
        assert!(a.same_process(&c));
        assert!(!a.same_process(&ProcessIdentity {
            pid: 11,
            created: Some(1)
        }));
    }

    #[test]
    fn tracks_root_and_children_and_detects_exit() {
        let root = proc(100, Some(1000), Some(1), "app.exe");
        let child = proc(200, Some(1100), Some(100), "helper.exe");
        let grandchild = proc(300, Some(1200), Some(200), "gpu.exe");
        let other = proc(400, Some(900), Some(1), "other.exe");
        let mut t = TargetTracker::new(spec(&root, true, false));
        let ch = t.update(
            1,
            &[
                root.clone(),
                child.clone(),
                grandchild.clone(),
                other.clone(),
            ],
        );
        assert_eq!(ch.len(), 3);
        assert!(t.owner(300).is_some());
        assert!(t.owner(400).is_none());

        let ch = t.update(2, &[root.clone(), grandchild.clone(), other.clone()]);
        assert_eq!(
            ch,
            vec![TrackerChange::Exited {
                identity: child.identity,
                last_seen: 1,
                gone_at: 2
            }]
        );
        assert_eq!(
            t.history()
                .iter()
                .find(|h| h.info.identity.pid == 200)
                .unwrap()
                .exited_at,
            Some(2)
        );
    }

    #[test]
    fn pid_reuse_does_not_merge_processes() {
        let root = proc(100, Some(1000), Some(1), "app.exe");
        let mut t = TargetTracker::new(spec(&root, true, false));
        t.update(1, std::slice::from_ref(&root));
        // The app exits and an unrelated process receives PID 100.
        let reused = proc(100, Some(5000), Some(1), "notepad.exe");
        let ch = t.update(2, std::slice::from_ref(&reused));
        assert_eq!(
            ch,
            vec![TrackerChange::PidReused {
                old: root.identity,
                new: reused.identity,
                new_name: "notepad.exe".into()
            }]
        );
        assert!(
            t.owner(100).is_none(),
            "the new owner of PID 100 must not be tracked"
        );
        // Even later snapshots must not adopt it as the root.
        assert!(t.update(3, &[reused]).is_empty());
    }

    #[test]
    fn child_with_reused_parent_pid_is_not_adopted() {
        let root = proc(100, Some(1000), Some(1), "app.exe");
        // A process created *before* the root whose parent PID happens to be
        // 100 (its real parent exited long ago and the PID was reused).
        let stale = proc(250, Some(500), Some(100), "stale.exe");
        let mut t = TargetTracker::new(spec(&root, true, false));
        t.update(1, &[root, stale]);
        assert!(t.owner(250).is_none());
    }

    #[test]
    fn same_image_follows_restart() {
        let root = proc(100, Some(1000), Some(1), "app.exe");
        let mut t = TargetTracker::new(spec(&root, false, true));
        t.update(1, std::slice::from_ref(&root));
        t.update(2, &[]);
        let restarted = proc(777, Some(9000), Some(1), "app.exe");
        let ch = t.update(3, std::slice::from_ref(&restarted));
        assert!(
            matches!(&ch[..], [TrackerChange::Tracked(p)] if p.reason == TrackReason::SameImage)
        );
        assert_eq!(t.owner(777), Some(restarted.identity));
    }

    #[test]
    fn pid_only_identity_reuse_detected_by_name() {
        let root = proc(100, None, None, "svc.exe");
        let mut t = TargetTracker::new(spec(&root, false, false));
        t.update(1, std::slice::from_ref(&root));
        let ch = t.update(2, &[proc(100, None, None, "other.exe")]);
        assert!(matches!(ch[0], TrackerChange::PidReused { .. }));
    }

    #[test]
    fn root_gone_before_start_is_not_replaced_by_new_pid_owner() {
        let root = proc(100, Some(1000), Some(1), "app.exe");
        let mut t = TargetTracker::new(spec(&root, false, false));
        assert!(t.update(1, &[]).is_empty());
        assert!(t.update(2, &[proc(100, None, None, "app.exe")]).is_empty());
    }
}
