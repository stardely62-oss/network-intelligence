//! Windows data sources for Network Intelligence.
//!
//! * Processes: `CreateToolhelp32Snapshot` / `Process32FirstW` /
//!   `Process32NextW`; identity and image path through `OpenProcess`
//!   (`PROCESS_QUERY_LIMITED_INFORMATION`), `GetProcessTimes` and
//!   `QueryFullProcessImageNameW`.
//! * Sockets: `GetExtendedTcpTable` (`TCP_TABLE_OWNER_MODULE_ALL`) and
//!   `GetExtendedUdpTable` (`UDP_TABLE_OWNER_MODULE`) for `AF_INET` and
//!   `AF_INET6`.
//! * Icons: `SHGetFileInfoW` + `GetIconInfo` + `GetDIBits`, encoded as PNG.
//!
//! Nothing here requires administrator rights. Without elevation some
//! processes cannot be opened; they are reported with
//! [`ni_core::process::ProcessAccess::Denied`] and a PID-only identity.
//!
//! On other platforms [`provider`] returns a provider that reports every
//! call as unavailable — it never produces rows.

use ni_core::source::{SnapshotProvider, UnavailableProvider};

#[cfg(windows)]
mod icon;
#[cfg(windows)]
mod net;
#[cfg(windows)]
mod proc;

/// Parsing helpers shared by the Windows code; platform-independent so the
/// byte-order handling is tested everywhere.
pub mod raw;

#[cfg(windows)]
pub use net::{tcp_table, udp_table};
#[cfg(windows)]
pub use proc::processes;

/// The snapshot provider for this platform.
pub fn provider() -> Box<dyn SnapshotProvider> {
    #[cfg(windows)]
    {
        Box::new(WindowsProvider)
    }
    #[cfg(not(windows))]
    {
        Box::new(UnavailableProvider {
            reason:
                "Сбор данных реализован только для Windows; на этой платформе источник недоступен."
                    .into(),
        })
    }
}

/// Provider that is always unavailable (used in tests and as a fallback).
pub fn unavailable(reason: &str) -> Box<dyn SnapshotProvider> {
    Box::new(UnavailableProvider {
        reason: reason.into(),
    })
}

#[cfg(windows)]
pub struct WindowsProvider;

#[cfg(windows)]
impl SnapshotProvider for WindowsProvider {
    fn name(&self) -> &'static str {
        "windows-iphlpapi-toolhelp"
    }
    fn processes(
        &mut self,
    ) -> Result<Vec<ni_core::process::ProcessInfo>, ni_core::source::SourceError> {
        proc::processes()
    }
    fn tcp(&mut self) -> Result<Vec<ni_core::endpoint::SocketRow>, ni_core::source::SourceError> {
        net::tcp_table()
    }
    fn udp(&mut self) -> Result<Vec<ni_core::endpoint::SocketRow>, ni_core::source::SourceError> {
        net::udp_table()
    }
}

/// PNG (32×32) of the shell icon for an executable, if one can be read.
pub fn icon_png(path: &str) -> Option<Vec<u8>> {
    #[cfg(windows)]
    {
        icon::icon_png(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

/// Whether the current process token is elevated. `None` if unknown.
pub fn is_elevated() -> Option<bool> {
    #[cfg(windows)]
    {
        proc::is_elevated()
    }
    #[cfg(not(windows))]
    {
        None
    }
}
