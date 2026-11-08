//! TCP/UDP endpoint tables through IP Helper.

use crate::raw;
use ni_core::addr::Family;
use ni_core::endpoint::SocketRow;
use ni_core::source::SourceError;
use ni_core::time::now_ms;
use std::ffi::c_void;
use std::mem::size_of;
use std::net::IpAddr;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE,
    MIB_UDP6ROW_OWNER_MODULE, MIB_UDPROW_OWNER_MODULE, TCP_TABLE_OWNER_MODULE_ALL,
    UDP_TABLE_OWNER_MODULE,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// Calls a `GetExtended*Table` function with a growing buffer. The table can
/// grow between the size query and the read, so this retries a few times.
fn read_table(
    call: impl Fn(*mut c_void, *mut u32) -> u32,
    what: &str,
) -> Result<Vec<u64>, SourceError> {
    let mut size: u32 = 0;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..8 {
        let ptr = if buf.is_empty() {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr() as *mut c_void
        };
        let rc = call(ptr, &mut size);
        match rc {
            NO_ERROR if !buf.is_empty() => return Ok(buf),
            NO_ERROR => {
                // A zero-length query cannot succeed with data; treat as empty.
                return Ok(Vec::new());
            }
            ERROR_INSUFFICIENT_BUFFER => {
                // u64 elements keep the 8-byte alignment of the rows; add
                // headroom for rows created in the meantime.
                let elems = (size as usize + 4096).div_ceil(8);
                buf = vec![0u64; elems];
                size = (elems * 8) as u32;
            }
            ERROR_ACCESS_DENIED => {
                return Err(SourceError::AccessDenied {
                    detail: format!("{what}: ERROR_ACCESS_DENIED"),
                })
            }
            code => {
                return Err(SourceError::Os {
                    code: code as i64,
                    message: format!("{what} failed with error {code}"),
                })
            }
        }
    }
    Err(SourceError::Os {
        code: ERROR_INSUFFICIENT_BUFFER as i64,
        message: format!("{what}: table kept growing"),
    })
}

/// Iterates the rows of a `MIB_*TABLE_*` buffer: a `DWORD dwNumEntries`
/// followed (after padding to the row alignment) by the row array.
fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
    if buf.is_empty() {
        return Vec::new();
    }
    let bytes = buf.len() * 8;
    let base = buf.as_ptr() as *const u8;
    // SAFETY: the buffer holds at least 4 bytes (dwNumEntries) once the call
    // succeeded; read_unaligned avoids any alignment assumption.
    let n = unsafe { std::ptr::read_unaligned(base as *const u32) } as usize;
    let align = std::mem::align_of::<T>().max(4);
    let offset = 4usize.div_ceil(align) * align;
    let max = (bytes.saturating_sub(offset)) / size_of::<T>();
    let n = n.min(max);
    (0..n)
        .map(|i| {
            // SAFETY: bounds checked against the buffer size above.
            unsafe { std::ptr::read_unaligned(base.add(offset + i * size_of::<T>()) as *const T) }
        })
        .collect()
}

pub fn tcp_table() -> Result<Vec<SocketRow>, SourceError> {
    let now = now_ms();
    let mut out = Vec::new();

    let v4 = read_table(
        |p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_MODULE_ALL, 0)
        },
        "GetExtendedTcpTable(AF_INET)",
    )?;
    for r in rows::<MIB_TCPROW_OWNER_MODULE>(&v4) {
        out.push(raw::tcp_row(
            Family::Ipv4,
            IpAddr::V4(raw::ipv4_from_dword(r.dwLocalAddr)),
            r.dwLocalPort,
            IpAddr::V4(raw::ipv4_from_dword(r.dwRemoteAddr)),
            r.dwRemotePort,
            r.dwState,
            r.dwOwningPid,
            r.liCreateTimestamp,
            now,
        ));
    }

    let v6 = read_table(
        |p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_MODULE_ALL, 0)
        },
        "GetExtendedTcpTable(AF_INET6)",
    )?;
    for r in rows::<MIB_TCP6ROW_OWNER_MODULE>(&v6) {
        out.push(raw::tcp_row(
            Family::Ipv6,
            IpAddr::V6(raw::ipv6_from_bytes(r.ucLocalAddr)),
            r.dwLocalPort,
            IpAddr::V6(raw::ipv6_from_bytes(r.ucRemoteAddr)),
            r.dwRemotePort,
            r.dwState,
            r.dwOwningPid,
            r.liCreateTimestamp,
            now,
        ));
    }
    Ok(out)
}

pub fn udp_table() -> Result<Vec<SocketRow>, SourceError> {
    let now = now_ms();
    let mut out = Vec::new();
    let v4 = read_table(
        |p, s| unsafe { GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_MODULE, 0) },
        "GetExtendedUdpTable(AF_INET)",
    )?;
    for r in rows::<MIB_UDPROW_OWNER_MODULE>(&v4) {
        out.push(raw::udp_row(
            Family::Ipv4,
            IpAddr::V4(raw::ipv4_from_dword(r.dwLocalAddr)),
            r.dwLocalPort,
            r.dwOwningPid,
            r.liCreateTimestamp,
            now,
        ));
    }
    let v6 = read_table(
        |p, s| unsafe { GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_MODULE, 0) },
        "GetExtendedUdpTable(AF_INET6)",
    )?;
    for r in rows::<MIB_UDP6ROW_OWNER_MODULE>(&v6) {
        out.push(raw::udp_row(
            Family::Ipv6,
            IpAddr::V6(raw::ipv6_from_bytes(r.ucLocalAddr)),
            r.dwLocalPort,
            r.dwOwningPid,
            r.liCreateTimestamp,
            now,
        ));
    }
    Ok(out)
}
