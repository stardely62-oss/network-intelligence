//! Classification of socket errors (WinSock and POSIX errno).

use ni_core::probe::OsError;
use std::io;

/// Coarse class of a socket error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Refused,
    TimedOut,
    Unreachable,
    /// ICMP port unreachable surfaced on a connected UDP socket.
    Reset,
    WouldBlock,
    Other,
}

/// Symbolic name and class of a raw OS error code.
pub fn name_of(code: i32) -> Option<(&'static str, ErrorClass)> {
    #[cfg(windows)]
    {
        Some(match code {
            10035 => ("WSAEWOULDBLOCK", ErrorClass::WouldBlock),
            10013 => ("WSAEACCES", ErrorClass::Other),
            10048 => ("WSAEADDRINUSE", ErrorClass::Other),
            10049 => ("WSAEADDRNOTAVAIL", ErrorClass::Other),
            10050 => ("WSAENETDOWN", ErrorClass::Unreachable),
            10051 => ("WSAENETUNREACH", ErrorClass::Unreachable),
            10052 => ("WSAENETRESET", ErrorClass::Reset),
            10053 => ("WSAECONNABORTED", ErrorClass::Other),
            10054 => ("WSAECONNRESET", ErrorClass::Reset),
            10060 => ("WSAETIMEDOUT", ErrorClass::TimedOut),
            10061 => ("WSAECONNREFUSED", ErrorClass::Refused),
            10064 => ("WSAEHOSTDOWN", ErrorClass::Unreachable),
            10065 => ("WSAEHOSTUNREACH", ErrorClass::Unreachable),
            11001 => ("WSAHOST_NOT_FOUND", ErrorClass::Other),
            11002 => ("WSATRY_AGAIN", ErrorClass::Other),
            11003 => ("WSANO_RECOVERY", ErrorClass::Other),
            11004 => ("WSANO_DATA", ErrorClass::Other),
            _ => return None,
        })
    }
    #[cfg(not(windows))]
    {
        Some(match code {
            11 => ("EAGAIN", ErrorClass::WouldBlock),
            13 => ("EACCES", ErrorClass::Other),
            98 => ("EADDRINUSE", ErrorClass::Other),
            99 => ("EADDRNOTAVAIL", ErrorClass::Other),
            100 => ("ENETDOWN", ErrorClass::Unreachable),
            101 => ("ENETUNREACH", ErrorClass::Unreachable),
            104 => ("ECONNRESET", ErrorClass::Reset),
            110 => ("ETIMEDOUT", ErrorClass::TimedOut),
            111 => ("ECONNREFUSED", ErrorClass::Refused),
            112 => ("EHOSTDOWN", ErrorClass::Unreachable),
            113 => ("EHOSTUNREACH", ErrorClass::Unreachable),
            _ => return None,
        })
    }
}

pub fn classify(e: &io::Error) -> ErrorClass {
    if let Some((_, c)) = e.raw_os_error().and_then(name_of) {
        return c;
    }
    match e.kind() {
        io::ErrorKind::ConnectionRefused => ErrorClass::Refused,
        io::ErrorKind::TimedOut => ErrorClass::TimedOut,
        io::ErrorKind::WouldBlock => ErrorClass::WouldBlock,
        io::ErrorKind::ConnectionReset => ErrorClass::Reset,
        io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NetworkDown => ErrorClass::Unreachable,
        _ => ErrorClass::Other,
    }
}

pub fn os_error(e: &io::Error) -> OsError {
    let code = e.raw_os_error();
    OsError {
        code,
        name: code.and_then(name_of).map(|(n, _)| n.to_string()),
        message: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_code_and_kind() {
        #[cfg(windows)]
        let refused = io::Error::from_raw_os_error(10061);
        #[cfg(not(windows))]
        let refused = io::Error::from_raw_os_error(111);
        assert_eq!(classify(&refused), ErrorClass::Refused);
        let oe = os_error(&refused);
        assert!(oe.name.as_deref().unwrap().contains("CONNREFUSED"));

        let t = io::Error::new(io::ErrorKind::TimedOut, "connection timed out");
        assert_eq!(classify(&t), ErrorClass::TimedOut);
        assert_eq!(os_error(&t).code, None);
        assert_eq!(classify(&io::Error::other("x")), ErrorClass::Other);
    }
}
