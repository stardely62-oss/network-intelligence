//! Process enumeration and identity.

use ni_core::process::{ProcessAccess, ProcessIdentity, ProcessInfo};
use ni_core::source::SourceError;
use ni_core::time::filetime_to_unix_ms;
use std::mem::{size_of, zeroed};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: we own the handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn wide_to_string(w: &[u16]) -> String {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..n])
}

fn ft(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

/// Opens the process for limited query and reads its creation time and
/// image path.
fn query(pid: u32) -> (Option<u64>, Option<String>, ProcessAccess) {
    if pid == 0 || pid == 4 {
        return (None, None, ProcessAccess::System);
    }
    // SAFETY: plain Win32 calls with checked results.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return (None, None, ProcessAccess::Denied);
        }
        let h = Handle(h);
        let mut c: FILETIME = zeroed();
        let mut e: FILETIME = zeroed();
        let mut k: FILETIME = zeroed();
        let mut u: FILETIME = zeroed();
        let created = (GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) != 0)
            .then(|| ft(c))
            .filter(|&v| v != 0);
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let path =
            (QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) != 0)
                .then(|| String::from_utf16_lossy(&buf[..len as usize]));
        let access = if created.is_some() {
            ProcessAccess::Full
        } else {
            ProcessAccess::Denied
        };
        (created, path, access)
    }
}

pub fn processes() -> Result<Vec<ProcessInfo>, SourceError> {
    // SAFETY: snapshot handle is closed by `Handle`; the entry struct is
    // initialised with its size as the API requires.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            let code = GetLastError();
            return Err(SourceError::Os {
                code: code as i64,
                message: format!("CreateToolhelp32Snapshot failed with error {code}"),
            });
        }
        let snap = Handle(snap);
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut out = Vec::new();
        if Process32FirstW(snap.0, &mut e) == 0 {
            let code = GetLastError();
            return Err(SourceError::Os {
                code: code as i64,
                message: format!("Process32FirstW failed with error {code}"),
            });
        }
        loop {
            let pid = e.th32ProcessID;
            let (created, path, access) = query(pid);
            out.push(ProcessInfo {
                identity: ProcessIdentity { pid, created },
                parent_pid: (e.th32ParentProcessID != 0 || pid == 0)
                    .then_some(e.th32ParentProcessID),
                name: wide_to_string(&e.szExeFile),
                path,
                access,
                threads: e.cntThreads,
                created_at: created.and_then(filetime_to_unix_ms),
            });
            if Process32NextW(snap.0, &mut e) == 0 {
                break;
            }
        }
        Ok(out)
    }
}

pub fn is_elevated() -> Option<bool> {
    // SAFETY: token handle is closed by `Handle`.
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return None;
        }
        let tok = Handle(tok);
        let mut el: TOKEN_ELEVATION = zeroed();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            tok.0,
            TokenElevation,
            &mut el as *mut _ as *mut _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        (ok != 0).then_some(el.TokenIsElevated != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_own_process_with_identity() {
        let me = std::process::id();
        let list = processes().expect("toolhelp snapshot");
        let p = list
            .iter()
            .find(|p| p.identity.pid == me)
            .expect("own process listed");
        assert!(
            p.identity.created.is_some(),
            "own process creation time readable"
        );
        assert_eq!(p.access, ProcessAccess::Full);
        let path = p.path.as_deref().expect("own image path");
        assert!(path.to_ascii_lowercase().ends_with(".exe"), "{path}");
        assert!(p.created_at.unwrap() <= ni_core::time::now_ms());
        // The System process is listed but not opened.
        let sys = list
            .iter()
            .find(|p| p.identity.pid == 4)
            .expect("System process");
        assert_eq!(sys.access, ProcessAccess::System);
    }

    #[test]
    fn child_identity_differs_and_parent_matches() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/C", "ping", "-n", "3", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn cmd");
        let cpid = child.id();
        let list = processes().unwrap();
        let c = list
            .iter()
            .find(|p| p.identity.pid == cpid)
            .expect("child listed");
        let me = list
            .iter()
            .find(|p| p.identity.pid == std::process::id())
            .unwrap();
        assert_eq!(c.parent_pid, Some(std::process::id()));
        assert!(c.identity.created.unwrap() >= me.identity.created.unwrap());
        let _ = child.kill();
        let _ = child.wait();
    }
}
