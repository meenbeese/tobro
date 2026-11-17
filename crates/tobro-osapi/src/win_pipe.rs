//! Windows named-pipe security for the helper IPC endpoint (M7 T4c).
//!
//! The helper's named pipe is its entire attack surface, so it is scoped to
//! exactly one user: the daemon user the installer recorded. This module owns
//! the three pieces that need Win32:
//!
//! - [`PipeSecurity::for_sid`] parses (and canonicalizes) the installer-chosen
//!   SID and builds a protected DACL — SYSTEM and Administrators keep access,
//!   the daemon user gets read/write, everyone else is denied by the OS before
//!   the helper sees a byte.
//! - [`PipeSecurity::create_server`] creates one tokio pipe instance with that
//!   descriptor (the helper serves one client at a time, like the Unix accept
//!   loop).
//! - [`peer_sid`] reads the user SID from the connecting process's token. The
//!   helper compares it with the installer-chosen SID and rejects mismatches,
//!   so a broader DACL (a legacy install, a manual run) still cannot drive
//!   privileged operations.
//!
//! The peer SID comes from the client's *process token* rather than
//! `ImpersonateNamedPipeClient`: identifying a peer needs no
//! `SeImpersonatePrivilege`, and the tokio client only requests
//! identification-level impersonation anyway.
//!
//! # Unsafe scope
//!
//! Every `unsafe` here is the FFI call itself: building/reading a security
//! descriptor or token buffer, and creating the pipe. Buffer sizes come from
//! the OS (`GetTokenInformation` / `GetLengthSid`), the SID is copied into a
//! Rust-owned `Vec` before the OS allocation is freed, and the security
//! descriptor is owned by [`PipeSecurity`] for exactly as long as it is used.
//! Nothing here logs, formats, or returns OS error details beyond an
//! `io::Error`.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, IsValidSid, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::core::PWSTR;

/// A named-pipe security descriptor scoped to one client SID.
///
/// The descriptor is a self-relative `SECURITY_DESCRIPTOR` allocated by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW` and freed on drop.
/// It is stored as a `usize` so the type stays `Send`/`Sync` while the serve
/// loop holds it across `.await` points.
pub struct PipeSecurity {
    descriptor: usize,
}

impl std::fmt::Debug for PipeSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeSecurity").finish_non_exhaustive()
    }
}

impl PipeSecurity {
    /// Build a protected DACL for `sid` (the daemon user).
    ///
    /// `sid` is validated and canonicalized by the OS first, so it cannot
    /// smuggle SDDL syntax into the descriptor.
    pub fn for_sid(sid: &str) -> io::Result<Self> {
        let canonical = canonical_sid_string(sid)?;
        // SYSTEM and Administrators keep access so service management and
        // recovery still work; the daemon user gets read/write only. `P`
        // prevents inherited ACEs from widening the DACL.
        let sddl = format!("D:P(A;;GRGW;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;{canonical})");
        let wide = wide(&sddl);
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut size = 0u32;
        // SAFETY: `wide` is a NUL-terminated string that outlives the call;
        // `descriptor` receives an OS allocation freed by `Drop` below.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if descriptor.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the OS returned an empty pipe security descriptor",
            ));
        }
        Ok(Self {
            descriptor: descriptor as usize,
        })
    }

    /// Create one named-pipe instance with this descriptor.
    pub fn create_server(&self, path: &Path) -> io::Result<NamedPipeServer> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor as PSECURITY_DESCRIPTOR,
            bInheritHandle: 0,
        };
        let mut options = ServerOptions::new();
        options.first_pipe_instance(true);
        // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES for the call's
        // duration and points at the descriptor owned by `self`.
        unsafe {
            options.create_with_security_attributes_raw(
                path,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and this is
        // the single owner, so it is freed exactly once.
        unsafe {
            LocalFree(self.descriptor as *mut c_void);
        }
    }
}

/// Read the connecting client's user SID from its process token.
///
/// Fails closed at the caller (the helper maps any error to an unverifiable
/// peer, which is denied).
pub fn peer_sid<P: AsRawHandle>(pipe: &P) -> io::Result<Vec<u8>> {
    let pipe_handle: HANDLE = pipe.as_raw_handle();
    let mut process_id = 0u32;
    // SAFETY: `pipe_handle` is a live, connected pipe instance owned by the
    // caller; the out-pointer is a valid local.
    if unsafe { GetNamedPipeClientProcessId(pipe_handle, &mut process_id) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a plain OpenProcess call; the handle is owned by `OwnedHandle`.
    let process =
        OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) })?;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is live; `token` receives an owned handle.
    if unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle::new(token)?;
    token_user_sid_bytes(token.raw())
}

/// The current process user's SID as a string (`S-1-...`).
///
/// Used by the daemon's installer orchestration on Windows; `None` when the
/// lookup fails (the caller fails the install rather than guessing).
pub fn current_user_sid_string() -> Option<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that must not be
    // closed; `token` receives an owned handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let token = OwnedHandle::new(token).ok()?;
    token_user_sid_string(token.raw()).ok()
}

/// Parse a SID string and return its raw bytes (for exact comparisons).
pub fn sid_from_string(sid: &str) -> io::Result<Vec<u8>> {
    let wide = wide(sid);
    let mut raw: PSID = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `raw` receives an OS allocation that
    // `_guard` frees only after the SID bytes are copied out.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{sid:?} is not a valid Windows SID"),
        ));
    }
    let _guard = LocalAlloc(raw as *mut c_void);
    copy_sid(raw)
}

// --- Internals -------------------------------------------------------------

/// A handle closed on drop (pipe/token/process handles).
#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is non-null, not INVALID_HANDLE_VALUE (checked in
        // `new`), and owned by this value.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// A `LocalAlloc`-family allocation freed on drop (SIDs, security
/// descriptors, string SIDs).
struct LocalAlloc(*mut c_void);

impl Drop for LocalAlloc {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a LocalAlloc-family API and is owned
        // by this value.
        unsafe {
            LocalFree(self.0);
        }
    }
}

/// NUL-terminated UTF-16 for a Win32 `PCWSTR` argument.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convert and canonicalize a SID string; the OS rejects malformed input.
fn canonical_sid_string(sid: &str) -> io::Result<String> {
    let wide = wide(sid);
    let mut raw: PSID = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `raw` receives an OS allocation that
    // `_guard` frees after conversion.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{sid:?} is not a valid Windows SID"),
        ));
    }
    let _guard = LocalAlloc(raw as *mut c_void);
    sid_to_string(raw)
}

/// Run `f` with the token's user SID pointer (valid only inside the call).
fn with_token_user<T>(token: HANDLE, f: impl FnOnce(PSID) -> io::Result<T>) -> io::Result<T> {
    let mut needed = 0u32;
    // SAFETY: the first call intentionally passes a null buffer to learn the
    // size; ERROR_INSUFFICIENT_BUFFER is the expected outcome.
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    // `TOKEN_USER` holds a pointer, so the buffer must be pointer-aligned;
    // `u64` covers the 4- and 8-byte alignments of the supported targets.
    let words = (needed as usize).div_ceil(std::mem::size_of::<u64>()) + 1;
    let mut buffer = vec![0u64; words];
    // SAFETY: the buffer is large enough for `needed` bytes and aligned for
    // `TOKEN_USER`.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the OS wrote a TOKEN_USER at the start of the aligned buffer;
    // the SID pointer inside it stays valid for the duration of `f`.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    f(sid)
}

fn token_user_sid_bytes(token: HANDLE) -> io::Result<Vec<u8>> {
    with_token_user(token, copy_sid)
}

fn token_user_sid_string(token: HANDLE) -> io::Result<String> {
    with_token_user(token, sid_to_string)
}

/// Copy a SID into a Rust-owned byte buffer (raw SID layout).
fn copy_sid(sid: PSID) -> io::Result<Vec<u8>> {
    if sid.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the token did not carry a user SID",
        ));
    }
    // SAFETY: `sid` points at a SID inside an OS-owned buffer.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the token carried an invalid user SID",
        ));
    }
    // SAFETY: `sid` is a valid SID, so its length is available.
    let length = unsafe { GetLengthSid(sid) };
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the user SID has no length",
        ));
    }
    let mut bytes = vec![0u8; length as usize];
    // SAFETY: the destination is `length` bytes and the source SID is
    // `length` bytes (per `GetLengthSid`).
    if unsafe { CopySid(length, bytes.as_mut_ptr().cast::<c_void>(), sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(bytes)
}

/// Render a SID as `S-1-...`.
fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut raw: PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID in an OS-owned buffer; `raw` receives a
    // LocalAlloc string freed by `_guard`.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = LocalAlloc(raw.cast::<c_void>());
    if raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the OS returned an empty SID string",
        ));
    }
    let mut length = 0usize;
    // SAFETY: the OS guarantees a NUL-terminated UTF-16 string.
    unsafe {
        while *raw.add(length) != 0 {
            length += 1;
        }
        Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
            raw, length,
        )))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_sid_strings() {
        for bad in [
            "",
            "S-1",
            "not-a-sid",
            "S-1-5-21-",
            "S-2-5-18",
            "S-1-5-18 x",
        ] {
            assert!(PipeSecurity::for_sid(bad).is_err(), "{bad:?}");
            assert!(sid_from_string(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn canonicalizes_and_compares_sids_exactly() {
        let sid = current_user_sid_string().expect("the test user always has a SID");
        let bytes = sid_from_string(&sid).expect("the current SID parses");
        assert!(!bytes.is_empty());
        assert_eq!(bytes, sid_from_string(&sid).expect("stable"));
        // A different, well-formed SID yields different bytes.
        assert_ne!(bytes, sid_from_string("S-1-5-18").expect("SYSTEM SID"));
    }

    #[test]
    fn pipe_security_builds_a_descriptor() {
        let sid = current_user_sid_string().expect("the test user always has a SID");
        let security = PipeSecurity::for_sid(&sid).expect("the current SID is accepted");
        assert_ne!(security.descriptor, 0);
    }
}
