//! Unix uid/gid lookups and socket ownership for the helper install (M7).
//!
//! The installer and the helper both need three tiny OS primitives that have
//! no safe std equivalent:
//!
//! - resolving a group *name* to a gid (the installed service runs as root
//!   but its IPC socket must be writable by the unprivileged daemon's group),
//! - resolving the *current* user's primary group name (the installer embeds
//!   it into the generated service definitions),
//! - chowning a path to a gid (fixing up the helper's IPC socket after bind),
//! - taking ownership of a service-manager-passed listening socket (systemd
//!   socket activation uses the `LISTEN_PID`/`LISTEN_FDS` protocol).
//!
//! As everywhere in this crate, the unsafe surface is minimal, fixed-shape,
//! and takes no attacker-controlled lengths or pointers: the only inputs are
//! a validated group name and paths already vetted by the caller.

use std::io;
use std::os::fd::FromRawFd as _;

/// Maximum group-name length we accept. `getgrnam_r` needs a caller-supplied
/// buffer; group names are short by convention (`_POSIX_LOGIN_NAME_MAX`).
const MAX_GROUP_NAME: usize = 64;

/// Maximum passwd/group entry size hint for the `getgr*_r` buffers. A
/// 4 KiB buffer comfortably holds any real-world entry with its member list.
const ENTRY_BUFFER: usize = 4096;

/// True when `name` is shaped like a group name we are willing to resolve:
/// short, printable ASCII, no separators. The callers embed resolved names
/// in generated unit files, so anything unusual is rejected here.
pub fn is_valid_group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_GROUP_NAME
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '$'))
}

/// Resolve a group name to its gid (`getgrnam_r`). `None` when the group
/// does not exist or the name is not a valid group name.
pub fn group_gid(name: &str) -> Option<u32> {
    if !is_valid_group_name(name) {
        return None;
    }
    let c_name = std::ffi::CString::new(name).ok()?;
    let mut buffer = vec![0u8; ENTRY_BUFFER];
    loop {
        // `getgrnam_r` needs scratch space for the record (`scratch`) and for
        // the strings it points into (`buffer`), and reports the result
        // through `entry` (NULL = not found).
        let mut scratch: libc::group = unsafe { std::mem::zeroed() };
        let mut entry: *mut libc::group = std::ptr::null_mut();
        // SAFETY: `c_name` is a valid NUL-terminated string; `scratch` and
        // `buffer` are fixed-size allocations owned by this call; `entry` is
        // written by libc on return. No attacker-controlled lengths exist
        // (the name was validated, the buffer is a fixed 4 KiB that grows on
        // `ERANGE`).
        let rc = unsafe {
            libc::getgrnam_r(
                c_name.as_ptr(),
                &mut scratch,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut entry,
            )
        };
        if rc == 0 {
            if entry.is_null() {
                return None; // not found
            }
            // SAFETY: on success `entry` is non-null and points at a valid
            // group record inside `scratch`/`buffer` with `gr_gid` filled in.
            return Some(unsafe { (*entry).gr_gid });
        }
        if rc != libc::ERANGE {
            return None; // any other errno: treat as unknown
        }
        buffer.resize(buffer.len() * 2, 0);
    }
}

/// Resolve a gid to its group name (`getgrgid_r`). `None` when unknown.
pub fn group_name(gid: u32) -> Option<String> {
    let mut buffer = vec![0u8; ENTRY_BUFFER];
    loop {
        let mut scratch: libc::group = unsafe { std::mem::zeroed() };
        let mut entry: *mut libc::group = std::ptr::null_mut();
        // SAFETY: as in `group_gid`: fixed-size owned buffers, plain-data
        // inputs, libc fills `entry` on return.
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                &mut scratch,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut entry,
            )
        };
        if rc == 0 {
            if entry.is_null() {
                return None; // not found
            }
            // SAFETY: `gr_name` is a NUL-terminated C string owned by
            // `buffer` for the lifetime of this call.
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).gr_name) };
            return Some(name.to_string_lossy().into_owned());
        }
        if rc != libc::ERANGE {
            return None;
        }
        buffer.resize(buffer.len() * 2, 0);
    }
}

/// The current process's primary group name (`getgid` + `getgrgid_r`).
/// `None` when the primary group has no resolvable name.
pub fn primary_group_name() -> Option<String> {
    let gid = unsafe { libc::getgid() };
    group_name(gid)
}

/// Chown `path` to `gid`, leaving the owner uid unchanged (`chown(path, -1,
/// gid)`). The caller owns logging policy; only the `io::Error` surfaces.
pub fn chown_group(path: &std::path::Path, gid: u32) -> io::Result<()> {
    let c_path = std::ffi::CString::new(
        path.as_os_str()
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 path"))?,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    // SAFETY: `c_path` is a valid NUL-terminated C string; `(uid_t)-1` keeps
    // the owner unchanged and `gid` is plain data. No buffers are involved.
    let rc = unsafe { libc::chown(c_path.as_ptr(), libc::uid_t::MAX, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Take ownership of a listening Unix socket passed in by the service
/// manager (systemd socket activation, the `LISTEN_PID`/`LISTEN_FDS`
/// protocol): returns the listener when the environment indicates exactly
/// this process received at least one listening socket and fd 3 verifies as
/// a socket. The fd is *taken* (the env vars are removed, matching the
/// protocol's ownership transfer).
pub fn take_inherited_listen_fd() -> Option<std::os::unix::net::UnixListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    if pid != std::process::id() {
        return None;
    }
    let fds: usize = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if fds == 0 {
        return None;
    }
    const LISTEN_FD: i32 = 3; // the protocol starts service sockets at fd 3
    if !is_socket_fd(LISTEN_FD) {
        return None;
    }
    // Ownership moves to the returned listener; clear the markers so nothing
    // downstream re-inherits them. (`remove_var` is unsafe in edition 2024 —
    // single-threaded process setup here, no other thread reads the environ
    // concurrently during helper startup.)
    // SAFETY: single-threaded context, no concurrent environ access.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
    }
    // SAFETY: fd 3 was verified to be a socket and, per the activation
    // protocol, is owned by this process and not shared; wrapping it in a
    // `UnixListener` transfers that ownership exactly once.
    Some(unsafe { std::os::unix::net::UnixListener::from_raw_fd(LISTEN_FD) })
}

/// `true` when `fd` refers to a socket (`fstat`, `S_IFSOCK` check only).
fn is_socket_fd(fd: i32) -> bool {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `stat` is a fixed-size plain-data struct owned by this call.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return false;
    }
    stat.st_mode & libc::S_IFMT == libc::S_IFSOCK
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn group_name_validation_rejects_odd_shapes() {
        assert!(is_valid_group_name("wheel"));
        assert!(is_valid_group_name("adm"));
        assert!(is_valid_group_name("sftp-users"));
        assert!(!is_valid_group_name(""));
        assert!(!is_valid_group_name("has space"));
        assert!(!is_valid_group_name("semi;colon"));
        assert!(!is_valid_group_name("line\nbreak"));
        assert!(!is_valid_group_name(&"x".repeat(MAX_GROUP_NAME + 1)));
    }

    #[test]
    fn well_known_groups_resolve() {
        // The gid-0 group exists on every macOS (`wheel`) / Linux (`root`)
        // system that runs tests.
        let name = if cfg!(target_os = "macos") {
            "wheel"
        } else {
            "root"
        };
        assert_eq!(group_gid(name), Some(0));
        assert_eq!(group_gid("definitely-not-a-real-group-xyz"), None);
        assert_eq!(group_gid(""), None, "invalid names are rejected up front");
    }

    #[test]
    fn gid_zero_maps_to_a_known_group_name() {
        let name = group_name(0).expect("gid 0 always has a name");
        if cfg!(target_os = "macos") {
            assert_eq!(name, "wheel");
        } else {
            assert_eq!(name, "root");
        }
    }

    #[test]
    fn primary_group_is_resolvable() {
        // Whatever user runs the tests has a primary group; the name must
        // resolve or the installer would refuse to build service definitions.
        let name = primary_group_name();
        assert!(name.is_some(), "the primary group must have a name");
        let gid = group_gid(name.as_deref().unwrap_or_default());
        assert!(gid.is_some(), "the resolved name must round-trip");
    }

    #[test]
    fn no_inherited_listener_without_activation_env() {
        // Tests do not run under systemd socket activation.
        // SAFETY: test setup, single-threaded.
        unsafe {
            std::env::remove_var("LISTEN_PID");
            std::env::remove_var("LISTEN_FDS");
        }
        assert!(take_inherited_listen_fd().is_none());
    }

    #[test]
    fn inherited_listener_requires_a_matching_pid() {
        // SAFETY: test setup, single-threaded.
        unsafe {
            std::env::set_var("LISTEN_PID", "1"); // pid 1 is never the test binary
            std::env::set_var("LISTEN_FDS", "1");
        }
        assert!(take_inherited_listen_fd().is_none());
        // SAFETY: test teardown, single-threaded.
        unsafe {
            std::env::remove_var("LISTEN_PID");
            std::env::remove_var("LISTEN_FDS");
        }
    }
}
