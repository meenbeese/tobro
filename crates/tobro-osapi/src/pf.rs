//! macOS packet-filter (PF) kill-switch enforcement over `/dev/pf` ioctls.
//!
//! The helper must not shell out (§10.5), so instead of `pfctl` this module
//! speaks the `/dev/pf` ioctl interface directly. The structures below are
//! transcriptions of the kernel's `net/pfvar.h` (LP64 layout) and every size
//! is pinned by a compile-time assertion, so an Apple header change that
//! would silently corrupt the ABI fails the build instead of loading a
//! mangled rule.
//!
//! # Enforcement design
//!
//! Three rules are loaded into the **root filter ruleset** (empty anchor
//! name). Anchor-only rules are never evaluated unless something references
//! the anchor from the main ruleset, so the root ruleset is the only place
//! rules are guaranteed to fire:
//!
//! 1. `pass quick` on the loopback interface (both families);
//! 2. `pass quick` on the tunnel interface (both families);
//! 3. `block drop quick` outbound on every interface (both families).
//!
//! Egress-only blocking mirrors the Linux backend's blackhole-route
//! insurance: replies and other inbound traffic are untouched, and only the
//! leak direction (packets leaving through a physical interface) is dropped.
//! Because the rules live in the kernel, they keep enforcing even if the
//! helper crashes — fail-closed, like the Linux backend — and `teardown`
//! removes them again.
//!
//! # Sharing the machine safely
//!
//! PF is a shared resource (`pfctl`, other VPN clients, sandbox profiles).
//! This module therefore:
//!
//! - refuses to install its rules unless the root filter ruleset is empty or
//!   already contains **only** the `tobro` rules (identified by the
//!   [`RULE_LABEL`] label);
//! - enables PF through the reference-counted `DIOCSTARTREF`/`DIOCSTOPREF`
//!   token interface instead of the plain `DIOCSTART`/`DIOCSTOP` pair, which
//!   would clobber other processes' enable state. Callers should take a
//!   reference only when they actually changed something ([`PfSession::is_running`]
//!   tells them whether PF is already up): a crashed helper's token is
//!   unrecoverable, so blindly re-enabling on every crash-relaunch would
//!   leak one reference per crash and keep PF enabled forever;
//! - never touches rules it does not own, and fails closed (error) rather
//!   than removing someone else's rules.
//!
//! # Unsafe scope
//!
//! All `unsafe` here is the FFI itself: opening `/dev/pf` and issuing
//! ioctls with fixed-size, pointer-free structures whose bytes are built
//! from validated plain-data inputs (an interface name and constants). The
//! only variable-length data are the NUL-terminated interface and anchor
//! names, which are length-checked before every fill. No packets, addresses,
//! or logs ever pass through this module (§10.5).

use std::fs::{File, OpenOptions};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, RawFd};

use libc::ENOENT;

/// Label carried by every rule this module installs (max 63 bytes).
const RULE_LABEL: &str = "tobro-ks";
/// The number of rules one kill-switch enforcement consists of.
const RULE_COUNT: usize = 3;

/// `PF_PASS`: accept matching packets (`pf_rule::action`).
const PF_PASS: u8 = 0;
/// `PF_DROP`: drop matching packets (`pf_rule::action`).
const PF_DROP: u8 = 1;
/// `PF_INOUT`: match both directions (`pf_rule::direction`).
const PF_INOUT: u8 = 0;
/// `PF_OUT`: match the outbound direction (`pf_rule::direction`).
const PF_OUT: u8 = 2;
/// `PF_RULESET_FILTER`: the filter ruleset number (trans ioctls and
/// `pf_get_ruleset_number(PF_PASS|PF_DROP)`).
const PF_RULESET_FILTER: i32 = 1;
/// `PF_ADDR_ADDRMASK`: a plain address/mask pair (`pf_addr_wrap` type).
const PF_ADDR_ADDRMASK: u8 = 0;
/// `AF_UNSPEC`: a rule address matches both families (`pf_rule::af`).
const AF_UNSPEC: u8 = 0;

// ---------------------------------------------------------------------------
// Structure transcriptions (net/pfvar.h, LP64). Sizes are asserted below.
// ---------------------------------------------------------------------------

/// `struct pf_addr`: a 128-bit address/mask cell, no family field (family
/// lives in `pf_rule::af`). C alignment is 4 (`u_int32_t` view).
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PfAddr([u8; 16]);

/// `struct pf_addr_wrap`: value union + a kernel pointer slot + type bytes.
/// The `v` member is treated as its `a` branch (addr + mask); `p` is only
/// ever zero (no dynamic interfaces, tables, or labels are used).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfAddrWrap {
    v: PfAddrWrapValue,
    p: usize,
    addr_type: u8,
    iflags: u8,
}

/// The `v` member of `pf_addr_wrap`, as its largest user: addr + mask.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfAddrWrapValue {
    addr: PfAddr,
    mask: PfAddr,
}

/// `struct pf_port_range`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfPortRange {
    port: [u16; 2],
    op: u8,
}

/// `union pf_rule_xport` (6-byte `pf_port_range` largest member; the union's
/// size rounds up to its 4-byte alignment).
#[repr(C)]
#[derive(Clone, Copy)]
union PfRuleXport {
    range: PfPortRange,
    call_id: u16,
    spi: u32,
}

impl Default for PfRuleXport {
    fn default() -> Self {
        Self {
            range: PfPortRange::default(),
        }
    }
}

impl std::fmt::Debug for PfRuleXport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("pf_rule_xport").finish()
    }
}

/// `struct pf_rule_addr`: address + port + negation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfRuleAddr {
    addr: PfAddrWrap,
    xport: PfRuleXport,
    neg: u8,
}

/// `TAILQ_ENTRY(pf_rule)`: two pointers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfTailqEntry {
    next: usize,
    prev: usize,
}

/// `union pf_rule_ptr`: kernel pointer or rule number.
#[repr(C)]
#[derive(Clone, Copy)]
union PfRulePtr {
    ptr: usize,
    nr: u32,
}

impl Default for PfRulePtr {
    fn default() -> Self {
        Self { ptr: 0 }
    }
}

impl std::fmt::Debug for PfRulePtr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("pf_rule_ptr").finish()
    }
}

/// `struct pf_palist` (`TAILQ_HEAD`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfPalist {
    first: usize,
    last: usize,
}

/// `struct pf_pool`: translation pool (only ever zero here).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfPool {
    list: PfPalist,
    cur: usize,
    key: [u32; 4],
    counter: PfAddr,
    tblidx: i32,
    proxy_port: [u16; 2],
    port_op: u8,
    opts: u8,
    af: u8,
}

/// `struct pf_rule_uid` / `struct pf_rule_gid` (identical layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfRuleUid {
    uid: [u32; 2],
    op: u8,
    pad: [u8; 3],
}

/// `struct pf_rule`: the full 1040-byte kernel rule. Only the fields set by
/// [`build_rules`] are meaningfully initialized; everything else stays zero,
/// which the kernel interprets as "no restriction" (`PF_OP_NONE` uid/gid and
/// ports, zero probability, no tags, no route-to, no state keeping, ...).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct PfRule {
    src: PfRuleAddr,
    dst: PfRuleAddr,
    skip: [PfRulePtr; 8],
    label: [u8; 64],
    ifname: [u8; 16],
    qname: [u8; 64],
    pqname: [u8; 64],
    tagname: [u8; 64],
    match_tagname: [u8; 64],
    overload_tblname: [u8; 32],
    entries: PfTailqEntry,
    rpool: PfPool,
    evaluations: u64,
    packets: [u64; 2],
    bytes: [u64; 2],
    ticket: u64,
    owner: [u8; 64],
    priority: u32,
    kif: usize,
    anchor: usize,
    overload_tbl: usize,
    os_fingerprint: u32,
    rtableid: u32,
    timeout: [u32; 26],
    states: u32,
    max_states: u32,
    src_nodes: u32,
    max_src_nodes: u32,
    max_src_states: u32,
    max_src_conn: u32,
    max_src_conn_rate: [u32; 2],
    qid: u32,
    pqid: u32,
    rt_listid: u32,
    nr: u32,
    prob: u32,
    cuid: u32,
    cpid: i32,
    return_icmp: u16,
    return_icmp6: u16,
    max_mss: u16,
    tag: u16,
    match_tag: u16,
    uid: PfRuleUid,
    gid: PfRuleUid,
    rule_flag: u32,
    action: u8,
    direction: u8,
    log: u8,
    logif: u8,
    quick: u8,
    ifnot: u8,
    match_tag_not: u8,
    natpass: u8,
    keep_state: u8,
    af: u8,
    proto: u8,
    rule_type: u8,
    code: u8,
    flags: u8,
    flagset: u8,
    min_ttl: u8,
    allow_opts: u8,
    rt: u8,
    return_ttl: u8,
    tos: u8,
    anchor_relative: u8,
    anchor_wildcard: u8,
    flush: u8,
    proto_variant: u8,
    extfilter: u8,
    extmap: u8,
    dnpipe: u32,
    dntype: u32,
}

impl Default for PfRule {
    fn default() -> Self {
        // SAFETY: `pf_rule` is a plain C aggregate (pointers are null,
        // unions hold no discriminant) and the all-zero value is exactly
        // what the kernel-side rule starts from before field fix-ups.
        unsafe { mem::zeroed() }
    }
}

/// `struct pfioc_rule`: the `DIOCADDRULE`/`DIOCGETRULES`/`DIOCGETRULE`
/// parameter.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct PfiocRule {
    action: u32,
    ticket: u32,
    pool_ticket: u32,
    nr: u32,
    anchor: [u8; MAXPATHLEN],
    anchor_call: [u8; MAXPATHLEN],
    rule: PfRule,
}

impl Default for PfiocRule {
    fn default() -> Self {
        // SAFETY: plain C aggregate; all-zero is a valid initial value.
        unsafe { mem::zeroed() }
    }
}

/// `struct pf_pooladdr` (embedded in `pfioc_pooladdr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfPooladdr {
    addr: PfAddrWrap,
    entries: PfTailqEntry,
    ifname: [u8; 16],
    kif: usize,
}

/// `struct pfioc_pooladdr`: the `DIOCBEGINADDRS` parameter (we only use the
/// returned `ticket`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct PfiocPooladdr {
    action: u32,
    ticket: u32,
    nr: u32,
    r_num: u32,
    r_action: u8,
    r_last: u8,
    af: u8,
    anchor: [u8; MAXPATHLEN],
    addr: PfPooladdr,
}

impl Default for PfiocPooladdr {
    fn default() -> Self {
        // SAFETY: plain C aggregate; all-zero is a valid initial value.
        unsafe { mem::zeroed() }
    }
}

/// `struct pfioc_trans::pfioc_trans_e`: one transaction element.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct PfiocTransE {
    rs_num: i32,
    anchor: [u8; MAXPATHLEN],
    ticket: u32,
}

impl Default for PfiocTransE {
    fn default() -> Self {
        // SAFETY: plain C aggregate; all-zero is a valid initial value.
        unsafe { mem::zeroed() }
    }
}

/// `struct pfioc_trans` (LP64 userland form; identical binary layout to
/// `pfioc_trans_64`, which is what the kernel reads from a 64-bit process).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct PfiocTrans {
    size: i32,
    esize: i32,
    array: *mut PfiocTransE,
}

/// `struct pfioc_remove_token`: the `DIOCSTOPREF` parameter.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PfiocRemoveToken {
    token_value: u64,
    refcount: u64,
}

/// `struct pf_status`: the `DIOCGETSTATUS` parameter (only `running` is
/// read; the kernel fills the rest).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct PfStatus {
    counters: [u64; 17],
    lcounters: [u64; 7],
    fcounters: [u64; 3],
    scounters: [u64; 3],
    pcounters: [u64; 12],
    bcounters: [u64; 4],
    stateid: u64,
    running: u32,
    states: u32,
    src_nodes: u32,
    since: u64,
    debug: u32,
    hostid: u32,
    ifname: [u8; 16],
    checksum: [u8; 16],
}

impl Default for PfStatus {
    fn default() -> Self {
        // SAFETY: plain C aggregate; all-zero is a valid initial value.
        unsafe { mem::zeroed() }
    }
}

/// `MAXPATHLEN` from `sys/param.h` (the kernel anchor buffers).
const MAXPATHLEN: usize = 1024;

// Layout pinning: these must match the kernel's LP64 `net/pfvar.h` exactly.
// The expected values were measured with the real header (offsetof/sizeof)
// on the reference LP64 targets; an Apple header change that breaks them
// fails the build here.
const _: () = assert!(mem::size_of::<PfAddr>() == 16);
const _: () = assert!(mem::size_of::<PfAddrWrap>() == 48);
const _: () = assert!(mem::size_of::<PfRuleAddr>() == 64);
const _: () = assert!(mem::size_of::<PfPool>() == 72);
const _: () = assert!(mem::size_of::<PfPooladdr>() == 88);
const _: () = assert!(mem::size_of::<PfRule>() == 1040);
const _: () = assert!(mem::size_of::<PfiocRule>() == 3104);
const _: () = assert!(mem::size_of::<PfiocPooladdr>() == 1136);
const _: () = assert!(mem::size_of::<PfiocTransE>() == 1032);
const _: () = assert!(mem::size_of::<PfiocRemoveToken>() == 16);
const _: () = assert!(mem::size_of::<PfStatus>() == 440);
// Key offsets from the same measurement.
const _: () = assert!(mem::offset_of!(PfRule, label) == 192);
const _: () = assert!(mem::offset_of!(PfRule, ifname) == 256);
const _: () = assert!(mem::offset_of!(PfRule, action) == 1004);
const _: () = assert!(mem::offset_of!(PfRule, keep_state) == 1012);
const _: () = assert!(mem::offset_of!(PfRule, af) == 1013);
const _: () = assert!(mem::offset_of!(PfiocRule, rule) == 2064);
const _: () = assert!(mem::offset_of!(PfiocTransE, ticket) == 1028);
const _: () = assert!(mem::offset_of!(PfStatus, running) == 376);

// ---------------------------------------------------------------------------
// Ioctl numbers (`sys/ioccom.h` encoding + `net/pfvar.h` definitions).
// ---------------------------------------------------------------------------

/// `_IOC(inout, group, num, len)` from `sys/ioccom.h`.
const fn ioc(inout: u32, group: u8, num: u8, len: usize) -> u64 {
    (inout as u64) | (((len as u64) & 0x1fff) << 16) | ((group as u64) << 8) | (num as u64)
}

/// `IOC_INOUT` from `sys/ioccom.h` (`_IOWR`).
const IOC_INOUT: u32 = 0xc000_0000;
/// `IOC_OUT` from `sys/ioccom.h` (`_IOR`).
const IOC_OUT: u32 = 0x4000_0000;
/// The `'D'` ioctl group of `/dev/pf`.
const PF_IOCTL_GROUP: u8 = b'D';

const DIOCSTARTREF: u64 = ioc(IOC_OUT, PF_IOCTL_GROUP, 8, mem::size_of::<u64>());
const DIOCSTOPREF: u64 = ioc(
    IOC_INOUT,
    PF_IOCTL_GROUP,
    9,
    mem::size_of::<PfiocRemoveToken>(),
);
const DIOCGETRULES: u64 = ioc(IOC_INOUT, PF_IOCTL_GROUP, 6, mem::size_of::<PfiocRule>());
const DIOCGETRULE: u64 = ioc(IOC_INOUT, PF_IOCTL_GROUP, 7, mem::size_of::<PfiocRule>());
const DIOCADDRULE: u64 = ioc(IOC_INOUT, PF_IOCTL_GROUP, 4, mem::size_of::<PfiocRule>());
const DIOCBEGINADDRS: u64 = ioc(
    IOC_INOUT,
    PF_IOCTL_GROUP,
    51,
    mem::size_of::<PfiocPooladdr>(),
);
const DIOCXBEGIN: u64 = ioc(IOC_INOUT, PF_IOCTL_GROUP, 81, mem::size_of::<PfiocTrans>());
const DIOCXCOMMIT: u64 = ioc(IOC_INOUT, PF_IOCTL_GROUP, 82, mem::size_of::<PfiocTrans>());
const DIOCGETSTATUS: u64 = ioc(IOC_INOUT, PF_IOCTL_GROUP, 21, mem::size_of::<PfStatus>());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One open `/dev/pf` session. All operations take `&self` (ioctls do not
/// require exclusive access); the file descriptor is closed on drop, which
/// releases no kernel state by itself — enforcement persists until
/// [`PfSession::disable`] and [`PfSession::remove_kill_switch_rules`].
#[derive(Debug)]
pub struct PfSession(File);

impl PfSession {
    /// Open `/dev/pf` for reading and writing (writes are required by
    /// `DIOCADDRULE`/`DIOCXBEGIN`).
    pub fn open() -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open("/dev/pf")?;
        Ok(Self(file))
    }

    /// Enable PF and take a reference (returns the release token). The
    /// reference keeps PF running until released, even if other enablers
    /// come and go. Enabling an already-running PF succeeds (the reference
    /// is added on top).
    pub fn enable(&self) -> io::Result<u64> {
        let mut token: u64 = 0;
        // SAFETY: `token` is a valid, aligned u64; `DIOCSTARTREF` copies out
        // exactly one u64.
        unsafe { Self::ioctl(self.0.as_raw_fd(), DIOCSTARTREF, &mut token) }?;
        Ok(token)
    }

    /// Release a reference taken by [`PfSession::enable`]. PF stops when the
    /// last reference goes away. Idempotent: if PF is not running (all
    /// references were dropped, e.g. by an external `pfctl -d`), the
    /// release already happened.
    pub fn disable(&self, token: u64) -> io::Result<()> {
        let mut request = PfiocRemoveToken {
            token_value: token,
            refcount: 0,
        };
        let result = self.call(DIOCSTOPREF, &mut request);
        match result {
            Err(error) if error.raw_os_error() == Some(ENOENT) => Ok(()),
            other => other,
        }
    }

    /// Whether PF is currently running (evaluating rules).
    pub fn is_running(&self) -> io::Result<bool> {
        let mut status = PfStatus::default();
        self.call(DIOCGETSTATUS, &mut status)?;
        Ok(status.running != 0)
    }

    /// Load the kill-switch rules into the root filter ruleset (idempotent).
    ///
    /// Returns the number of rules that were newly installed; `0` means the
    /// exact [`RULE_COUNT`]-rule set was already present. Errors if the
    /// ruleset contains rules this module does not own — those are never
    /// clobbered.
    pub fn apply_kill_switch_rules(&self, tunnel_interface: &str) -> io::Result<usize> {
        let count = self.root_filter_rule_count()?;
        if count == 0 {
            self.load_rules(tunnel_interface)?;
            return Ok(RULE_COUNT);
        }
        if !self.rules_are_ours(count)? {
            return Err(clobber_error());
        }
        if count as usize == RULE_COUNT {
            return Ok(0);
        }
        // Our rules are present alongside more of our own (e.g. a crash
        // mid-reload): replace the whole owned set inside a fresh
        // transaction. Verified ours above, so nothing foreign is touched.
        self.clear_rules()?;
        self.load_rules(tunnel_interface)?;
        Ok(RULE_COUNT)
    }

    /// Remove the kill-switch rules from the root filter ruleset
    /// (idempotent). Returns the number of rules removed; `0` means none of
    /// ours were present. Errors if the ruleset contains rules this module
    /// does not own.
    pub fn remove_kill_switch_rules(&self) -> io::Result<usize> {
        let count = self.root_filter_rule_count()?;
        if count == 0 {
            return Ok(0);
        }
        if !self.rules_are_ours(count)? {
            return Err(clobber_error());
        }
        self.clear_rules()?;
        Ok(count as usize)
    }
}

/// The error returned when the root filter ruleset holds rules this module
/// does not own: enforcement refuses to touch (or rely on) them.
fn clobber_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "the root PF filter ruleset contains rules not owned by this helper",
    )
}

// Private machinery.
impl PfSession {
    /// Issue an ioctl; non-zero return is an error carrying the kernel's
    /// `errno`.
    ///
    /// # Safety
    ///
    /// `arg` must point to a valid, initialized object of the type the
    /// request reads and writes; all callers pass pinned local variables.
    unsafe fn ioctl<T>(fd: RawFd, request: u64, arg: *mut T) -> io::Result<()> {
        // SAFETY: `ioctl` is called with a valid fd and a valid `arg` as
        // documented above.
        unsafe {
            let result = libc::ioctl(fd, request, arg);
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Issue an ioctl against this session.
    fn call<T>(&self, request: u64, arg: *mut T) -> io::Result<()> {
        // SAFETY: callers pass valid, pinned objects; `self.0` is a valid fd.
        unsafe { Self::ioctl(self.0.as_raw_fd(), request, arg) }
    }

    /// The number of rules in the root (empty-anchor) filter ruleset.
    fn root_filter_rule_count(&self) -> io::Result<u32> {
        let mut request = PfiocRule {
            rule: PfRule {
                action: PF_DROP,
                ..PfRule::default()
            },
            ..PfiocRule::default()
        };
        self.call(DIOCGETRULES, &mut request)?;
        Ok(request.nr)
    }

    /// Verify every rule in the root filter ruleset carries our label.
    /// `count` must be non-zero. Reads the active ticket first
    /// (`DIOCGETRULES`) and then each rule (`DIOCGETRULE`).
    fn rules_are_ours(&self, count: u32) -> io::Result<bool> {
        let mut rules = PfiocRule {
            rule: PfRule {
                action: PF_DROP,
                ..PfRule::default()
            },
            ..PfiocRule::default()
        };
        self.call(DIOCGETRULES, &mut rules)?;
        for index in 0..count {
            let mut rule = PfiocRule {
                rule: PfRule {
                    action: PF_DROP,
                    ..PfRule::default()
                },
                ticket: rules.ticket,
                nr: index,
                ..PfiocRule::default()
            };
            self.call(DIOCGETRULE, &mut rule)?;
            if !label_is_ours(&rule.rule.label) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Begin a filter transaction on the root ruleset and return its
    /// (inactive) ticket.
    fn trans_begin(&self) -> io::Result<u32> {
        let mut element = PfiocTransE {
            rs_num: PF_RULESET_FILTER,
            ..PfiocTransE::default()
        };
        let mut request = PfiocTrans {
            size: 1,
            esize: mem::size_of::<PfiocTransE>() as i32,
            array: std::ptr::addr_of_mut!(element),
        };
        self.call(DIOCXBEGIN, &mut request)?;
        Ok(element.ticket)
    }

    /// Commit the transaction opened by [`PfSession::trans_begin`] with
    /// whatever rules were added since (possibly none, which clears the
    /// ruleset).
    fn trans_commit(&self, ticket: u32) -> io::Result<()> {
        let mut element = PfiocTransE {
            rs_num: PF_RULESET_FILTER,
            ticket,
            ..PfiocTransE::default()
        };
        let mut request = PfiocTrans {
            size: 1,
            esize: mem::size_of::<PfiocTransE>() as i32,
            array: std::ptr::addr_of_mut!(element),
        };
        self.call(DIOCXCOMMIT, &mut request)
    }

    /// Open the pool-addr buffer and return the `pool_ticket` the kernel
    /// requires on every subsequent `DIOCADDRULE`.
    fn begin_addrs(&self) -> io::Result<u32> {
        let mut request = PfiocPooladdr::default();
        self.call(DIOCBEGINADDRS, &mut request)?;
        Ok(request.ticket)
    }

    /// Add one rule to the open transaction.
    fn add_rule(&self, rule: &PfRule, ticket: u32, pool_ticket: u32) -> io::Result<()> {
        let mut request = PfiocRule {
            ticket,
            pool_ticket,
            rule: *rule,
            ..PfiocRule::default()
        };
        self.call(DIOCADDRULE, &mut request)
    }

    /// Install the three kill-switch rules in one transaction.
    fn load_rules(&self, tunnel_interface: &str) -> io::Result<()> {
        let interface = validate_interface_name(tunnel_interface)?;
        let ticket = self.trans_begin()?;
        // A failed load commits nothing; the next `trans_begin` discards the
        // abandoned inactive rules (the kernel drains them on re-begin).
        let pool_ticket = self.begin_addrs()?;
        for rule in build_rules(interface) {
            self.add_rule(&rule, ticket, pool_ticket)?;
        }
        self.trans_commit(ticket)
    }

    /// Clear the root filter ruleset: commit an empty transaction. Only
    /// callers that verified the ruleset is entirely ours may use this.
    fn clear_rules(&self) -> io::Result<()> {
        let ticket = self.trans_begin()?;
        self.trans_commit(ticket)
    }
}

// ---------------------------------------------------------------------------
// Rule construction
// ---------------------------------------------------------------------------

/// Build the three enforcement rules: pass loopback, pass the tunnel
/// interface, block everything outbound.
fn build_rules(tunnel_interface: &str) -> [PfRule; RULE_COUNT] {
    [
        pass_rule("lo0"),
        pass_rule(tunnel_interface),
        block_out_rule(),
    ]
}

/// A `pass quick` rule bound to an interface, both families, no ports, no
/// state keeping (state is irrelevant for a static permit).
fn pass_rule(ifname: &str) -> PfRule {
    PfRule {
        action: PF_PASS,
        direction: PF_INOUT,
        quick: 1,
        af: AF_UNSPEC,
        ifname: fill_ifname(ifname),
        label: fill_label(),
        src: any_rule_addr(),
        dst: any_rule_addr(),
        ..PfRule::default()
    }
}

/// A `block drop quick` rule on every interface, outbound only, both
/// families.
fn block_out_rule() -> PfRule {
    PfRule {
        action: PF_DROP,
        direction: PF_OUT,
        quick: 1,
        af: AF_UNSPEC,
        label: fill_label(),
        src: any_rule_addr(),
        dst: any_rule_addr(),
        ..PfRule::default()
    }
}

/// An "any" rule address: `PF_ADDR_ADDRMASK` with a zeroed address and a
/// zeroed mask. The kernel matches `(address & mask) == (rule & mask)`, so a
/// zero mask matches everything; `AF_UNSPEC` matches both families.
fn any_rule_addr() -> PfRuleAddr {
    PfRuleAddr {
        addr: PfAddrWrap {
            addr_type: PF_ADDR_ADDRMASK,
            ..PfAddrWrap::default()
        },
        ..PfRuleAddr::default()
    }
}

/// Copy a short NUL-terminated name into a fixed kernel buffer, truncating
/// at the buffer end (callers validate lengths; the kernel also NUL-checks).
fn fill_into<const N: usize>(name: &str) -> [u8; N] {
    let mut buffer = [0u8; N];
    let len = name.len().min(N);
    buffer[..len].copy_from_slice(&name.as_bytes()[..len]);
    buffer
}

/// Fill an `IFNAMSIZ` buffer (16).
fn fill_ifname(name: &str) -> [u8; 16] {
    fill_into::<16>(name)
}

/// Fill a `PF_RULE_LABEL_SIZE` buffer (64).
fn fill_label() -> [u8; 64] {
    fill_into::<64>(RULE_LABEL)
}

/// Check a rule label buffer against [`RULE_LABEL`]: exact match, followed
/// by a NUL byte. A longer label sharing the prefix is foreign.
fn label_is_ours(label: &[u8; 64]) -> bool {
    let bytes = RULE_LABEL.as_bytes();
    label[..bytes.len()] == *bytes && label[bytes.len()] == 0
}

/// Validate a BSD interface name for the kernel: printable ASCII, at most
/// `IFNAMSIZ - 1` bytes (the kernel requires the NUL terminator).
fn validate_interface_name(name: &str) -> io::Result<&str> {
    if name.is_empty() || name.len() >= 16 || !name.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name must be 1-15 printable ASCII bytes",
        ));
    }
    Ok(name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rule_label_roundtrip() {
        let label = fill_label();
        assert!(label_is_ours(&label));
        // A longer label sharing our prefix is not ours.
        let mut extended = fill_label();
        extended[RULE_LABEL.len()] = b'x';
        assert!(!label_is_ours(&extended));
        assert!(!label_is_ours(&fill_into::<64>("other")));
    }

    #[test]
    fn interface_name_validation() {
        assert_eq!(validate_interface_name("utun7").expect("valid"), "utun7");
        assert_eq!(validate_interface_name("lo0").expect("valid"), "lo0");
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("utun999999999999999").is_err());
        assert!(validate_interface_name("utun 1").is_err());
        assert!(validate_interface_name("utün").is_err());
    }

    #[test]
    fn rules_are_well_formed() {
        let rules = build_rules("utun4");
        assert_eq!(rules.len(), RULE_COUNT);
        // pass lo0
        assert_eq!(rules[0].action, PF_PASS);
        assert_eq!(rules[0].direction, PF_INOUT);
        assert_eq!(rules[0].quick, 1);
        assert_eq!(&rules[0].ifname[..4], b"lo0\0");
        assert!(rules[0].keep_state == 0 && rules[0].af == AF_UNSPEC);
        // pass tunnel
        assert_eq!(rules[1].action, PF_PASS);
        assert_eq!(&rules[1].ifname[..6], b"utun4\0");
        // block out
        assert_eq!(rules[2].action, PF_DROP);
        assert_eq!(rules[2].direction, PF_OUT);
        assert!(rules[2].ifname.iter().all(|byte| *byte == 0));
        // all rules carry our label and "any" addresses
        for rule in &rules {
            assert!(label_is_ours(&rule.label));
            assert_eq!(rule.src.addr.addr_type, PF_ADDR_ADDRMASK);
            assert_eq!(rule.src.addr.v.addr, PfAddr([0; 16]));
            assert_eq!(rule.src.addr.v.mask, PfAddr([0; 16]));
        }
    }

    #[test]
    fn ioctl_numbers_match_the_c_encoding() {
        // DIOCSTARTREF = _IOR('D', 8, u64): IOC_OUT | len<<16 | 'D'<<8 | 8
        assert_eq!(DIOCSTARTREF, 0x4008_4408);
        // DIOCSTOPREF = _IOWR('D', 9, struct pfioc_remove_token)
        assert_eq!(DIOCSTOPREF, 0xc010_4409);
        // DIOCADDRULE = _IOWR('D', 4, struct pfioc_rule)
        assert_eq!(DIOCADDRULE, 0xcc20_4404);
        // DIOCGETRULES = _IOWR('D', 6, struct pfioc_rule)
        assert_eq!(DIOCGETRULES, 0xcc20_4406);
        // DIOCGETRULE = _IOWR('D', 7, struct pfioc_rule)
        assert_eq!(DIOCGETRULE, 0xcc20_4407);
        // DIOCBEGINADDRS = _IOWR('D', 51, struct pfioc_pooladdr)
        assert_eq!(DIOCBEGINADDRS, 0xc470_4433);
        // DIOCXBEGIN = _IOWR('D', 81, struct pfioc_trans)
        assert_eq!(DIOCXBEGIN, 0xc010_4451);
        // DIOCXCOMMIT = _IOWR('D', 82, struct pfioc_trans)
        assert_eq!(DIOCXCOMMIT, 0xc010_4452);
        // DIOCGETSTATUS = _IOWR('D', 21, struct pf_status)
        assert_eq!(DIOCGETSTATUS, 0xc1b8_4415);
    }
}
