//! Windows Filtering Platform (WFP) kill-switch enforcement.
//!
//! The helper must not shell out (§10.5), so instead of `netsh wfp` this
//! module talks to the WFP engine (`fwpuclnt.dll`) directly through the
//! `windows-sys` bindings. It installs a set of **persistent** filters that
//! drop all outbound IPv4/IPv6 except loopback, the tunnel adapter, and the
//! split-tunnel bypass destinations.
//!
//! # Enforcement design
//!
//! Two layers are used (`FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `..._V6`), each
//! holding, inside one dedicated sublayer:
//!
//! 1. a `permit` for loopback traffic (`FWP_CONDITION_FLAG_IS_LOOPBACK`);
//! 2. a `permit` for traffic bound to the tunnel adapter (matched by its
//!    Win32 interface LUID);
//! 3. one `permit` per split-tunnel bypass destination (a remote-address
//!    subnet condition: these destinations leave through the physical
//!    network, so the catch-all block must not drop them);
//! 4. a `block` of everything else.
//!
//! Permits carry the maximum filter weight and blocks the minimum, so the
//! first-match arbitration always resolves loopback/tunnel/bypass traffic
//! before the catch-all block. Egress-only enforcement (the
//! `ALE_AUTH_CONNECT` layers are evaluated for outgoing connections) mirrors
//! the Linux backend's blackhole-route insurance: inbound traffic is
//! untouched, and only the leak direction is dropped.
//!
//! # Persistence and fail-closed behaviour
//!
//! Filters and sublayer are created with the `PERSISTENT` flag: they live in
//! the WFP object store, survive helper crashes and reboots, and keep
//! enforcing until they are explicitly deleted. `apply` is therefore
//! replace-semantics: everything in the dedicated sublayer is enumerated
//! and deleted first, then freshly added with the current adapter LUID and
//! bypass set; `teardown`/uninstall deletes them all. Bypass permits use
//! deterministic keys (derived from the prefix), but since the bypass set
//! changes between applies, ownership is swept by enumeration rather than
//! by fixed keys — the sublayer makes ownership unambiguous, so nothing
//! outside it is ever touched.
//!
//! # Unsafe scope
//!
//! All `unsafe` here is the FFI itself: opening/closing the engine handle
//! and calling the `Fwpm*` functions with fixed-size structs built from
//! constants plus validated values (the adapter LUID and the bypass
//! prefixes). No packets, addresses, or logs ever pass through this module
//! (§10.5).

use std::io;
use std::net::IpAddr;

use windows_sys::Win32::Foundation::{FWP_E_ALREADY_EXISTS, FWP_E_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0,
    FWP_FILTER_ENUM_FULLY_CONTAINED, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ANY_SET, FWP_UINT8,
    FWP_UINT32, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK,
    FWP_V6_ADDR_MASK, FWP_VALUE0, FWPM_ACTION0, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::{GUID, PWSTR};
use wintun_bindings::NET_LUID_LH;

/// The dedicated sublayer all kill-switch filters live in. A separate
/// sublayer makes ownership unambiguous: `teardown` deletes exactly the
/// objects this module created, leaving other WFP consumers alone.
const SUBLAYER_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0001);

/// Fixed keys for the base filters (one per object, persistent):
/// loopback permit, tunnel-interface permit, catch-all block, per family.
const LOOPBACK_PERMIT_V4_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0011);
const INTERFACE_PERMIT_V4_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0012);
const BLOCK_ALL_V4_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0013);
const LOOPBACK_PERMIT_V6_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0021);
const INTERFACE_PERMIT_V6_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0022);
const BLOCK_ALL_V6_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0023);

/// How many base filters one enforcement consists of (3 per family), before
/// the dynamically-keyed bypass permits.
const FILTER_COUNT: usize = 6;

/// How many filters one enumeration batch asks for.
const ENUM_BATCH: u32 = 1000;

/// Highest explicit filter weight (permits are evaluated first).
const PERMIT_WEIGHT: u8 = 15;
/// Lowest explicit filter weight (the catch-all block is evaluated last).
const BLOCK_WEIGHT: u8 = 0;

/// Build a `GUID` from its 128-bit value (little-endian byte layout).
const fn guid(value: u128) -> GUID {
    GUID::from_u128(value)
}

/// Field-wise `GUID` comparison (windows-sys `GUID` has no `PartialEq`).
fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

/// Extract the 64-bit interface identifier from a Win32 `NET_LUID_LH`.
pub fn adapter_luid(luid: NET_LUID_LH) -> u64 {
    // SAFETY: `NET_LUID_LH` is a union whose `Value` member covers the whole
    // struct; reading the raw value is the documented way to use it.
    unsafe { luid.Value }
}

/// One open WFP engine session (an admin handle). All operations take
/// `&self`; the engine is closed on drop.
pub struct WfpEngine(HANDLE);

impl std::fmt::Debug for WfpEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the handle value itself.
        formatter.debug_struct("WfpEngine").finish_non_exhaustive()
    }
}

impl WfpEngine {
    /// Open a handle to the local WFP engine. Requires administrator
    /// privileges (the helper runs elevated).
    pub fn open() -> io::Result<Self> {
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: all arguments are valid: null server name (local engine),
        // NTLM authentication, no credentials, no session template, and an
        // out-pointer to a valid local handle slot.
        let error = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                std::ptr::null(),
                &mut handle,
            )
        };
        check(error, "FwpmEngineOpen0")?;
        Ok(Self(handle))
    }

    /// Install (replace-semantics) the kill-switch filters for the given
    /// tunnel adapter LUID, plus one remote-subnet `permit` per split-tunnel
    /// bypass prefix. Idempotent: re-applying produces the same set.
    /// Returns the number of filters enforced (base set + one per bypass).
    pub fn apply_kill_switch(
        &self,
        tunnel_luid: u64,
        bypass: &[(IpAddr, u8)],
    ) -> io::Result<usize> {
        self.ensure_sublayer()?;
        // Replace: sweep our sublayer first (a previous apply may have
        // enforced a different adapter LUID or bypass set).
        self.delete_sublayer_filters()?;
        for filter in build_filters(tunnel_luid, bypass) {
            self.add_filter(&filter)?;
        }
        Ok(FILTER_COUNT + bypass.len())
    }

    /// Remove every kill-switch filter and the sublayer itself
    /// (idempotent). Never touches objects outside the dedicated sublayer.
    pub fn remove_kill_switch(&self) -> io::Result<()> {
        self.delete_sublayer_filters()?;
        // SAFETY: `SUBLAYER_KEY` is a valid, static GUID.
        let error = unsafe { FwpmSubLayerDeleteByKey0(self.0, &SUBLAYER_KEY) };
        match check(error, "FwpmSubLayerDeleteByKey0") {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    /// Add the sublayer if it does not exist yet (persistent).
    fn ensure_sublayer(&self) -> io::Result<()> {
        let mut name = wide("tobro kill switch");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display_data(name.as_mut_ptr()),
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            weight: u16::MAX, // evaluated before default-weight sublayers
            ..FWPM_SUBLAYER0::default()
        };
        // SAFETY: `sublayer` and its `displayData` buffers live across the
        // call; `FwpmSubLayerAdd0` copies the object into the engine.
        let error = unsafe { FwpmSubLayerAdd0(self.0, &sublayer, std::ptr::null_mut()) };
        match check(error, "FwpmSubLayerAdd0") {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            other => other,
        }
    }

    /// Add one persistent filter.
    fn add_filter(&self, filter: &FilterSpec) -> io::Result<()> {
        let mut scratch = ConditionScratch::new();
        let mut conditions = build_conditions(&filter.condition, &mut scratch);
        let mut name = wide(&filter.name);
        let native = FWPM_FILTER0 {
            filterKey: filter.key,
            displayData: display_data(name.as_mut_ptr()),
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            layerKey: filter.layer,
            subLayerKey: SUBLAYER_KEY,
            weight: weight_value(filter.weight),
            numFilterConditions: conditions
                .len()
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many conditions"))?,
            filterCondition: conditions.as_mut_ptr().cast::<FWPM_FILTER_CONDITION0>(),
            action: FWPM_ACTION0 {
                r#type: filter.action,
                ..FWPM_ACTION0::default()
            },
            ..FWPM_FILTER0::default()
        };
        let mut id: u64 = 0;
        // SAFETY: `native` and every buffer it points to (`name`,
        // `conditions`, `scratch`) live across the call; `id` is a valid out
        // slot for the assigned filter identifier.
        let error = unsafe { FwpmFilterAdd0(self.0, &native, std::ptr::null_mut(), &mut id) };
        check(error, "FwpmFilterAdd0")
    }

    /// Delete every filter this module owns in the dedicated sublayer,
    /// across both connect layers. Enumeration-based: the sublayer holds
    /// dynamically-keyed bypass permits, so a full sweep of the sublayer is
    /// the only complete cleanup; the sublayer check happens client-side.
    /// Returns the number of filters removed.
    fn delete_sublayer_filters(&self) -> io::Result<usize> {
        let mut removed = 0;
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ] {
            removed += self.delete_layer_filters(&layer)?;
        }
        Ok(removed)
    }

    /// Enumerate one layer's filters and delete those in our sublayer.
    fn delete_layer_filters(&self, layer: &GUID) -> io::Result<usize> {
        // SAFETY: zeroing a struct with raw-pointer members yields a valid
        // all-null state; the used members are set right after.
        let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { std::mem::zeroed() };
        template.layerKey = *layer;
        template.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
        // actionMask 0: enumerate filters regardless of their action.
        template.actionMask = 0;

        let mut enum_handle: HANDLE = std::ptr::null_mut();
        // SAFETY: valid engine handle, valid template reference, out-slot
        // for the enumeration handle.
        let error = unsafe { FwpmFilterCreateEnumHandle0(self.0, &template, &mut enum_handle) };
        check(error, "FwpmFilterCreateEnumHandle0")?;

        let mut ids: Vec<u64> = Vec::new();
        let mut batch_error = Ok(());
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut returned: u32 = 0;
            // SAFETY: valid engine and enumeration handles; `entries` and
            // `returned` are out-slots.
            let error = unsafe {
                FwpmFilterEnum0(self.0, enum_handle, ENUM_BATCH, &mut entries, &mut returned)
            };
            if let Err(error) = check(error, "FwpmFilterEnum0") {
                batch_error = Err(error);
                break;
            }
            if returned == 0 {
                break;
            }
            // SAFETY: `FwpmFilterEnum0` filled `returned` consecutive
            // pointers into `entries`.
            let filters = unsafe {
                std::slice::from_raw_parts(entries, usize::try_from(returned).unwrap_or(0))
            };
            for entry in filters {
                // SAFETY: each entry points to a filter owned by the engine
                // until `FwpmFreeMemory0` below.
                let filter = unsafe { &**entry };
                if guid_eq(&filter.subLayerKey, &SUBLAYER_KEY) {
                    ids.push(filter.filterId);
                }
            }
            // SAFETY: `entries` was allocated by `FwpmFilterEnum0`; freeing
            // it releases that allocation.
            unsafe { FwpmFreeMemory0(entries.cast::<*mut core::ffi::c_void>()) };
        }
        // SAFETY: the handle came from `FwpmFilterCreateEnumHandle0`.
        let error = unsafe { FwpmFilterDestroyEnumHandle0(self.0, enum_handle) };
        check(error, "FwpmFilterDestroyEnumHandle0")?;
        batch_error?;

        let mut removed = 0;
        for id in ids {
            // SAFETY: valid engine handle and a filter identifier just
            // obtained from the enumeration.
            let error = unsafe { FwpmFilterDeleteById0(self.0, id) };
            match check(error, "FwpmFilterDeleteById0") {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(removed)
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle is valid and owned; closing is best-effort
            // on the drop path.
            unsafe { FwpmEngineClose0(self.0) };
        }
    }
}

// ---------------------------------------------------------------------------
// Filter descriptions
// ---------------------------------------------------------------------------

/// One filter to install, kept symbolic so the FFI fill stays testable.
struct FilterSpec {
    /// Persistent object key.
    key: GUID,
    /// Layer (`ALE_AUTH_CONNECT` v4 or v6).
    layer: GUID,
    /// Display name (diagnostics only; never logged by the helper).
    name: String,
    /// Action (`FWP_ACTION_PERMIT` or `FWP_ACTION_BLOCK`).
    action: u32,
    /// Explicit weight: permits above blocks.
    weight: u8,
    /// What the filter matches.
    condition: FilterCondition,
}

/// What one kill-switch filter matches.
enum FilterCondition {
    /// Loopback traffic (condition-flags match).
    Loopback,
    /// Traffic bound to one interface LUID (the tunnel adapter).
    Interface(u64),
    /// Traffic to one remote subnet — the split-tunnel bypass permit.
    RemoteSubnet {
        /// Subnet address (host bits are masked off defensively).
        addr: IpAddr,
        /// Prefix length (clamped to the family maximum).
        prefix_len: u8,
    },
    /// Everything (the catch-all block).
    Any,
}

/// The fixed keys of the base enforcement (loopback, interface, block;
/// v4 then v6), in add order. Test-visible only: runtime deletion sweeps
/// the sublayer by enumeration instead of by fixed keys.
#[cfg(test)]
const BASE_KEYS: [GUID; FILTER_COUNT] = [
    LOOPBACK_PERMIT_V4_KEY,
    INTERFACE_PERMIT_V4_KEY,
    BLOCK_ALL_V4_KEY,
    LOOPBACK_PERMIT_V6_KEY,
    INTERFACE_PERMIT_V6_KEY,
    BLOCK_ALL_V6_KEY,
];

/// Build the base enforcement filters for one adapter LUID plus one bypass
/// permit per split-tunnel prefix.
fn build_filters(tunnel_luid: u64, bypass: &[(IpAddr, u8)]) -> Vec<FilterSpec> {
    let mut filters = vec![
        FilterSpec {
            key: LOOPBACK_PERMIT_V4_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            name: "tobro kill switch: permit loopback (IPv4)".to_owned(),
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            condition: FilterCondition::Loopback,
        },
        FilterSpec {
            key: INTERFACE_PERMIT_V4_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            name: "tobro kill switch: permit tunnel adapter (IPv4)".to_owned(),
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            condition: FilterCondition::Interface(tunnel_luid),
        },
        FilterSpec {
            key: BLOCK_ALL_V4_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            name: "tobro kill switch: block all egress (IPv4)".to_owned(),
            action: FWP_ACTION_BLOCK,
            weight: BLOCK_WEIGHT,
            condition: FilterCondition::Any,
        },
        FilterSpec {
            key: LOOPBACK_PERMIT_V6_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            name: "tobro kill switch: permit loopback (IPv6)".to_owned(),
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            condition: FilterCondition::Loopback,
        },
        FilterSpec {
            key: INTERFACE_PERMIT_V6_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            name: "tobro kill switch: permit tunnel adapter (IPv6)".to_owned(),
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            condition: FilterCondition::Interface(tunnel_luid),
        },
        FilterSpec {
            key: BLOCK_ALL_V6_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            name: "tobro kill switch: block all egress (IPv6)".to_owned(),
            action: FWP_ACTION_BLOCK,
            weight: BLOCK_WEIGHT,
            condition: FilterCondition::Any,
        },
    ];
    for &(addr, prefix_len) in bypass {
        let (layer, family) = match addr {
            IpAddr::V4(_) => (FWPM_LAYER_ALE_AUTH_CONNECT_V4, "IPv4"),
            IpAddr::V6(_) => (FWPM_LAYER_ALE_AUTH_CONNECT_V6, "IPv6"),
        };
        filters.push(FilterSpec {
            key: bypass_key(addr, prefix_len),
            layer,
            name: format!("tobro kill switch: permit bypass {addr}/{prefix_len} ({family})"),
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            condition: FilterCondition::RemoteSubnet { addr, prefix_len },
        });
    }
    filters
}

/// Deterministic filter key for one bypass permit: two independent 64-bit
/// FNV-1a streams over a domain-separated byte stream (family tag, address
/// octets, prefix length) packed into one GUID. Determinism keeps the key
/// stable across applies of the same prefix, and the domain separation keeps
/// different prefixes (and the same prefix across families) on distinct
/// keys.
fn bypass_key(addr: IpAddr, prefix_len: u8) -> GUID {
    let mut stream = Vec::with_capacity(18);
    match addr {
        IpAddr::V4(v4) => {
            stream.push(b'4');
            stream.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            stream.push(b'6');
            stream.extend_from_slice(&v6.octets());
        }
    }
    stream.push(prefix_len);
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut key: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 64-bit offset basis
    let mut salt: u64 = 0x746f_6272_6f5f_6b73; // "tobro_ks"
    for byte in &stream {
        key = (key ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
        salt = (salt ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
    }
    let value = (u128::from(key) << 64) | u128::from(salt);
    // A zero GUID means "no key"; flip a bit if the hash lands exactly on it.
    guid(if value == 0 { 1 } else { value })
}

/// Scratch storage the condition values point into. WFP copies condition
/// data during `FwpmFilterAdd0`, so this must outlive that call.
struct ConditionScratch {
    /// Backing store for an `FWP_UINT64` interface-LUID condition.
    luid: u64,
    /// Backing store for an `FWP_V4_ADDR_MASK` condition.
    v4: FWP_V4_ADDR_AND_MASK,
    /// Backing store for an `FWP_V6_ADDR_MASK` condition.
    v6: FWP_V6_ADDR_AND_MASK,
}

impl ConditionScratch {
    fn new() -> Self {
        Self {
            luid: 0,
            v4: FWP_V4_ADDR_AND_MASK { addr: 0, mask: 0 },
            v6: FWP_V6_ADDR_AND_MASK {
                addr: [0; 16],
                prefixLength: 0,
            },
        }
    }
}

/// Materialize the WFP condition array for one filter condition. The
/// returned Vec and the scratch storage must outlive the `FwpmFilterAdd0`
/// call.
fn build_conditions(
    condition: &FilterCondition,
    scratch: &mut ConditionScratch,
) -> Vec<FWPM_FILTER_CONDITION0> {
    let mut conditions = Vec::new();
    match condition {
        FilterCondition::Loopback => {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_FLAGS,
                matchType: FWP_MATCH_FLAGS_ANY_SET,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    // Union write selecting the `uint32` member for
                    // `FWP_UINT32` (writing a union member needs no `unsafe`;
                    // only reading a non-`Copy`-validated member would).
                    Anonymous: {
                        let mut value = FWP_CONDITION_VALUE0::default();
                        value.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                        value.Anonymous
                    },
                },
            });
        }
        FilterCondition::Interface(luid) => {
            scratch.luid = *luid;
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT64,
                    // Union write selecting the `uint64` member; the pointer
                    // target (`scratch.luid`) outlives the engine call.
                    Anonymous: {
                        let mut value_out = FWP_CONDITION_VALUE0::default();
                        value_out.Anonymous.uint64 = std::ptr::from_mut(&mut scratch.luid);
                        value_out.Anonymous
                    },
                },
            });
        }
        FilterCondition::RemoteSubnet { addr, prefix_len } => match addr {
            // `FWP_V4_ADDR_AND_MASK` carries the address and mask in HOST
            // byte order (fwptypes.h), unlike iphlpapi's network order.
            IpAddr::V4(v4) => {
                scratch.v4 = FWP_V4_ADDR_AND_MASK {
                    addr: u32::from(*v4),
                    mask: subnet_mask_v4(*prefix_len),
                };
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V4_ADDR_MASK,
                        Anonymous: {
                            let mut value = FWP_CONDITION_VALUE0::default();
                            value.Anonymous.v4AddrMask = std::ptr::from_mut(&mut scratch.v4);
                            value.Anonymous
                        },
                    },
                });
            }
            IpAddr::V6(v6) => {
                scratch.v6 = FWP_V6_ADDR_AND_MASK {
                    addr: v6.octets(),
                    prefixLength: (*prefix_len).min(128),
                };
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_V6_ADDR_MASK,
                        Anonymous: {
                            let mut value = FWP_CONDITION_VALUE0::default();
                            value.Anonymous.v6AddrMask = std::ptr::from_mut(&mut scratch.v6);
                            value.Anonymous
                        },
                    },
                });
            }
        },
        FilterCondition::Any => {}
    }
    conditions
}

/// Host-order IPv4 subnet mask for a prefix length.
fn subnet_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len.min(32)))
    }
}

/// Build an explicit `FWP_UINT8` weight value.
fn weight_value(weight: u8) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT8,
        // Union write selecting the `uint8` member for `FWP_UINT8`.
        Anonymous: {
            let mut value = FWP_VALUE0::default();
            value.Anonymous.uint8 = weight;
            value.Anonymous
        },
    }
}

/// Build a NUL-terminated UTF-16 display name buffer.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build a display-data struct pointing at `name`.
fn display_data(name: PWSTR) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name,
        description: std::ptr::null_mut(),
    }
}

/// Map a WFP `HRESULT` to an `io::Result`; success is `S_OK` (0).
fn check(error: u32, call: &'static str) -> io::Result<()> {
    if error == 0 {
        return Ok(());
    }
    // Known-status mapping so callers can be idempotent.
    match u32::cast_signed(error) {
        code if code == FWP_E_NOT_FOUND => Err(io::Error::from(io::ErrorKind::NotFound)),
        code if code == FWP_E_ALREADY_EXISTS => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        _ => Err(io::Error::other(format!("{call} failed: 0x{error:08X}"))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Build one filter spec for condition tests.
    fn spec(condition: FilterCondition) -> FilterSpec {
        FilterSpec {
            key: LOOPBACK_PERMIT_V4_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            name: "x".to_owned(),
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            condition,
        }
    }

    #[test]
    fn base_keys_are_distinct() {
        for (index, key) in BASE_KEYS.iter().enumerate() {
            assert!(!guid_eq(key, &SUBLAYER_KEY));
            for other in &BASE_KEYS[index + 1..] {
                assert!(!guid_eq(key, other));
            }
        }
    }

    #[test]
    fn filters_cover_both_families_and_arbitration() {
        let filters = build_filters(0x1234, &[]);
        assert_eq!(filters.len(), FILTER_COUNT);
        let v4: Vec<_> = filters
            .iter()
            .filter(|f| guid_eq(&f.layer, &FWPM_LAYER_ALE_AUTH_CONNECT_V4))
            .collect();
        let v6: Vec<_> = filters
            .iter()
            .filter(|f| guid_eq(&f.layer, &FWPM_LAYER_ALE_AUTH_CONNECT_V6))
            .collect();
        assert_eq!(v4.len(), 3);
        assert_eq!(v6.len(), 3);
        for family in [&v4, &v6] {
            assert!(
                family
                    .iter()
                    .all(|f| f.action == FWP_ACTION_PERMIT || f.action == FWP_ACTION_BLOCK)
            );
            // Permits strictly outweigh the block.
            let block = family
                .iter()
                .find(|f| f.action == FWP_ACTION_BLOCK)
                .unwrap();
            assert_eq!(block.weight, BLOCK_WEIGHT);
            assert!(matches!(block.condition, FilterCondition::Any));
            for permit in family.iter().filter(|f| f.action == FWP_ACTION_PERMIT) {
                assert!(permit.weight > block.weight);
                assert!(matches!(
                    permit.condition,
                    FilterCondition::Loopback | FilterCondition::Interface(_)
                ));
            }
            // The interface permit pins exactly the requested LUID.
            let iface = family
                .iter()
                .find(|f| matches!(f.condition, FilterCondition::Interface(0x1234)))
                .unwrap();
            assert!(matches!(iface.condition, FilterCondition::Interface(_)));
        }
    }

    #[test]
    fn bypass_filters_are_subnet_permits_on_their_own_layer() {
        let bypass = [
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24u8),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                32u8,
            ),
        ];
        let filters = build_filters(0x1234, &bypass);
        assert_eq!(filters.len(), FILTER_COUNT + bypass.len());

        let v4_bypass = &filters[FILTER_COUNT];
        assert!(guid_eq(&v4_bypass.layer, &FWPM_LAYER_ALE_AUTH_CONNECT_V4));
        assert_eq!(v4_bypass.action, FWP_ACTION_PERMIT);
        assert_eq!(v4_bypass.weight, PERMIT_WEIGHT);
        assert!(matches!(
            v4_bypass.condition,
            FilterCondition::RemoteSubnet { .. }
        ));

        let v6_bypass = &filters[FILTER_COUNT + 1];
        assert!(guid_eq(&v6_bypass.layer, &FWPM_LAYER_ALE_AUTH_CONNECT_V6));

        // Keys are deterministic, distinct across family/prefix, and never
        // collide with the base keys.
        assert!(guid_eq(
            &bypass_key(bypass[0].0, bypass[0].1),
            &v4_bypass.key
        ));
        assert!(!guid_eq(
            &bypass_key(bypass[0].0, bypass[0].1),
            &bypass_key(bypass[1].0, bypass[1].1)
        ));
        // Same address, different family => different key.
        assert!(!guid_eq(
            &bypass_key(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            &bypass_key(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        ));
        // Same address, different prefix => different key.
        assert!(!guid_eq(
            &bypass_key(bypass[0].0, 24),
            &bypass_key(bypass[0].0, 25)
        ));
        for key in &BASE_KEYS {
            assert!(!guid_eq(&v4_bypass.key, key));
        }
    }

    #[test]
    fn condition_values_are_well_formed() {
        // Loopback condition: flags + IS_LOOPBACK, FWP_UINT32.
        let conditions = build_conditions(&FilterCondition::Loopback, &mut ConditionScratch::new());
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].matchType, FWP_MATCH_FLAGS_ANY_SET);
        // SAFETY: the condition was built with `FWP_UINT32`; reading the
        // active member is sound in this test-only check.
        let value = unsafe { conditions[0].conditionValue.Anonymous.uint32 };
        assert_eq!(value, FWP_CONDITION_FLAG_IS_LOOPBACK);

        // Interface condition: equality + the LUID pointer, FWP_UINT64.
        let conditions = build_conditions(
            &FilterCondition::Interface(0xdead_beef),
            &mut ConditionScratch::new(),
        );
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].matchType, FWP_MATCH_EQUAL);
        // SAFETY: built with `FWP_UINT64`; the pointer target is the LUID.
        let pointer = unsafe { conditions[0].conditionValue.Anonymous.uint64 };
        assert_eq!(unsafe { *pointer }, 0xdead_beef);

        // Catch-all: no conditions at all.
        let conditions = build_conditions(&FilterCondition::Any, &mut ConditionScratch::new());
        assert!(conditions.is_empty());
    }

    #[test]
    fn subnet_conditions_match_their_prefixes() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0));
        let mut scratch = ConditionScratch::new();
        let conditions = build_conditions(
            &FilterCondition::RemoteSubnet {
                addr: v4,
                prefix_len: 24,
            },
            &mut scratch,
        );
        assert_eq!(conditions.len(), 1);
        let condition = &conditions[0];
        assert!(guid_eq(
            &condition.fieldKey,
            &FWPM_CONDITION_IP_REMOTE_ADDRESS
        ));
        assert_eq!(condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.conditionValue.r#type, FWP_V4_ADDR_MASK);
        // SAFETY: built with `FWP_V4_ADDR_MASK`; read the pointed value.
        let value = unsafe { *condition.conditionValue.Anonymous.v4AddrMask };
        // Host byte order, per fwptypes.h.
        assert_eq!(value.addr, u32::from(Ipv4Addr::new(192, 0, 2, 0)));
        assert_eq!(value.mask, 0xff00_0000);

        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let mut scratch = ConditionScratch::new();
        let conditions = build_conditions(
            &FilterCondition::RemoteSubnet {
                addr: IpAddr::V6(v6),
                prefix_len: 32,
            },
            &mut scratch,
        );
        assert_eq!(conditions[0].conditionValue.r#type, FWP_V6_ADDR_MASK);
        // SAFETY: built with `FWP_V6_ADDR_MASK`; read the pointed value.
        let value = unsafe { *conditions[0].conditionValue.Anonymous.v6AddrMask };
        assert_eq!(value.addr, v6.octets());
        assert_eq!(value.prefixLength, 32);
    }

    #[test]
    fn subnet_masks_are_host_order() {
        assert_eq!(subnet_mask_v4(0), 0);
        assert_eq!(subnet_mask_v4(24), 0xff00_0000);
        assert_eq!(subnet_mask_v4(32), u32::MAX);
        // Over-long prefix lengths are clamped.
        assert_eq!(subnet_mask_v4(99), u32::MAX);
    }

    #[test]
    fn weight_and_status_helpers() {
        let weight = weight_value(15);
        assert_eq!(weight.r#type, FWP_UINT8);
        // SAFETY: the value was built with `FWP_UINT8`.
        assert_eq!(unsafe { weight.Anonymous.uint8 }, 15);

        assert!(check(0, "x").is_ok());
        assert_eq!(
            check(FWP_E_NOT_FOUND as u32, "x").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            check(FWP_E_ALREADY_EXISTS as u32, "x").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(check(0x8032_0099, "x").is_err());
    }

    #[test]
    fn wide_strings_are_nul_terminated() {
        assert_eq!(wide("ab"), vec![b'a' as u16, b'b' as u16, 0]);
        assert_eq!(wide(""), vec![0]);
    }
}
