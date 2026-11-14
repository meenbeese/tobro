//! Windows Filtering Platform (WFP) kill-switch enforcement.
//!
//! The helper must not shell out (§10.5), so instead of `netsh wfp` this
//! module talks to the WFP engine (`fwpuclnt.dll`) directly through the
//! `windows-sys` bindings. It installs a set of **persistent** filters that
//! drop all outbound IPv4/IPv6 except loopback and the tunnel adapter.
//!
//! # Enforcement design
//!
//! Two layers are used (`FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `..._V6`), each
//! holding three filters inside one dedicated sublayer:
//!
//! 1. `permit` loopback traffic (`FWP_CONDITION_FLAG_IS_LOOPBACK`);
//! 2. `permit` traffic bound to the tunnel adapter (matched by its Win32
//!    interface LUID);
//! 3. `block` everything else.
//!
//! Permits carry the maximum filter weight and blocks the minimum, so the
//! first-match arbitration always resolves loopback/tunnel traffic before
//! the catch-all block. Egress-only enforcement (the `ALE_AUTH_CONNECT`
//! layers are evaluated for outgoing connections) mirrors the Linux
//! backend's blackhole-route insurance: inbound traffic is untouched, and
//! only the leak direction is dropped.
//!
//! # Persistence and fail-closed behaviour
//!
//! Filters and sublayer are created with the `PERSISTENT` flag: they live in
//! the WFP object store, survive helper crashes and reboots, and keep
//! enforcing until they are explicitly deleted. `apply` is therefore
//! replace-semantics (stale filters are deleted first, then freshly added
//! with the current adapter LUID), and `teardown`/uninstall deletes them.
//! Filter objects use fixed GUID keys, so `teardown` is key-based and
//! idempotent (`FWP_E_NOT_FOUND` treated as success).
//!
//! # Unsafe scope
//!
//! All `unsafe` here is the FFI itself: opening/closing the engine handle
//! and calling the `Fwpm*` functions with fixed-size structs built from
//! constants plus one validated value (the adapter LUID). No packets,
//! addresses, or logs ever pass through this module (§10.5).

use std::io;

use windows_sys::Win32::Foundation::{FWP_E_ALREADY_EXISTS, FWP_E_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0,
    FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ANY_SET, FWP_UINT8, FWP_UINT32, FWP_UINT64, FWP_VALUE0,
    FWPM_ACTION0, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::{GUID, PWSTR};
use wintun_bindings::NET_LUID_LH;

/// The dedicated sublayer all kill-switch filters live in. A separate
/// sublayer makes ownership unambiguous: `teardown` deletes exactly the
/// objects this module created, leaving other WFP consumers alone.
const SUBLAYER_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0001);

/// Filter keys (fixed, one per object; persistent replace-by-key):
/// loopback permit, tunnel-interface permit, catch-all block, per family.
const LOOPBACK_PERMIT_V4_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0011);
const INTERFACE_PERMIT_V4_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0012);
const BLOCK_ALL_V4_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0013);
const LOOPBACK_PERMIT_V6_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0021);
const INTERFACE_PERMIT_V6_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0022);
const BLOCK_ALL_V6_KEY: GUID = guid(0x746f_6272_6f5f_6b73_a000_0000_0000_0023);

/// How many filters one enforcement consists of (3 per family).
const FILTER_COUNT: usize = 6;

/// Highest explicit filter weight (permits are evaluated first).
const PERMIT_WEIGHT: u8 = 15;
/// Lowest explicit filter weight (the catch-all block is evaluated last).
const BLOCK_WEIGHT: u8 = 0;

/// Build a `GUID` from its 128-bit value (little-endian byte layout).
const fn guid(value: u128) -> GUID {
    GUID::from_u128(value)
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
    /// tunnel adapter LUID. Idempotent: re-applying produces the same set.
    /// Returns the number of filters enforced (always 6 on success).
    pub fn apply_kill_switch(&self, tunnel_luid: u64) -> io::Result<usize> {
        self.ensure_sublayer()?;
        // Replace: drop any stale persistent filters first (a previous
        // apply may have enforced a different adapter LUID).
        for key in FILTER_KEYS {
            self.delete_filter_by_key(&key)?;
        }
        for filter in build_filters(tunnel_luid).iter() {
            self.add_filter(filter)?;
        }
        Ok(FILTER_COUNT)
    }

    /// Remove every kill-switch filter and the sublayer itself
    /// (idempotent). Never touches objects outside the dedicated sublayer.
    pub fn remove_kill_switch(&self) -> io::Result<()> {
        for key in FILTER_KEYS {
            self.delete_filter_by_key(&key)?;
        }
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
        let mut luid = filter.tunnel_luid.unwrap_or(0);
        let mut conditions = build_conditions(filter, &mut luid);
        let mut name = wide(filter.name);
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
        // `conditions`, `luid`) live across the call; `id` is a valid out
        // slot for the assigned filter identifier.
        let error = unsafe { FwpmFilterAdd0(self.0, &native, std::ptr::null_mut(), &mut id) };
        check(error, "FwpmFilterAdd0")
    }

    /// Delete one filter by its fixed key; `FWP_E_NOT_FOUND` is success.
    fn delete_filter_by_key(&self, key: &GUID) -> io::Result<()> {
        // SAFETY: `key` is a valid, static GUID.
        let error = unsafe { FwpmFilterDeleteByKey0(self.0, key) };
        match check(error, "FwpmFilterDeleteByKey0") {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
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
    /// Fixed persistent object key.
    key: GUID,
    /// Layer (`ALE_AUTH_CONNECT` v4 or v6).
    layer: GUID,
    /// Display name (diagnostics only; never logged by the helper).
    name: &'static str,
    /// Action (`FWP_ACTION_PERMIT` or `FWP_ACTION_BLOCK`).
    action: u32,
    /// Explicit weight: permits above blocks.
    weight: u8,
    /// `Some(luid)`: match the tunnel adapter; `None`: catch-all.
    tunnel_luid: Option<u64>,
    /// `Some(())`: match loopback traffic.
    loopback: Option<()>,
}

/// The fixed keys, in add order (loopback, interface, block; v4 then v6).
const FILTER_KEYS: [GUID; FILTER_COUNT] = [
    LOOPBACK_PERMIT_V4_KEY,
    INTERFACE_PERMIT_V4_KEY,
    BLOCK_ALL_V4_KEY,
    LOOPBACK_PERMIT_V6_KEY,
    INTERFACE_PERMIT_V6_KEY,
    BLOCK_ALL_V6_KEY,
];

/// Build the six enforcement filters for one adapter LUID.
fn build_filters(tunnel_luid: u64) -> [FilterSpec; FILTER_COUNT] {
    [
        FilterSpec {
            key: LOOPBACK_PERMIT_V4_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            name: "tobro kill switch: permit loopback (IPv4)",
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            tunnel_luid: None,
            loopback: Some(()),
        },
        FilterSpec {
            key: INTERFACE_PERMIT_V4_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            name: "tobro kill switch: permit tunnel adapter (IPv4)",
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            tunnel_luid: Some(tunnel_luid),
            loopback: None,
        },
        FilterSpec {
            key: BLOCK_ALL_V4_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            name: "tobro kill switch: block all egress (IPv4)",
            action: FWP_ACTION_BLOCK,
            weight: BLOCK_WEIGHT,
            tunnel_luid: None,
            loopback: None,
        },
        FilterSpec {
            key: LOOPBACK_PERMIT_V6_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            name: "tobro kill switch: permit loopback (IPv6)",
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            tunnel_luid: None,
            loopback: Some(()),
        },
        FilterSpec {
            key: INTERFACE_PERMIT_V6_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            name: "tobro kill switch: permit tunnel adapter (IPv6)",
            action: FWP_ACTION_PERMIT,
            weight: PERMIT_WEIGHT,
            tunnel_luid: Some(tunnel_luid),
            loopback: None,
        },
        FilterSpec {
            key: BLOCK_ALL_V6_KEY,
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            name: "tobro kill switch: block all egress (IPv6)",
            action: FWP_ACTION_BLOCK,
            weight: BLOCK_WEIGHT,
            tunnel_luid: None,
            loopback: None,
        },
    ]
}

/// Materialize the WFP condition array for one filter. The returned Vec must
/// outlive the `FwpmFilterAdd0` call, and `luid` must outlive it too (the
/// `FWP_UINT64` condition points at it).
fn build_conditions(filter: &FilterSpec, luid: &mut u64) -> Vec<FWPM_FILTER_CONDITION0> {
    let mut conditions = Vec::new();
    if filter.loopback.is_some() {
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
    if let Some(value) = filter.tunnel_luid {
        *luid = value;
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                // Union write selecting the `uint64` member; the pointer
                // target (`luid`) outlives the engine call.
                Anonymous: {
                    let mut value_out = FWP_CONDITION_VALUE0::default();
                    value_out.Anonymous.uint64 = std::ptr::from_mut(luid);
                    value_out.Anonymous
                },
            },
        });
    }
    conditions
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

    /// windows-sys `GUID` has no `PartialEq`; compare field-wise.
    fn guid_eq(a: &GUID, b: &GUID) -> bool {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    }

    #[test]
    fn keys_are_distinct() {
        let keys = FILTER_KEYS;
        for (index, key) in keys.iter().enumerate() {
            assert!(!guid_eq(key, &SUBLAYER_KEY));
            for other in &keys[index + 1..] {
                assert!(!guid_eq(key, other));
            }
        }
    }

    #[test]
    fn filters_cover_both_families_and_arbitration() {
        let filters = build_filters(0x1234);
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
            assert_eq!(block.tunnel_luid, None);
            assert_eq!(block.loopback, None);
            for permit in family.iter().filter(|f| f.action == FWP_ACTION_PERMIT) {
                assert!(permit.weight > block.weight);
                assert!(permit.loopback.is_some() ^ permit.tunnel_luid.is_some());
            }
            // The interface permit pins exactly the requested LUID.
            let iface = family
                .iter()
                .find(|f| f.tunnel_luid == Some(0x1234))
                .unwrap();
            assert!(iface.loopback.is_none());
        }
    }

    #[test]
    fn condition_values_are_well_formed() {
        let mut luid = 0u64;
        // Loopback condition: flags + IS_LOOPBACK, FWP_UINT32.
        let loopback = build_conditions(
            &FilterSpec {
                key: LOOPBACK_PERMIT_V4_KEY,
                layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                name: "x",
                action: FWP_ACTION_PERMIT,
                weight: PERMIT_WEIGHT,
                tunnel_luid: None,
                loopback: Some(()),
            },
            &mut luid,
        );
        assert_eq!(loopback.len(), 1);
        assert_eq!(loopback[0].matchType, FWP_MATCH_FLAGS_ANY_SET);
        // SAFETY: the condition was built with `FWP_UINT32`; reading the
        // active member is sound in this test-only check.
        let value = unsafe { loopback[0].conditionValue.Anonymous.uint32 };
        assert_eq!(value, FWP_CONDITION_FLAG_IS_LOOPBACK);

        // Interface condition: equality + the LUID pointer, FWP_UINT64.
        let iface = build_conditions(
            &FilterSpec {
                key: INTERFACE_PERMIT_V4_KEY,
                layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                name: "x",
                action: FWP_ACTION_PERMIT,
                weight: PERMIT_WEIGHT,
                tunnel_luid: Some(0xdead_beef),
                loopback: None,
            },
            &mut luid,
        );
        assert_eq!(iface.len(), 1);
        assert_eq!(iface[0].matchType, FWP_MATCH_EQUAL);
        // SAFETY: built with `FWP_UINT64`; the pointer target is `luid`.
        let pointer = unsafe { iface[0].conditionValue.Anonymous.uint64 };
        assert_eq!(unsafe { *pointer }, 0xdead_beef);
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
