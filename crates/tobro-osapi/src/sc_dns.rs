//! macOS system DNS via the SystemConfiguration dynamic store.
//!
//! The helper writes the global resolver key `State:/Network/Global/DNS`
//! (dictionary `{ ServerAddresses: [ip...] }`) for the tunnel lifetime and
//! restores the previous value on teardown. The backup is serialized as an
//! XML property list (`Vec<u8>`, `Send`) because CF objects may not cross
//! threads; restoration parses it back inside the same (blocking) thread
//! context.
//!
//! Every operation opens its own `SCDynamicStore` session and must be
//! called from a blocking thread: `SCDynamicStore` is not `Send`.
//!
//! # Unsafe scope
//!
//! The single `unsafe` block wraps the raw pointer returned by
//! `CFPropertyListCreateWithData` back into the owning `CFPropertyList`
//! type. The pointer comes from CoreFoundation's own parser over bytes we
//! wrote; no other unsafe exists here.
//!
//! Note: unlike a full resolver monitor, values set by other apps while the
//! tunnel is up are not re-asserted (planned M8 hardening).

use std::net::IpAddr;

use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::base::ToVoid;
use system_configuration::core_foundation::data::CFData;
use system_configuration::core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use system_configuration::core_foundation::propertylist::{
    CFPropertyList, create_data, create_with_data, kCFPropertyListImmutable,
    kCFPropertyListXMLFormat_v1_0,
};
use system_configuration::core_foundation::string::CFString;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};

/// The dynamic-store key holding the global DNS resolver configuration.
const GLOBAL_DNS_KEY: &str = "State:/Network/Global/DNS";
/// Property name inside the DNS dictionary.
const SERVER_ADDRESSES_KEY: &str = "ServerAddresses";

fn open_store() -> Result<SCDynamicStore, String> {
    SCDynamicStoreBuilder::new("tobro-helper")
        .build()
        .ok_or_else(|| "could not open the SystemConfiguration dynamic store".to_owned())
}

/// The untyped `{ ServerAddresses: [ip...] }` dictionary.
fn dns_dictionary(servers: &[IpAddr]) -> CFDictionary {
    let server_strings: Vec<CFString> = servers
        .iter()
        .map(|ip| CFString::new(&ip.to_string()))
        .collect();
    let addresses = CFArray::from_CFTypes(&server_strings).into_untyped();
    let key = CFString::new(SERVER_ADDRESSES_KEY);
    let mut dictionary = CFMutableDictionary::new();
    dictionary.add(&key.to_void(), &addresses.to_void());
    dictionary.to_immutable()
}

/// Apply the resolver configuration: back up the current global DNS value
/// and overwrite the key with the given servers. The backup is
/// `Some(Option<Vec<u8>>)` when one was taken (`take_backup`): the inner
/// `None` means the key did not exist before, `Some(Some(xml))` carries the
/// previous value serialized as XML bytes. Without a backup (already taken
/// earlier in this tunnel lifetime) the result is `None`. Blocking; call
/// via `spawn_blocking`.
pub fn apply_dns(
    servers: Vec<IpAddr>,
    take_backup: bool,
) -> Result<Option<Option<Vec<u8>>>, String> {
    let store = open_store()?;
    let backup = if take_backup {
        Some(backup_current(&store)?)
    } else {
        None
    };
    if store.set(GLOBAL_DNS_KEY, dns_dictionary(&servers)) {
        Ok(backup)
    } else {
        Err("could not set the system resolver".to_owned())
    }
}

/// Serialize the current global DNS value to XML bytes (`None` if absent).
fn backup_current(store: &SCDynamicStore) -> Result<Option<Vec<u8>>, String> {
    let Some(current) = store.get(GLOBAL_DNS_KEY) else {
        return Ok(None);
    };
    let xml = create_data(current.as_CFTypeRef(), kCFPropertyListXMLFormat_v1_0)
        .map_err(|error| format!("could not serialize the DNS backup: {error}"))?;
    Ok(Some(xml.bytes().to_vec()))
}

/// Restore a backup previously returned by [`apply_dns`]: `None` = nothing
/// was applied (no-op); `Some(None)` = the key did not exist before, remove
/// it; `Some(Some(xml))` = write the previous value back. Blocking; call
/// via `spawn_blocking`.
pub fn restore_dns(backup: Option<Option<Vec<u8>>>) -> Result<(), String> {
    let store = open_store()?;
    match backup {
        None => Ok(()),
        Some(None) => {
            if store.remove(GLOBAL_DNS_KEY) {
                Ok(())
            } else {
                Err("could not remove the generated DNS settings".to_owned())
            }
        }
        Some(Some(xml)) => {
            let (plist, _) = create_with_data(CFData::from_buffer(&xml), kCFPropertyListImmutable)
                .map_err(|error| format!("could not deserialize the DNS backup: {error}"))?;
            // SAFETY: `plist` is a valid, owned CF object reference returned
            // by CoreFoundation's property list parser; wrapping it into the
            // owning type takes over that reference exactly once.
            let plist = unsafe { CFPropertyList::wrap_under_create_rule(plist) };
            if store.set_raw(GLOBAL_DNS_KEY, &plist) {
                Ok(())
            } else {
                Err("could not restore the previous DNS settings".to_owned())
            }
        }
    }
}
