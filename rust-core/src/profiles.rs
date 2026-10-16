//! Local profile FFI. No developer session or network operation is reachable.
use crate::{
    error_text::report_text,
    ffi_util::{cstr, opt_str},
};
use isideload::{
    sideload::{cert_identity::CertificateIdentity, imported_profiles},
    util::fs_storage::FsStorage,
};
use std::{
    ffi::c_char,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
};

pub unsafe fn profiles(
    storage_dir: *const c_char,
    apple_email: *const c_char,
    udid: *const c_char,
    action: *const c_char,
    uuid: *const c_char,
    data: *const u8,
    data_len: usize,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = opt_str(storage_dir, "");
        if dir.is_empty() {
            return Err("Profile storage is unavailable.".to_string());
        }
        let storage = FsStorage::new(PathBuf::from(dir));
        match opt_str(action, "list").as_str() {
            "import" => {
                if data.is_null() || data_len == 0 || data_len > 4 * 1024 * 1024 {
                    return Err("Invalid provisioning profile file.".to_string());
                }
                imported_profiles::save(&storage, std::slice::from_raw_parts(data, data_len))
                    .map_err(|e| report_text(&e))?;
            }
            "remove" => imported_profiles::remove(&storage, &opt_str(uuid, ""))
                .map_err(|e| report_text(&e))?,
            "list" => (),
            _ => return Err("Unknown profile operation.".to_string()),
        }
        let email = opt_str(apple_email, "");
        let udid = opt_str(udid, "");
        let cert = CertificateIdentity::local_certificate(&email, &storage).map_err(|_| {
            "Could not read the signing Keychain. Unlock this device and try again.".to_string()
        })?;
        let items = imported_profiles::load(&storage).map_err(|e| report_text(&e))?;
        // The team's exact comparison is repeated by the signer. Offline UI
        // derives readiness from DER membership of the active account's key.
        let summaries: Vec<_> = items
            .iter()
            .map(|p| p.summary(None, Some(&udid), cert.as_deref()))
            .collect();
        serde_json::to_string(&summaries)
            .map_err(|_| "Could not read provisioning profiles.".to_string())
    }));
    match result {
        Ok(Ok(json)) => {
            *out_json = cstr(json);
            0
        }
        Ok(Err(error)) => {
            *out_error = cstr(error);
            1
        }
        Err(_) => {
            *out_error = cstr("Could not process provisioning profile.");
            2
        }
    }
}
