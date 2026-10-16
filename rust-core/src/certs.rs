//! Lists and revokes iOS development certificates via `isideload`'s
//! `DeveloperSession` (developer portal only, no device). `si_cert_signin` opens
//! a session on the first team, `si_cert_list` returns its certificates as JSON,
//! and `si_cert_revoke` revokes one by serial number.

use std::ffi::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use isideload::sideload::cert_identity::CertificateIdentity;
use isideload::util::fs_storage::FsStorage;

use isideload::dev::{
    certificates::{CertificatesApi, DevelopmentCertificate},
    developer_session::DeveloperSession,
    device_type::DeveloperDeviceType,
    teams::DeveloperTeam,
};
use serde::Serialize;

use crate::account::{make_2fa, TwoFactorCb, TwoFaCtx};
use crate::apple_session;
use crate::error_text::report_text;
use crate::ffi_util::{cstr, opt_str};

/// Opaque handle owning the runtime, developer session and selected team.
pub struct CertSession {
    // `pub(crate)` so `entitlements` can reuse this session and team instead of
    // signing in (and prompting for 2FA) again.
    pub(crate) rt: tokio::runtime::Runtime,
    pub(crate) dev: DeveloperSession,
    pub(crate) team: DeveloperTeam,
    apple_email: String,
    storage_dir: PathBuf,
    certificates: Vec<DevelopmentCertificate>,
}

// Used only through its own runtime, serialized by Swift on one queue.
unsafe impl Send for CertSession {}

/// A certificate flattened to plain strings, so Swift decodes no optionals.
#[derive(Serialize)]
struct CertInfo {
    name: String,
    serial_number: String,
    machine_name: String,
    machine_id: String,
    certificate_id: String,
    platform: String,
    status: String,
    /// RFC3339 expiry (e.g. `2027-01-01T00:00:00Z`), or "" if Apple omitted it.
    expiration: String,
    has_private_key: bool,
}

impl From<&DevelopmentCertificate> for CertInfo {
    fn from(c: &DevelopmentCertificate) -> Self {
        let s = |o: &Option<String>| o.clone().unwrap_or_default();
        CertInfo {
            has_private_key: false,
            name: s(&c.name),
            serial_number: s(&c.serial_number),
            machine_name: s(&c.machine_name),
            machine_id: s(&c.machine_id),
            certificate_id: s(&c.certificate_id),
            platform: s(&c.certificate_platform),
            status: s(&c.status),
            // plist::Date's XML form is RFC3339 (e.g. 2027-01-01T00:00:00Z).
            expiration: c
                .expiration_date
                .as_ref()
                .map(|d| d.to_xml_format())
                .unwrap_or_default(),
        }
    }
}

/// Log in, open a developer session, and select the first team. Returns 0 on
/// success; free the session with `si_cert_session_free`.
///
/// # Safety
/// All `*const c_char` args must be null or valid C strings; the out pointers
/// must be valid and writable.
#[allow(clippy::too_many_arguments)]
pub unsafe fn cert_signin(
    apple_id: *const c_char,
    password: *const c_char,
    anisette_url: *const c_char,
    // Unused; matches `si_apple_signin`'s signature.
    _machine_name: *const c_char,
    storage_dir: *const c_char,
    twofa_cb: TwoFactorCb,
    ctx: *mut c_void,
    out_session: *mut *mut CertSession,
    out_summary: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    let apple_id = opt_str(apple_id, "");
    let password = opt_str(password, "");
    let anisette_url = opt_str(anisette_url, "https://ani.sidestore.io");
    let storage_dir = opt_str(storage_dir, ".");
    let twofa = make_2fa(twofa_cb, TwoFaCtx(ctx));

    let result = catch_unwind(AssertUnwindSafe(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to start runtime: {e}"))?;

        let (dev, team, summary) = rt.block_on(async {
            // Always the active account, so the session is saved and reused.
            let (dev, teams) = apple_session::open(
                &apple_id,
                &password,
                &anisette_url,
                Path::new(&storage_dir),
                true,
                twofa,
                "Certs",
            )
            .await?;
            let team = teams
                .into_iter()
                .next()
                .ok_or_else(|| "no development teams on this Apple ID".to_string())?;
            tracing::info!("Certs: using team {}", team.team_id);

            let summary = format!(
                "team: {} ({})",
                team.name.as_deref().unwrap_or("<unnamed>"),
                team.team_id
            );
            Ok::<_, String>((dev, team, summary))
        })?;

        Ok::<_, String>((rt, dev, team, summary))
    }));

    match result {
        Ok(Ok((rt, dev, team, summary))) => {
            let session = Box::new(CertSession { rt, dev, team, apple_email: apple_id, storage_dir: PathBuf::from(storage_dir), certificates: Vec::new() });
            *out_session = Box::into_raw(session);
            *out_summary = cstr(summary);
            0
        }
        Ok(Err(e)) => {
            *out_error = cstr(e);
            1
        }
        Err(_) => {
            *out_error = cstr("panic during certificate sign-in");
            2
        }
    }
}

/// List the team's certificates as a JSON array of `CertInfo`.
///
/// # Safety
/// `session` must be a valid pointer from `cert_signin`; out pointers valid.
pub unsafe fn cert_list(
    session: *mut CertSession,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        *out_error = cstr("null session");
        return 2;
    }
    let session = &mut *session;

    let result = catch_unwind(AssertUnwindSafe(|| {
        session.rt.block_on(async {
            let certs = session
                .dev
                .list_ios_certs(&session.team)
                .await
                .map_err(|e| format!("list certs failed: {}", report_text(&e)))?;
            tracing::info!("Certs: {} iOS development certificate(s)", certs.len());
            let storage = FsStorage::new(session.storage_dir.clone());
            let mut infos = Vec::new();
            for cert in &certs {
                let mut info = CertInfo::from(cert);
                if let Some(content) = &cert.cert_content {
                    info.has_private_key = CertificateIdentity::has_local_key(&session.apple_email, content.as_ref(), &storage)
                        .map_err(|_| "Could not read the local signing Keychain".to_string())?;
                }
                infos.push(info);
            }
            session.certificates = certs;
            serde_json::to_string(&infos).map_err(|e| format!("serialize certs: {e}"))
        })
    }));

    match result {
        Ok(Ok(json)) => {
            *out_json = cstr(json);
            0
        }
        Ok(Err(e)) => {
            *out_error = cstr(e);
            1
        }
        Err(_) => {
            *out_error = cstr("panic while listing certificates");
            2
        }
    }
}

/// Revoke the certificate with `serial_number`.
///
/// # Safety
/// `session` must be a valid pointer from `cert_signin`; `serial_number` a
/// valid C string; `out_error` valid and writable.
pub unsafe fn cert_revoke(
    session: *mut CertSession,
    serial_number: *const c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        *out_error = cstr("null session");
        return 2;
    }
    let session = &mut *session;
    let serial = opt_str(serial_number, "");
    if serial.is_empty() {
        *out_error = cstr("empty serial number");
        return 2;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        session.rt.block_on(async {
            tracing::info!("Certs: revoking certificate {serial}");
            session
                .dev
                .revoke_development_cert(&session.team, &serial, DeveloperDeviceType::Ios)
                .await
                .map_err(|e| format!("revoke failed: {}", report_text(&e)))?;
            Ok::<_, String>(())
        })
    }));

    match result {
        Ok(Ok(())) => {
            tracing::info!("Certs: revoked {serial}");
            0
        }
        Ok(Err(e)) => {
            *out_error = cstr(e);
            1
        }
        Err(_) => {
            *out_error = cstr("panic while revoking certificate");
            2
        }
    }
}

/// Free a `CertSession`.
///
/// # Safety
/// `session` must be null or a pointer from `cert_signin`.
pub unsafe fn cert_session_free(session: *mut CertSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}

/// Import a validated PKCS#12 key into the existing account storage. This
/// endpoint only reads Apple certificates and cannot request or revoke one.
pub unsafe fn cert_import_key(
    session: *mut CertSession,
    cert: *const u8, cert_len: usize,
    key: *const u8, key_len: usize,
    out_error: *mut *mut c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if session.is_null() || cert.is_null() || key.is_null() || cert_len == 0 || key_len == 0 || cert_len > 65536 || key_len > 16384 {
            return Err("Invalid imported signing identity".to_string());
        }
        let session = &mut *session;
        let storage = FsStorage::new(session.storage_dir.clone());
        session.rt.block_on(CertificateIdentity::import_existing_key(
            &session.apple_email, std::slice::from_raw_parts(cert, cert_len),
            std::slice::from_raw_parts(key, key_len), &mut session.dev, &session.team, &storage,
        )).map_err(|e| report_text(&e))
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => { *out_error = cstr(error); 1 }
        Err(_) => { *out_error = cstr("Could not import signing identity"); 2 }
    }
}

pub unsafe fn cert_remove_local_key(session: *mut CertSession, serial: *const c_char, out_error: *mut *mut c_char) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if session.is_null() { return Err("No certificate session".to_string()); }
        let serial = opt_str(serial, "");
        let session = &mut *session;
        // Use the public certificate from the last list; local deletion works
        // offline and has no DeveloperSession/network operation.
        let cert = session.certificates.iter().find(|c| c.serial_number.as_deref() == Some(serial.as_str()))
            .ok_or_else(|| "Load the certificate list first".to_string())?;
        let content = cert.cert_content.as_ref().ok_or_else(|| "Certificate content unavailable".to_string())?;
        CertificateIdentity::remove_local_key(&session.apple_email, content.as_ref(), &FsStorage::new(session.storage_dir.clone()))
            .map_err(|_| "Could not remove the local signing key".to_string())
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => { *out_error = cstr(error); 1 }
        Err(_) => { *out_error = cstr("Could not remove local signing key"); 2 }
    }
}
