//! Optional, local-only provisioning profiles. This module has no portal API.
use crate::util::storage::SideloadingStorage;
use apple_codesign_quick::ProvisioningProfile;
use plist::{Dictionary, Value};
use rootcause::prelude::*;
use serde::Serialize;
use std::{collections::BTreeMap, sync::Mutex, time::SystemTime};
use x509_cert::{Certificate, der::Decode};

static STORE_LOCK: Mutex<()> = Mutex::new(());
const INDEX: &str = "imported-profiles/index.json";

#[derive(Clone)]
pub struct ImportedProfile {
    pub encoded: Vec<u8>,
    pub name: String,
    pub uuid: String,
    pub team_id: String,
    pub application_identifier: String,
    pub bundle_id: String,
    pub creation: plist::Date,
    pub expiration: plist::Date,
    pub devices: Option<Vec<String>>,
    pub certificates: Vec<Vec<u8>>,
    pub entitlements: Dictionary,
    pub all_devices: bool,
}

#[derive(Serialize)]
pub struct ProfileSummary {
    name: String,
    uuid: String,
    team_id: String,
    bundle_id: String,
    application_identifier: String,
    creation: String,
    expiration: String,
    device_valid: bool,
    certificate_match: bool,
    ready: bool,
    issues: Vec<String>,
}

impl ImportedProfile {
    pub fn parse(data: &[u8]) -> Result<Self, Report> {
        if data.is_empty() || data.len() > 4 * 1024 * 1024 {
            bail!("Invalid provisioning profile file size.");
        }
        super::profile_cms::verify(data).context("Invalid or corrupt provisioning profile.")?;
        let parsed =
            ProvisioningProfile::parse(data).context("Invalid provisioning profile plist.")?;
        Self::from_plist(data, parsed.plist())
    }

    pub(super) fn from_plist(data: &[u8], plist: &Dictionary) -> Result<Self, Report> {
        let text = |key: &str| -> Result<String, Report> {
            plist
                .get(key)
                .and_then(Value::as_string)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| report!("Provisioning profile is missing {key}."))
        };
        let name = text("Name")?;
        let uuid = uuid::Uuid::parse_str(&text("UUID")?)
            .context("Invalid profile UUID.")?
            .to_string();
        let teams = plist
            .get("TeamIdentifier")
            .and_then(Value::as_array)
            .ok_or_else(|| report!("Missing TeamIdentifier."))?;
        if teams.len() != 1 {
            bail!("Provisioning profile must identify exactly one team.");
        }
        let team_id = teams[0]
            .as_string()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| report!("Invalid TeamIdentifier."))?
            .to_owned();
        let entitlements = plist
            .get("Entitlements")
            .and_then(Value::as_dictionary)
            .ok_or_else(|| report!("Missing Entitlements."))?
            .clone();
        let application_identifier = entitlements
            .get("application-identifier")
            .and_then(Value::as_string)
            .ok_or_else(|| report!("Missing application-identifier."))?
            .to_owned();
        let bundle_id = application_identifier
            .strip_prefix(&format!("{team_id}."))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| report!("Profile application-identifier does not match its Team ID."))?
            .to_owned();
        if bundle_id.contains('*')
            && !(bundle_id == "*"
                || (bundle_id.ends_with(".*") && bundle_id.matches('*').count() == 1))
        {
            bail!("Invalid profile Bundle ID wildcard.");
        }
        if entitlements
            .get("com.apple.developer.team-identifier")
            .and_then(Value::as_string)
            != Some(team_id.as_str())
        {
            bail!("Profile team entitlement does not match TeamIdentifier.");
        }
        let date = |key: &str| {
            plist
                .get(key)
                .and_then(Value::as_date)
                .ok_or_else(|| report!("Missing or invalid {key}."))
        };
        let creation = date("CreationDate")?;
        let expiration = date("ExpirationDate")?;
        if SystemTime::from(expiration) <= SystemTime::from(creation) {
            bail!("Invalid provisioning profile date range.");
        }
        let devices = match plist.get("ProvisionedDevices") {
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|v| {
                        v.as_string()
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .ok_or_else(|| report!("Invalid ProvisionedDevices entry."))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Some(_) => bail!("Invalid ProvisionedDevices."),
            None => None,
        };
        let certificates = plist
            .get("DeveloperCertificates")
            .and_then(Value::as_array)
            .ok_or_else(|| report!("Missing DeveloperCertificates."))?
            .iter()
            .map(|v| {
                let der = v
                    .as_data()
                    .ok_or_else(|| report!("Invalid DeveloperCertificates entry."))?;
                Certificate::from_der(der).context("Invalid developer certificate DER.")?;
                Ok(der.to_vec())
            })
            .collect::<Result<Vec<_>, Report>>()?;
        if certificates.is_empty() {
            bail!("Provisioning profile contains no developer certificates.");
        }
        Ok(Self {
            encoded: data.to_vec(),
            name,
            uuid,
            team_id,
            application_identifier,
            bundle_id,
            creation,
            expiration,
            devices,
            certificates,
            entitlements,
            all_devices: plist
                .get("ProvisionsAllDevices")
                .and_then(Value::as_boolean)
                .unwrap_or(false),
        })
    }

    pub fn matches_bundle(&self, bundle_id: &str) -> bool {
        allowed_string(&self.bundle_id, bundle_id)
    }
    pub fn device_valid(&self, udid: Option<&str>) -> bool {
        match &self.devices {
            Some(devices) => udid.is_some_and(|id| {
                !id.is_empty() && devices.iter().any(|d| d.eq_ignore_ascii_case(id))
            }),
            None => self.all_devices, // App Store profiles cannot install locally.
        }
    }
    pub fn certificate_match(&self, cert: Option<&[u8]>) -> bool {
        cert.is_some_and(|der| self.certificates.iter().any(|candidate| candidate == der))
    }
    pub fn issues(
        &self,
        team: Option<&str>,
        udid: Option<&str>,
        cert: Option<&[u8]>,
        now: SystemTime,
    ) -> Vec<String> {
        let mut issues = Vec::new();
        if team.is_some_and(|t| t != self.team_id) {
            issues.push("Provisioning profile belongs to a different Team ID.".into());
        }
        if now >= SystemTime::from(self.expiration) {
            issues.push("Provisioning profile has expired.".into());
        }
        if now < SystemTime::from(self.creation) {
            issues.push("Provisioning profile is not yet valid.".into());
        }
        if !self.device_valid(udid) {
            issues.push(
                if udid.is_none_or(str::is_empty) {
                    "Connect or pair this device to validate its UDID."
                } else {
                    "This provisioning profile does not include this device."
                }
                .into(),
            );
        }
        if !self.certificate_match(cert) {
            issues.push(
                "Provisioning profile does not include the imported signing certificate.".into(),
            );
        }
        if let Some(cert) = cert.and_then(|der| Certificate::from_der(der).ok()) {
            let validity = &cert.tbs_certificate.validity;
            let now = now
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            if now < validity.not_before.to_unix_duration()
                || now >= validity.not_after.to_unix_duration()
            {
                issues.push("The imported signing certificate is expired or not yet valid.".into());
            }
            if !cert
                .tbs_certificate
                .subject
                .0
                .iter()
                .flat_map(|r| r.0.iter())
                .any(|a| {
                    a.oid.to_string() == "2.5.4.11" && a.value.value() == self.team_id.as_bytes()
                })
            {
                issues.push("Provisioning profile belongs to a different Team ID.".into());
            }
        }
        issues
    }
    pub fn validate(
        &self,
        bundle: &str,
        team: &str,
        udid: Option<&str>,
        cert: &[u8],
    ) -> Result<(), Report> {
        if !self.matches_bundle(bundle) {
            bail!("Provisioning profile Bundle ID mismatch for {bundle}.");
        }
        let issues = self.issues(Some(team), udid, Some(cert), SystemTime::now());
        if !issues.is_empty() {
            bail!("{}: {}", bundle, issues.join(" "));
        }
        Ok(())
    }
    pub fn summary(
        &self,
        team: Option<&str>,
        udid: Option<&str>,
        cert: Option<&[u8]>,
    ) -> ProfileSummary {
        let issues = self.issues(team, udid, cert, SystemTime::now());
        ProfileSummary {
            name: self.name.clone(),
            uuid: self.uuid.clone(),
            team_id: self.team_id.clone(),
            bundle_id: self.bundle_id.clone(),
            application_identifier: self.application_identifier.clone(),
            creation: self.creation.to_xml_format(),
            expiration: self.expiration.to_xml_format(),
            device_valid: self.device_valid(udid),
            certificate_match: self.certificate_match(cert),
            ready: issues.is_empty(),
            issues,
        }
    }
}

/// Exact IDs win over wildcard profiles; among usable candidates prefer the
/// latest expiration. An invalid imported match fails closed, never falls back
/// to silently creating an App ID/profile for that same target.
pub fn select<'a>(
    profiles: &'a [ImportedProfile],
    bundle: &str,
    team: &str,
    udid: Option<&str>,
    cert: &[u8],
) -> Result<Option<&'a ImportedProfile>, Report> {
    let mut candidates: Vec<_> = profiles
        .iter()
        .filter(|p| p.matches_bundle(bundle))
        .collect();
    candidates.sort_by_key(|p| {
        (
            p.bundle_id != bundle,
            std::cmp::Reverse(SystemTime::from(p.expiration)),
            p.uuid.clone(),
        )
    });
    if candidates.is_empty() {
        return Ok(None);
    }
    // Exact matches are authoritative; wildcard is considered only if no exact
    // profile exists. Multiple renewals of the same profile are supported.
    let exact = candidates.iter().any(|p| p.bundle_id == bundle);
    candidates.retain(|p| !exact || p.bundle_id == bundle);
    for p in &candidates {
        if p.validate(bundle, team, udid, cert).is_ok() {
            return Ok(Some(p));
        }
    }
    candidates[0].validate(bundle, team, udid, cert)?;
    unreachable!()
}

pub fn allowed_string(pattern: &str, value: &str) -> bool {
    pattern == value
        || pattern
            .strip_suffix('*')
            .is_some_and(|prefix| !prefix.contains('*') && value.starts_with(prefix))
}

pub fn main_bundle_id(profiles: &[ImportedProfile], original: &str, team: &str) -> String {
    if profiles.iter().any(|p| p.matches_bundle(original)) {
        original.to_owned()
    } else if original.ends_with(&format!(".{team}")) {
        original.to_owned()
    } else {
        format!("{original}.{team}")
    }
}

pub fn plan<'a>(
    profiles: &'a [ImportedProfile],
    targets: &[String],
    team: &str,
    udid: Option<&str>,
    cert: &[u8],
) -> Result<(BTreeMap<String, &'a ImportedProfile>, Vec<String>), Report> {
    let mut imported = BTreeMap::new();
    let mut fallback = Vec::new();
    for id in targets {
        match select(profiles, id, team, udid, cert)? {
            Some(profile) => {
                imported.insert(id.clone(), profile);
            }
            None => fallback.push(id.clone()),
        }
    }
    Ok((imported, fallback))
}

fn path(uuid: &str) -> Result<String, Report> {
    Ok(format!(
        "imported-profiles/{}.mobileprovision",
        uuid::Uuid::parse_str(uuid)?
    ))
}
fn index(storage: &dyn SideloadingStorage) -> Result<BTreeMap<String, String>, Report> {
    Ok(match storage.retrieve(INDEX)? {
        Some(text) => {
            serde_json::from_str(&text).context("Could not read imported profile index.")?
        }
        None => BTreeMap::new(),
    })
}
pub fn load(storage: &dyn SideloadingStorage) -> Result<Vec<ImportedProfile>, Report> {
    let _lock = STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    index(storage)?
        .keys()
        .map(|uuid| {
            let data = storage.retrieve_data(&path(uuid)?)?.ok_or_else(|| {
                report!("Imported profile file is missing. Remove and import it again.")
            })?;
            ImportedProfile::parse(&data)
        })
        .collect()
}
pub fn save(storage: &dyn SideloadingStorage, data: &[u8]) -> Result<ImportedProfile, Report> {
    let profile = ImportedProfile::parse(data)?;
    save_validated(storage, &profile)?;
    Ok(profile)
}
fn save_validated(
    storage: &dyn SideloadingStorage,
    profile: &ImportedProfile,
) -> Result<(), Report> {
    let _lock = STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut entries = index(storage)?;
    storage.store_data(&path(&profile.uuid)?, &profile.encoded)?;
    entries.insert(profile.uuid.clone(), profile.bundle_id.clone());
    storage.store(INDEX, &serde_json::to_string(&entries)?)?;
    Ok(())
}
pub fn remove(storage: &dyn SideloadingStorage, uuid: &str) -> Result<(), Report> {
    let _lock = STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut entries = index(storage)?;
    let file = path(uuid)?;
    entries.remove(&uuid::Uuid::parse_str(uuid)?.to_string());
    storage.store(INDEX, &serde_json::to_string(&entries)?)?;
    storage.delete(&file)?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::util::storage::InMemoryStorage;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use std::time::Duration;

    pub fn fixture_plist(cert: &[u8], bundle: &str) -> Dictionary {
        let mut ent = Dictionary::new();
        ent.insert(
            "application-identifier".into(),
            format!("TESTTEAM01.{bundle}").into(),
        );
        ent.insert(
            "com.apple.developer.team-identifier".into(),
            "TESTTEAM01".into(),
        );
        ent.insert(
            "keychain-access-groups".into(),
            Value::Array(vec!["TESTTEAM01.*".into()]),
        );
        ent.insert("get-task-allow".into(), true.into());
        let now = SystemTime::now();
        let mut dict = Dictionary::new();
        dict.insert("Name".into(), format!("Synthetic {bundle}").into());
        dict.insert("UUID".into(), uuid::Uuid::new_v4().to_string().into());
        dict.insert(
            "TeamIdentifier".into(),
            Value::Array(vec!["TESTTEAM01".into()]),
        );
        dict.insert(
            "CreationDate".into(),
            Value::Date((now - Duration::from_secs(60)).into()),
        );
        dict.insert(
            "ExpirationDate".into(),
            Value::Date((now + Duration::from_secs(3600)).into()),
        );
        dict.insert(
            "ProvisionedDevices".into(),
            Value::Array(vec!["TEST-UDID".into()]),
        );
        dict.insert(
            "DeveloperCertificates".into(),
            Value::Array(vec![Value::Data(cert.to_vec())]),
        );
        dict.insert("Entitlements".into(), ent.into());
        dict
    }
    fn fixture(bundle: &str) -> (ImportedProfile, Vec<u8>) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Synthetic profile test");
        name.push(DnType::OrganizationalUnitName, "TESTTEAM01");
        params.distinguished_name = name;
        let cert = params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .to_vec();
        let dict = fixture_plist(&cert, bundle);
        (
            ImportedProfile::from_plist(b"synthetic test data", &dict).unwrap(),
            cert,
        )
    }
    fn select_one(profile: &ImportedProfile, cert: &[u8]) -> Result<(), Report> {
        profile.validate("com.example.app", "TESTTEAM01", Some("TEST-UDID"), cert)
    }
    #[test]
    fn valid_profile_extracts_all_required_fields() {
        let (p, c) = fixture("com.example.app");
        select_one(&p, &c).unwrap();
        assert_eq!(p.application_identifier, "TESTTEAM01.com.example.app");
        assert_eq!(p.bundle_id, "com.example.app");
        assert!(!p.name.is_empty());
        assert!(!p.uuid.is_empty());
        assert_eq!(p.certificates, vec![c]);
        assert!(!p.entitlements.is_empty());
    }
    #[test]
    fn expired_profile_is_rejected() {
        let (mut p, c) = fixture("com.example.app");
        p.expiration = (SystemTime::now() - Duration::from_secs(1)).into();
        assert!(
            select_one(&p, &c)
                .unwrap_err()
                .to_string()
                .contains("Provisioning profile has expired.")
        );
    }
    #[test]
    fn wrong_team_is_rejected() {
        let (p, c) = fixture("com.example.app");
        assert!(
            p.validate(&p.bundle_id, "OTHERTEAM", Some("TEST-UDID"), &c)
                .is_err()
        );
    }
    #[test]
    fn missing_device_is_rejected_and_unknown_udid_is_not_ready() {
        let (p, c) = fixture("com.example.app");
        assert!(
            p.validate(&p.bundle_id, "TESTTEAM01", Some("OTHER-UDID"), &c)
                .unwrap_err()
                .to_string()
                .contains("This provisioning profile does not include this device.")
        );
        assert!(!p.summary(None, None, Some(&c)).ready);
    }
    #[test]
    fn certificate_matching_uses_der_not_subject_name() {
        let (p, _) = fixture("com.example.app");
        let (_, other) = fixture("com.example.app");
        assert!(
            select_one(&p, &other).unwrap_err().to_string().contains(
                "Provisioning profile does not include the imported signing certificate."
            )
        );
    }
    #[test]
    fn main_and_extensions_match_independent_profiles() {
        let (main, cert) = fixture("com.example.app");
        let extension = ImportedProfile::from_plist(
            b"synthetic",
            &fixture_plist(&cert, "com.example.app.widget"),
        )
        .unwrap();
        let targets = vec![main.bundle_id.clone(), extension.bundle_id.clone()];
        let profiles = vec![main, extension];
        let (selected, fallback) =
            plan(&profiles, &targets, "TESTTEAM01", Some("TEST-UDID"), &cert).unwrap();
        assert!(fallback.is_empty());
        assert_eq!(selected.len(), 2);
        assert_ne!(selected[&targets[0]].uuid, selected[&targets[1]].uuid);
        assert!(
            select(
                &profiles,
                "com.example.apple",
                "TESTTEAM01",
                Some("TEST-UDID"),
                &cert
            )
            .unwrap()
            .is_none()
        );
    }
    #[test]
    fn multiple_profiles_prefer_valid_exact_renewal() {
        let (valid, cert) = fixture("com.example.app");
        let mut expired = valid.clone();
        expired.uuid = uuid::Uuid::new_v4().to_string();
        expired.expiration = (SystemTime::now() - Duration::from_secs(1)).into();
        let profiles = vec![expired, valid.clone()];
        assert_eq!(
            select(
                &profiles,
                &valid.bundle_id,
                "TESTTEAM01",
                Some("TEST-UDID"),
                &cert
            )
            .unwrap()
            .unwrap()
            .uuid,
            valid.uuid
        );
    }
    #[test]
    fn imported_target_is_excluded_from_profile_generation_and_missing_extension_falls_back() {
        let (main, cert) = fixture("com.example.app");
        let targets = vec![main.bundle_id.clone(), "com.example.app.widget".into()];
        let (selected, fallback) = plan(&[main], &targets, "TESTTEAM01", Some("TEST-UDID"), &cert)
            .map(|(p, f)| (p.len(), f))
            .unwrap();
        assert_eq!(selected, 1);
        assert_eq!(fallback, vec!["com.example.app.widget"]);
        let (selected, fallback) =
            plan(&[], &targets, "TESTTEAM01", Some("TEST-UDID"), &cert).unwrap();
        assert!(selected.is_empty());
        assert_eq!(fallback, targets);
    }
    #[test]
    fn invalid_imported_match_blocks_plan_instead_of_generating_profile() {
        let (mut main, cert) = fixture("com.example.app");
        main.devices = Some(vec![]);
        assert!(
            plan(
                &[main],
                &["com.example.app".into()],
                "TESTTEAM01",
                Some("TEST-UDID"),
                &cert
            )
            .is_err()
        );
    }
    #[test]
    fn profiles_persist_by_uuid_and_removal_is_local_and_idempotent() {
        let (first, _) = fixture("com.example.app");
        let (second, _) = fixture("com.example.app.widget");
        let storage = InMemoryStorage::new();
        storage.store("unrelated-key", "keep").unwrap();
        save_validated(&storage, &first).unwrap();
        save_validated(&storage, &second).unwrap();
        save_validated(&storage, &first).unwrap();
        assert_eq!(index(&storage).unwrap().len(), 2);
        remove(&storage, &first.uuid).unwrap();
        remove(&storage, &first.uuid).unwrap();
        assert_eq!(index(&storage).unwrap().len(), 1);
        assert!(
            storage
                .retrieve_data(&path(&first.uuid).unwrap())
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .retrieve_data(&path(&second.uuid).unwrap())
                .unwrap()
                .is_some()
        );
        assert_eq!(
            storage.retrieve("unrelated-key").unwrap().as_deref(),
            Some("keep")
        );
        assert!(remove(&storage, "../../key").is_err());
    }
    #[test]
    fn automatic_bundle_id_matching_preserves_exact_and_team_suffixed_ids() {
        let (p, _) = fixture("com.example.app");
        assert_eq!(
            main_bundle_id(&[p], "com.example.app", "TESTTEAM01"),
            "com.example.app"
        );
        assert_eq!(
            main_bundle_id(&[], "com.example.app", "TESTTEAM01"),
            "com.example.app.TESTTEAM01"
        );
        assert_eq!(
            main_bundle_id(&[], "com.example.app.TESTTEAM01", "TESTTEAM01"),
            "com.example.app.TESTTEAM01"
        );
    }
    #[test]
    fn entitlement_mismatch_is_explicit_and_profile_is_the_signing_basis() {
        let (p, _) = fixture("com.example.app");
        let mut requested = Dictionary::new();
        requested.insert("aps-environment".into(), "production".into());
        assert!(
            super::super::requested_entitlements::for_profile(
                &p,
                &requested,
                &p.bundle_id,
                &p.bundle_id
            )
            .unwrap_err()
            .to_string()
            .contains("aps-environment")
        );
        let signed = super::super::requested_entitlements::for_profile(
            &p,
            &Dictionary::new(),
            &p.bundle_id,
            &p.bundle_id,
        )
        .unwrap();
        assert_eq!(
            signed["application-identifier"],
            Value::String(p.application_identifier.clone())
        );
        assert_eq!(
            signed["keychain-access-groups"],
            Value::Array(vec![p.application_identifier.into()])
        );
    }
    #[test]
    fn app_store_profile_and_corrupt_files_cannot_be_used_for_local_install() {
        let (mut p, c) = fixture("com.example.app");
        p.devices = None;
        p.all_devices = false;
        assert!(select_one(&p, &c).is_err());
        assert!(ImportedProfile::parse(b"not a mobileprovision").is_err());
        let mut dict = fixture_plist(&c, "com.example.app");
        dict.remove("ExpirationDate");
        assert!(ImportedProfile::from_plist(b"synthetic", &dict).is_err());
    }
}
