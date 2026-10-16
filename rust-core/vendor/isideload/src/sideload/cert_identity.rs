use apple_codesign_quick::ProvisioningProfile;
use hex::ToHex;
use rootcause::prelude::*;
use rsa::{
    RsaPrivateKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};

use sha1::Sha1;
use sha2::{Digest, Sha256};
use tracing::{error, info};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

use crate::{
    SideloadError,
    dev::{
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
        teams::DeveloperTeam,
    },
    sideload::builder::MaxCertsBehavior,
    util::storage::SideloadingStorage,
};

/// Apple's root and the WWDR G3 intermediate that issues development
/// certificates, for the chain sent with each signature (upstream cc9fa9c).
pub const APPLE_ROOT: &[u8] = include_bytes!("../auth/apple_root.der");
pub const APPLE_WWDR_G3_CERTIFICATE_DER: &[u8] = include_bytes!("../assets/AppleWWDRCAG3.cer");

pub struct CertificateIdentity {
    pub machine_id: String,
    pub machine_name: String,
    pub private_key: RsaPrivateKey,
    pub certificate: Certificate,
}

impl CertificateIdentity {
    // This implementation was mostly borrowed from Impactor (https://github.com/khcrysalis/Impactor/blob/main/crates/plume_core/src/utils/certificate.rs)
    /// Exports the certificate and private key as a PKCS#12 archive
    /// If you plan to import into SideStore/AltStore, use the machine id as the password
    pub async fn as_p12(&self, password: &str) -> Result<Vec<u8>, Report> {
        let cert_der = self.certificate.to_der()?;
        let cert_der_len = cert_der.len();
        let key_der = self.private_key.to_pkcs8_der()?.as_bytes().to_vec();
        let key_der_len = key_der.len();

        let cert = p12_keystore::Certificate::from_der(&cert_der)
            .map_err(|e| report!("Failed to parse certificate: {:?}", e))?;
        let cert_subject = cert.subject().to_string();
        let cert_issuer = cert.issuer().to_string();

        let local_key_id = {
            let mut hasher = Sha1::new();
            hasher.update(&key_der);
            let hash = hasher.finalize();
            hash[..8].to_vec()
        };

        let key_chain = p12_keystore::PrivateKeyChain::new(
            local_key_id,
            p12_keystore::PrivateKey::from_der(&key_der)?,
            vec![cert],
        );

        let mut keystore = p12_keystore::KeyStore::new();
        keystore.add_entry(
            "isideload",
            p12_keystore::KeyStoreEntry::PrivateKeyChain(key_chain),
        );

        let writer = keystore.writer(password);
        match writer.write() {
            Ok(p12) => Ok(p12),
            Err(e) => {
                let subject_codepoints = cert_subject
                    .chars()
                    .map(|c| format!("U+{:04X}", c as u32))
                    .collect::<Vec<_>>()
                    .join(" ");
                let has_non_bmp_subject_chars = cert_subject.chars().any(|c| (c as u32) > 0xFFFF);

                error!(
                    cert_subject = %cert_subject,
                    cert_issuer = %cert_issuer,
                    cert_subject_codepoints = %subject_codepoints,
                    has_non_bmp_subject_chars,
                    cert_der_len,
                    key_der_len,
                    password_char_len = password.chars().count(),
                    "Failed to write PKCS#12 archive"
                );

                let err = format!("Failed to write PKCS#12 archive: {:?}", e);
                Err(e).context(err)?
            }
        }
    }

    pub fn get_serial_number(&self) -> String {
        let serial: String = self
            .certificate
            .tbs_certificate
            .serial_number
            .as_bytes()
            .encode_hex::<String>();
        serial.trim_start_matches('0').to_string().to_uppercase()
    }

    /// Signing is reuse-only: no CSR, certificate creation, or revocation.
    pub async fn retrieve(
        machine_name: &str,
        apple_email: &str,
        developer_session: &mut DeveloperSession,
        team: &DeveloperTeam,
        storage: &dyn SideloadingStorage,
        _max_certs_behavior: &MaxCertsBehavior,
    ) -> Result<Self, Report> {
        Ok(Self::retrieve_existing(machine_name, apple_email, developer_session, team, storage)
            .await?
            .ok_or_else(|| report!(SideloadError::DeveloperError(7460,
                "This certificate exists on Apple, but its private key is not available on this device. Import its P12/PFX file.".into())))?)
    }

    pub async fn retrieve_existing(
        _machine_name: &str,
        apple_email: &str,
        developer_session: &mut DeveloperSession,
        team: &DeveloperTeam,
        storage: &dyn SideloadingStorage,
    ) -> Result<Option<Self>, Report> {
        // Always refresh Apple's list; propagate portal errors without treating
        // them as permission to request a replacement certificate.
        let certs = developer_session.list_ios_certs(team).await?;
        let Some(private_key) = Self::load_private_key(apple_email, storage)? else {
            return Ok(None);
        };
        let imported_certificate = storage.retrieve_data(&Self::certificate_path(apple_email))?;
        for cert in certs {
            let Some(content) = cert.cert_content.as_ref() else { continue };
            // A renewed certificate can share the same public key. Respect the
            // exact certificate selected by P12 import, not portal list order.
            if imported_certificate.as_ref().is_some_and(|expected| expected.as_slice() != content.as_ref()) { continue; }
            if Self::key_matches(&private_key, content.as_ref())? {
                let certificate = Certificate::from_der(content.as_ref())?;
                if !Self::valid_for_team(&certificate, &team.team_id) { continue; }
                info!("Reusing existing Apple development certificate with local private key");
                return Ok(Some(Self {
                    machine_id: cert.machine_id.unwrap_or_else(|| Self::serial(&certificate)),
                    machine_name: cert.machine_name.unwrap_or_default(),
                    private_key, certificate,
                }));
            }
        }
        Ok(None)
    }

    /// The certificates that sit between this identity's certificate and
    /// Apple's root, root last, for the signature's CMS. Taken from the
    /// profile's own CMS and the bundled WWDR G3 and root (upstream cc9fa9c).
    pub fn profile_to_certificate_chain(
        &self,
        profile: &ProvisioningProfile,
    ) -> Result<Vec<Certificate>, Report> {
        let mut certificate_candidates = Vec::new();

        for certificate_der in profile.certificate_chain_der() {
            let certificate = Certificate::from_der(certificate_der.as_ref())
                .context("failed to decode chain certificate")?;
            if !certificate_candidates.contains(&certificate) {
                certificate_candidates.push(certificate);
            }
        }

        for (name, certificate_der) in [
            ("Apple WWDR G3", APPLE_WWDR_G3_CERTIFICATE_DER),
            ("Apple Root CA", APPLE_ROOT),
        ] {
            let certificate = Certificate::from_der(certificate_der)
                .context(format!("failed to decode bundled {name} certificate"))?;
            if !certificate_candidates.contains(&certificate) {
                certificate_candidates.push(certificate);
            }
        }

        self.certificate_chain_for_signer(&certificate_candidates)
    }

    fn certificate_chain_for_signer(
        &self,
        certificate_candidates: &[Certificate],
    ) -> Result<Vec<Certificate>, Report> {
        if self.certificate.tbs_certificate.subject == self.certificate.tbs_certificate.issuer {
            return Ok(Vec::new());
        }

        let mut issuer = self.certificate.tbs_certificate.issuer.clone();
        let mut certificate_chain = Vec::new();

        loop {
            let certificate = certificate_candidates
                .iter()
                .find(|candidate| candidate.tbs_certificate.subject == issuer)
                .ok_or_else(|| {
                    report!(
                        "missing issuer certificate {issuer} for the code-signing certificate chain"
                    )
                })?
                .clone();

            if certificate_chain.contains(&certificate) {
                bail!("certificate chain contains a cycle");
            }

            let is_root = certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer;
            issuer = certificate.tbs_certificate.issuer.clone();
            certificate_chain.push(certificate);

            if is_root {
                return Ok(certificate_chain);
            }
        }
    }

    fn key_path(apple_email: &str) -> String {
        format!("{}/key", hex::encode(Sha256::digest(apple_email.as_bytes())))
    }

    fn load_private_key(apple_email: &str, storage: &dyn SideloadingStorage) -> Result<Option<RsaPrivateKey>, Report> {
        let Some(mut bytes) = storage.retrieve_data(&Self::key_path(apple_email))? else {
            return Ok(None);
        };
        let result = RsaPrivateKey::from_pkcs8_der(&bytes);
        bytes.fill(0);
        Ok(Some(result.context("Could not load the local signing key")?))
    }

    fn key_matches(key: &RsaPrivateKey, certificate_der: &[u8]) -> Result<bool, Report> {
        let cert = Certificate::from_der(certificate_der).context("Invalid certificate")?;
        let public_key = key.to_public_key().to_pkcs1_der()?;
        Ok(cert.tbs_certificate.subject_public_key_info.subject_public_key.as_bytes()
            == Some(public_key.as_bytes()))
    }

    fn serial(cert: &Certificate) -> String {
        hex::encode_upper(cert.tbs_certificate.serial_number.as_bytes())
            .trim_start_matches('0').to_owned()
    }

    fn valid_for_team(cert: &Certificate, team_id: &str) -> bool {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let validity = &cert.tbs_certificate.validity;
        validity.not_before.to_unix_duration() <= now && now < validity.not_after.to_unix_duration()
            && cert.tbs_certificate.subject.0.iter().flat_map(|rdn| rdn.0.iter())
                .any(|attr| attr.oid.to_string() == "2.5.4.11" && attr.value.value() == team_id.as_bytes())
    }

    pub fn has_local_key(apple_email: &str, certificate_der: &[u8], storage: &dyn SideloadingStorage) -> Result<bool, Report> {
        match Self::load_private_key(apple_email, storage)? {
            Some(key) => Self::key_matches(&key, certificate_der),
            None => Ok(false),
        }
    }

    /// Called only after SecPKCS12Import. Match the whole certificate against a
    /// fresh portal response, then bind its key to the existing account storage.
    pub async fn import_existing_key(
        apple_email: &str,
        certificate_der: &[u8],
        private_key_pkcs1: &[u8],
        developer_session: &mut DeveloperSession,
        team: &DeveloperTeam,
        storage: &dyn SideloadingStorage,
    ) -> Result<(), Report> {
        let certs = developer_session.list_ios_certs(team).await?;
        Self::bind_existing_key(apple_email, certificate_der, private_key_pkcs1, &team.team_id, &certs, storage)
    }

    fn bind_existing_key(apple_email: &str, certificate_der: &[u8], private_key_pkcs1: &[u8],
                         team_id: &str, certs: &[DevelopmentCertificate], storage: &dyn SideloadingStorage) -> Result<(), Report> {
        let key = RsaPrivateKey::from_pkcs1_der(private_key_pkcs1)
            .context("The signing engine requires an RSA private key")?;
        key.validate().context("Invalid signing key")?;
        if !Self::key_matches(&key, certificate_der)? {
            bail!("The private key does not match the selected certificate.");
        }
        let cert = Certificate::from_der(certificate_der)?;
        if !Self::valid_for_team(&cert, team_id) {
            bail!("Certificate is expired, not yet valid, or belongs to a different team.");
        }
        if !certs.iter().any(|c| c.cert_content.as_ref().is_some_and(|data| data.as_ref() == certificate_der)) {
            bail!("The imported certificate was not found on this Apple developer team. Check the selected account.");
        }
        let encoded = key.to_pkcs8_der()?;
        storage.store_data(&Self::key_path(apple_email), encoded.as_bytes())?;
        // Public certificate metadata is local app data, never private-key
        // storage. Profiles can be checked offline against the exact P12 DER.
        storage.store_data(&Self::certificate_path(apple_email), certificate_der)?;
        Ok(())
    }

    fn certificate_path(apple_email: &str) -> String {
        format!("{}/imported-certificate.der", hex::encode(Sha256::digest(apple_email.as_bytes())))
    }

    pub fn local_certificate(apple_email: &str, storage: &dyn SideloadingStorage) -> Result<Option<Vec<u8>>, Report> {
        let certificate = storage.retrieve_data(&Self::certificate_path(apple_email))?;
        match certificate {
            Some(der) if Self::has_local_key(apple_email, &der, storage)? => Ok(Some(der)),
            _ => Ok(None),
        }
    }

    /// Local storage only. There is deliberately no DeveloperSession here.
    pub fn remove_local_key(apple_email: &str, certificate_der: &[u8], storage: &dyn SideloadingStorage) -> Result<(), Report> {
        if Self::has_local_key(apple_email, certificate_der, storage)? {
            storage.delete(&Self::key_path(apple_email))?;
            storage.delete(&Self::certificate_path(apple_email))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod imported_identity_tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::LineEnding;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256};
    use crate::util::storage::InMemoryStorage;

    fn fixture() -> (RsaPrivateKey, Vec<u8>, DevelopmentCertificate) {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let signer = KeyPair::from_pkcs8_pem_and_sign_algo(&key.to_pkcs8_pem(LineEnding::LF).unwrap(), &PKCS_RSA_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Synthetic test certificate");
        name.push(DnType::OrganizationalUnitName, "TESTTEAM01");
        params.distinguished_name = name;
        let der = params.self_signed(&signer).unwrap().der().to_vec();
        let mut portal: DevelopmentCertificate = serde_json::from_str("{}").unwrap();
        portal.machine_name = Some("A different computer".into());
        portal.cert_content = Some(plist::Data::new(der.clone()));
        (key, der, portal)
    }

    #[test]
    fn imported_key_matches_apple_certificate_from_another_machine() {
        let (key, der, portal) = fixture();
        let storage = InMemoryStorage::new();
        CertificateIdentity::bind_existing_key("test@example.invalid", &der,
            key.to_pkcs1_der().unwrap().as_bytes(), "TESTTEAM01", &[portal], &storage).unwrap();
        assert!(CertificateIdentity::has_local_key("test@example.invalid", &der, &storage).unwrap());
        assert_eq!(CertificateIdentity::local_certificate("test@example.invalid", &storage).unwrap().as_deref(), Some(der.as_slice()));
    }

    #[test]
    fn missing_key_is_not_generated_and_wrong_account_cannot_reuse_it() {
        let (_, der, _) = fixture();
        let storage = InMemoryStorage::new();
        assert!(!CertificateIdentity::has_local_key("missing@example.invalid", &der, &storage).unwrap());
        assert!(storage.retrieve_data(&CertificateIdentity::key_path("missing@example.invalid")).unwrap().is_none());
    }

    #[test]
    fn mismatch_or_absent_apple_certificate_cannot_overwrite_key() {
        let (key, der, portal) = fixture();
        let (wrong, _, _) = fixture();
        let storage = InMemoryStorage::new();
        assert!(CertificateIdentity::bind_existing_key("test@example.invalid", &der,
            wrong.to_pkcs1_der().unwrap().as_bytes(), "TESTTEAM01", &[portal], &storage).is_err());
        assert!(CertificateIdentity::bind_existing_key("test@example.invalid", &der,
            key.to_pkcs1_der().unwrap().as_bytes(), "TESTTEAM01", &[], &storage).is_err());
        assert!(CertificateIdentity::load_private_key("test@example.invalid", &storage).unwrap().is_none());
    }

    #[test]
    fn wrong_team_is_rejected() {
        let (key, der, portal) = fixture();
        assert!(CertificateIdentity::bind_existing_key("test@example.invalid", &der,
            key.to_pkcs1_der().unwrap().as_bytes(), "OTHERTEAM1", &[portal], &InMemoryStorage::new()).is_err());
    }

    #[test]
    fn removing_local_key_only_changes_local_storage() {
        let (key, der, portal) = fixture();
        let storage = InMemoryStorage::new();
        CertificateIdentity::bind_existing_key("test@example.invalid", &der,
            key.to_pkcs1_der().unwrap().as_bytes(), "TESTTEAM01", &[portal.clone()], &storage).unwrap();
        CertificateIdentity::remove_local_key("test@example.invalid", &der, &storage).unwrap();
        assert!(!CertificateIdentity::has_local_key("test@example.invalid", &der, &storage).unwrap());
        assert!(CertificateIdentity::local_certificate("test@example.invalid", &storage).unwrap().is_none());
        assert_eq!(portal.cert_content.unwrap().as_ref(), der.as_slice());
    }
}
