//! Verify the CMS payload and its signer chain before trusting profile fields.
//! No profile contents, certificates or device identifiers are logged here.
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use rootcause::prelude::*;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    signature::Verifier,
};
use sha2_010::Digest;
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

fn verify_signature(
    cert: &Certificate,
    oid: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Report> {
    let public =
        RsaPublicKey::from_public_key_der(&cert.tbs_certificate.subject_public_key_info.to_der()?)?;
    let signature = Signature::try_from(signature)?;
    match oid {
        "2.16.840.1.101.3.4.2.1" | "1.2.840.113549.1.1.11" => {
            VerifyingKey::<sha2_010::Sha256>::new(public).verify(message, &signature)?
        }
        "1.3.14.3.2.26" | "1.2.840.113549.1.1.5" => {
            VerifyingKey::<sha1_010::Sha1>::new(public).verify(message, &signature)?
        }
        _ => bail!("Unsupported provisioning profile signature algorithm."),
    }
    Ok(())
}

pub(super) fn verify(data: &[u8]) -> Result<(), Report> {
    verify_with_root(data, super::cert_identity::APPLE_ROOT)
}

// Separate root injection is private, so tests can use a synthetic CA without
// admitting self-signed profiles into the production import path.
fn verify_with_root(data: &[u8], root_der: &[u8]) -> Result<(), Report> {
    let content = ContentInfo::from_der(data)?;
    if content.content_type.to_string() != "1.2.840.113549.1.7.2" {
        bail!("Invalid profile CMS content type.");
    }
    let signed = SignedData::from_der(&content.content.to_der()?)?;
    if signed.encap_content_info.econtent_type.to_string() != "1.2.840.113549.1.7.1" {
        bail!("Invalid profile payload type.");
    }
    let payload = signed
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| report!("Profile has no signed payload."))?;
    let root = Certificate::from_der(root_der)?;
    let mut certificates = Vec::new();
    if let Some(certs) = &signed.certificates {
        for cert in certs.0.iter() {
            if let CertificateChoices::Certificate(cert) = cert {
                certificates.push(cert.clone());
            }
        }
    }
    certificates.push(root.clone());
    if signed.signer_infos.0.is_empty() {
        bail!("Provisioning profile is not signed.");
    }
    for signer in signed.signer_infos.0.iter() {
        let SignerIdentifier::IssuerAndSerialNumber(id) = &signer.sid else {
            bail!("Unsupported profile signer identifier.");
        };
        let cert = certificates
            .iter()
            .find(|c| {
                c.tbs_certificate.issuer == id.issuer
                    && c.tbs_certificate.serial_number == id.serial_number
            })
            .ok_or_else(|| report!("Profile signing certificate is missing."))?;
        // An ordinary Apple development certificate must never be able to
        // fabricate a trusted profile just because it also chains to Apple.
        if !cert
            .tbs_certificate
            .subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .any(|a| {
                a.oid.to_string() == "2.5.4.3"
                    && matches!(
                        a.value.value(),
                        b"Apple iPhone OS Provisioning Profile Signing"
                            | b"Apple Provisioning Profile Signing"
                    )
            })
        {
            bail!("CMS signer is not an Apple provisioning profile signing certificate.");
        }
        if signer.signature_algorithm.oid.to_string() != "1.2.840.113549.1.1.1"
            && signer.signature_algorithm.oid.to_string() != "1.2.840.113549.1.1.11"
        {
            bail!("Unsupported profile CMS signature algorithm.");
        }
        let oid = signer.digest_alg.oid.to_string();
        let message = if let Some(attrs) = &signer.signed_attrs {
            let digest = match oid.as_str() {
                "2.16.840.1.101.3.4.2.1" => sha2_010::Sha256::digest(payload.value()).to_vec(),
                "1.3.14.3.2.26" => sha1_010::Sha1::digest(payload.value()).to_vec(),
                _ => bail!("Unsupported profile payload digest."),
            };
            let digests: Vec<_> = attrs
                .iter()
                .filter(|a| a.oid.to_string() == "1.2.840.113549.1.9.4")
                .collect();
            if digests.len() != 1
                || digests[0].values.len() != 1
                || digests[0].values.iter().next().unwrap().value() != digest
            {
                bail!("Provisioning profile is corrupt: signed payload digest mismatch.");
            }
            let types: Vec<_> = attrs
                .iter()
                .filter(|a| a.oid.to_string() == "1.2.840.113549.1.9.3")
                .collect();
            if types.len() != 1
                || types[0].values.len() != 1
                || types[0].values.iter().next().unwrap().to_der()?
                    != signed.encap_content_info.econtent_type.to_der()?
            {
                bail!("Provisioning profile signed content type mismatch.");
            }
            attrs.to_der()?
        } else {
            payload.value().to_vec()
        };
        verify_signature(cert, &oid, &message, signer.signature.as_bytes())
            .context("Provisioning profile CMS signature is invalid.")?;
        let mut current = cert;
        let mut visited = Vec::new();
        while current != &root {
            let der = current.to_der()?;
            if visited.contains(&der) {
                bail!("Profile signer chain contains a cycle.");
            }
            visited.push(der);
            let parent = certificates
                .iter()
                .find(|c| {
                    c.tbs_certificate.subject == current.tbs_certificate.issuer && *c != current
                })
                .ok_or_else(|| report!("Profile signer is not rooted in Apple Root CA."))?;
            if visited.len() > 8
                || !parent
                    .tbs_certificate
                    .get::<x509_cert::ext::pkix::BasicConstraints>()?
                    .is_some_and(|(_, constraints)| constraints.ca)
            {
                bail!("Invalid provisioning profile certification authority.");
            }
            verify_signature(
                parent,
                &current.signature_algorithm.oid.to_string(),
                &current.tbs_certificate.to_der()?,
                current
                    .signature
                    .as_bytes()
                    .ok_or_else(|| report!("Invalid profile signer signature."))?,
            )?;
            current = parent;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cms::{
        builder::{SignedDataBuilder, SignerInfoBuilder},
        cert::IssuerAndSerialNumber,
        signed_data::EncapsulatedContentInfo,
    };
    use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256};
    use rsa::{
        RsaPrivateKey,
        pkcs1v15::SigningKey,
        pkcs8::{EncodePrivateKey, LineEnding},
    };
    use x509_cert::{
        der::asn1::{ObjectIdentifier, OctetStringRef},
        spki::AlgorithmIdentifierOwned,
    };

    #[test]
    fn verifies_signed_cms_and_rejects_corruption_and_untrusted_signer() {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pair = KeyPair::from_pkcs8_pem_and_sign_algo(
            &key.to_pkcs8_pem(LineEnding::LF).unwrap(),
            &PKCS_RSA_SHA256,
        )
        .unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "Apple iPhone OS Provisioning Profile Signing",
        );
        let cert = params.self_signed(&pair).unwrap();
        let cert = Certificate::from_der(cert.der()).unwrap();
        let dict = super::super::imported_profiles::tests::fixture_plist(
            &cert.to_der().unwrap(),
            "com.example.app",
        );
        let mut payload = Vec::new();
        plist::to_writer_xml(&mut payload, &dict).unwrap();
        let content = EncapsulatedContentInfo {
            econtent_type: ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1"),
            econtent: Some(OctetStringRef::new(&payload).unwrap().into()),
        };
        let signing_key = SigningKey::<sha2_010::Sha256>::new(key);
        let algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            parameters: None,
        };
        let id = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        });
        let signer =
            SignerInfoBuilder::new(&signing_key, id, algorithm.clone(), &content, None).unwrap();
        let mut builder = SignedDataBuilder::new(&content);
        builder.add_digest_algorithm(algorithm).unwrap();
        builder
            .add_certificate(CertificateChoices::Certificate(cert.clone()))
            .unwrap();
        builder
            .add_signer_info::<SigningKey<sha2_010::Sha256>, Signature>(signer)
            .unwrap();
        let bytes = builder.build().unwrap().to_der().unwrap();
        assert!(verify_with_root(&bytes, &cert.to_der().unwrap()).is_ok());
        let parsed = apple_codesign_quick::ProvisioningProfile::parse(&bytes).unwrap();
        let profile =
            super::super::imported_profiles::ImportedProfile::from_plist(&bytes, parsed.plist())
                .unwrap();
        assert_eq!(profile.bundle_id, "com.example.app");
        assert!(verify(&bytes).is_err());
        let mut corrupt = bytes.clone();
        let offset = corrupt.windows(9).position(|w| w == b"Synthetic").unwrap();
        corrupt[offset] ^= 1;
        assert!(verify_with_root(&corrupt, &cert.to_der().unwrap()).is_err());
        assert!(verify(&bytes[..bytes.len() / 2]).is_err());
    }
}
