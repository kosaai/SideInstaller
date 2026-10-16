//! Private-runner smoke test for the exact signing profiles. No raw material is
//! printed; arguments contain file paths, public identifiers and fingerprint.
use isideload::{
    sideload::{
        imported_profiles::{self, ImportedProfile},
        requested_entitlements,
    },
    util::fs_storage::FsStorage,
};
use rootcause::prelude::*;
use sha2::{Digest, Sha256};

fn main() -> Result<(), Report> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 9 {
        bail!(
            "Expected main/extension paths, team, UDID, certificate SHA256, main/extension IDs and temporary store directory"
        );
    }
    let main_data = std::fs::read(&args[1])?;
    let ext_data = std::fs::read(&args[2])?;
    let main = ImportedProfile::parse(&main_data)?;
    let ext = ImportedProfile::parse(&ext_data)?;
    let cert = main
        .certificates
        .iter()
        .find(|c| hex::encode(Sha256::digest(c)).eq_ignore_ascii_case(&args[5]))
        .ok_or_else(|| report!("Expected P12 certificate is absent from main profile"))?;
    main.validate(&args[6], &args[3], Some(&args[4]), cert)?;
    ext.validate(&args[7], &args[3], Some(&args[4]), cert)?;
    let storage = FsStorage::new(args[8].clone().into());
    imported_profiles::save(&storage, &main_data)?;
    imported_profiles::save(&storage, &ext_data)?;
    let loaded = imported_profiles::load(&storage)?;
    let ids = vec![args[6].clone(), args[7].clone()];
    let (selected, fallback) =
        imported_profiles::plan(&loaded, &ids, &args[3], Some(&args[4]), cert)?;
    assert_eq!(selected.len(), 2);
    assert!(fallback.is_empty());
    assert_ne!(selected[&ids[0]].uuid, selected[&ids[1]].uuid);
    for id in &ids {
        requested_entitlements::for_profile(selected[id], &plist::Dictionary::new(), id, id)?;
    }
    imported_profiles::remove(&storage, &main.uuid)?;
    assert_eq!(imported_profiles::load(&storage)?.len(), 1);
    imported_profiles::remove(&storage, &ext.uuid)?;
    assert!(imported_profiles::load(&storage)?.is_empty());
    println!(
        "Production profile CMS/parser, certificate/device/team/expiration, Main + Extension selection, persistence and local removal: PASS"
    );
    Ok(())
}
