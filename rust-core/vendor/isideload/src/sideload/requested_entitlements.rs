//! Read original Mach-O entitlements before resigning; fail closed on malformed
//! signatures or DER-only entitlements that cannot be inspected as a plist.
use super::imported_profiles::{ImportedProfile, allowed_string};
use plist::{Dictionary, Value};
use rootcause::prelude::*;
use std::{fs, path::Path};

fn word(data: &[u8], at: usize, little: bool) -> Result<u32, Report> {
    let bytes: [u8; 4] = data
        .get(
            at..at
                .checked_add(4)
                .ok_or_else(|| report!("Mach-O offset overflow."))?,
        )
        .ok_or_else(|| report!("Truncated Mach-O signature."))?
        .try_into()?;
    Ok(if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}
fn region(data: &[u8], offset: usize, len: usize) -> Result<&[u8], Report> {
    data.get(
        offset
            ..offset
                .checked_add(len)
                .ok_or_else(|| report!("Mach-O size overflow."))?,
    )
    .ok_or_else(|| report!("Mach-O signature is out of bounds."))
}

pub fn read(path: &Path) -> Result<Dictionary, Report> {
    if fs::metadata(path)?.len() > 512 * 1024 * 1024 {
        bail!("Executable is too large to inspect entitlements.");
    }
    parse(&fs::read(path)?, 0)
}
fn parse(data: &[u8], depth: usize) -> Result<Dictionary, Report> {
    if depth > 2 {
        bail!("Invalid nested fat Mach-O.");
    }
    let magic = word(data, 0, false)?;
    if magic == 0xcafebabe || magic == 0xcafebabf || magic == 0xbebafeca || magic == 0xbfbafeca {
        let little = magic == 0xbebafeca || magic == 0xbfbafeca;
        let wide = magic == 0xcafebabf || magic == 0xbfbafeca;
        let count = word(data, 4, little)? as usize;
        if count == 0 || count > 64 {
            bail!("Invalid fat Mach-O architecture count.");
        }
        let mut merged = Dictionary::new();
        for i in 0..count {
            let at = 8 + i * if wide { 32 } else { 20 };
            let (offset, size) = if wide {
                let number = |pos| -> Result<usize, Report> {
                    let raw: [u8; 8] = region(data, pos, 8)?.try_into()?;
                    Ok(usize::try_from(if little {
                        u64::from_le_bytes(raw)
                    } else {
                        u64::from_be_bytes(raw)
                    })?)
                };
                (number(at + 8)?, number(at + 16)?)
            } else {
                (
                    word(data, at + 8, little)? as usize,
                    word(data, at + 12, little)? as usize,
                )
            };
            for (key, value) in parse(region(data, offset, size)?, depth + 1)? {
                if merged.get(&key).is_some_and(|old| old != &value) {
                    bail!("Entitlements differ between Mach-O architectures: {key}.");
                }
                merged.insert(key, value);
            }
        }
        return Ok(merged);
    }
    let little = magic == 0xcffaedfe || magic == 0xcefaedfe;
    let wide = magic == 0xcffaedfe || magic == 0xfeedfacf;
    if !matches!(magic, 0xcffaedfe | 0xcefaedfe | 0xfeedface | 0xfeedfacf) {
        bail!("Executable is not a valid Mach-O.");
    }
    let count = word(data, 16, little)? as usize;
    let mut at = if wide { 32 } else { 28 };
    let end = at + word(data, 20, little)? as usize;
    region(data, at, end - at)?;
    if count > 65536 {
        bail!("Invalid Mach-O load command count.");
    }
    for _ in 0..count {
        let cmd = word(data, at, little)?;
        let len = word(data, at + 4, little)? as usize;
        if len < 8 || at + len > end {
            bail!("Invalid Mach-O load command.");
        }
        if cmd == 0x1d {
            if len < 16 {
                bail!("Invalid code signature command.");
            }
            let blob = region(
                data,
                word(data, at + 8, little)? as usize,
                word(data, at + 12, little)? as usize,
            )?;
            return signature_entitlements(blob);
        }
        at += len;
    }
    Ok(Dictionary::new()) // Truly unsigned executable.
}
fn signature_entitlements(blob: &[u8]) -> Result<Dictionary, Report> {
    if word(blob, 0, false)? != 0xfade0cc0 {
        bail!("Invalid embedded signature superblob.");
    }
    let blob = region(blob, 0, word(blob, 4, false)? as usize)?;
    let count = word(blob, 8, false)? as usize;
    if count > 1024 {
        bail!("Invalid code signature blob count.");
    }
    region(blob, 12, count * 8)?;
    let mut xml = None;
    let mut der = false;
    for i in 0..count {
        let at = word(blob, 16 + i * 8, false)? as usize;
        let magic = word(blob, at, false)?;
        let len = word(blob, at + 4, false)? as usize;
        if len < 8 {
            bail!("Invalid entitlement blob length.");
        }
        let entry = region(blob, at, len)?;
        if magic == 0xfade7171 {
            if xml.is_some() {
                bail!("Duplicate entitlement blobs.");
            }
            xml = Some(
                Value::from_reader_xml(&entry[8..])?
                    .into_dictionary()
                    .ok_or_else(|| report!("Invalid entitlement plist."))?,
            );
        }
        if magic == 0xfade7172 {
            der = true;
        }
    }
    if der && xml.is_none() {
        bail!(
            "Cannot validate DER-only app entitlements. Use an IPA with inspectable XML entitlements."
        );
    }
    Ok(xml.unwrap_or_default())
}

fn permits(allowed: &Value, requested: &Value) -> bool {
    match (allowed, requested) {
        (Value::String(pattern), Value::String(value)) => allowed_string(pattern, value),
        (Value::Array(allowed), Value::Array(requested)) => requested
            .iter()
            .all(|r| allowed.iter().any(|a| permits(a, r))),
        (Value::Dictionary(allowed), Value::Dictionary(requested)) => requested
            .iter()
            .all(|(k, r)| allowed.get(k).is_some_and(|a| permits(a, r))),
        (Value::Boolean(true), Value::Boolean(_)) => true,
        _ => allowed == requested,
    }
}

fn has_wildcard(value: &Value) -> bool {
    match value {
        Value::String(s) => s.contains('*'),
        Value::Array(values) => values.iter().any(has_wildcard),
        Value::Dictionary(values) => values.values().any(has_wildcard),
        _ => false,
    }
}

pub fn for_profile(
    profile: &ImportedProfile,
    requested: &Dictionary,
    bundle: &str,
    original_bundle: &str,
) -> Result<Dictionary, Report> {
    let app_id = format!("{}.{}", profile.team_id, bundle);
    let mut output = profile.entitlements.clone();
    output.insert("application-identifier".into(), app_id.clone().into());
    output.insert(
        "com.apple.developer.team-identifier".into(),
        profile.team_id.clone().into(),
    );
    // Identity keys are deliberately rebound to the selected profile/team;
    // capabilities (app groups, push, iCloud, etc.) are never silently rebased.
    for (key, value) in requested {
        if key == "application-identifier" || key == "com.apple.developer.team-identifier" {
            continue;
        }
        let value = if key == "keychain-access-groups" {
            let groups = value
                .as_array()
                .ok_or_else(|| report!("Invalid app keychain-access-groups."))?;
            let old_app_id = requested
                .get("application-identifier")
                .and_then(Value::as_string);
            Value::Array(
                groups
                    .iter()
                    .map(|v| {
                        let text = v
                            .as_string()
                            .ok_or_else(|| report!("Invalid app keychain group."))?;
                        Ok(
                            if Some(text) == old_app_id
                                || text.ends_with(&format!(".{original_bundle}"))
                            {
                                app_id.clone().into()
                            } else {
                                v.clone()
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, Report>>()?,
            )
        } else {
            value.clone()
        };
        if !profile
            .entitlements
            .get(key)
            .is_some_and(|allowed| permits(allowed, &value))
        {
            bail!(
                "Entitlements mismatch for {bundle}: {key} is not allowed by the imported provisioning profile."
            );
        }
        output.insert(key.clone(), value);
    }
    if !requested.contains_key("keychain-access-groups")
        && let Some(allowed) = profile.entitlements.get("keychain-access-groups")
    {
        let group = Value::Array(vec![app_id.into()]);
        if !permits(allowed, &group) {
            bail!("Entitlements mismatch for {bundle}: keychain-access-groups.");
        }
        output.insert("keychain-access-groups".into(), group);
    }
    // A wildcard in a profile is an authorization pattern, not a concrete
    // capability to grant to the executable. Unrequested wildcard capabilities
    // have no app-specific expansion and must not be blindly copied.
    output.retain(|key, value| requested.contains_key(key) || !has_wildcard(value));
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcard_arrays_do_not_allow_extra_groups_or_capabilities() {
        assert!(permits(
            &Value::Array(vec!["TEAM.*".into()]),
            &Value::Array(vec!["TEAM.com.example.app".into()])
        ));
        assert!(!permits(
            &Value::Array(vec!["group.a".into()]),
            &Value::Array(vec!["group.a".into(), "group.b".into()])
        ));
        assert!(!permits(&"development".into(), &"production".into()));
    }
    #[test]
    fn unsigned_and_corrupt_macho_are_distinguished() {
        let mut executable = vec![0u8; 32];
        executable[..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
        assert!(parse(&executable, 0).unwrap().is_empty());
        executable[16..20].copy_from_slice(&1u32.to_le_bytes());
        assert!(parse(&executable, 0).is_err());
        assert!(parse(b"broken", 0).is_err());
    }

    fn signed_executable(entitlements: &Dictionary) -> Vec<u8> {
        let mut xml = Vec::new();
        plist::to_writer_xml(&mut xml, entitlements).unwrap();
        let mut blob = Vec::new();
        for word in [
            0xfade0cc0,
            (28 + xml.len()) as u32,
            1,
            5,
            20,
            0xfade7171,
            (8 + xml.len()) as u32,
        ] {
            blob.extend_from_slice(&word.to_be_bytes());
        }
        blob.extend_from_slice(&xml);
        let mut macho = vec![0u8; 48];
        for (at, value) in [
            (0, 0xfeedfacfu32),
            (16, 1),
            (20, 16),
            (32, 0x1d),
            (36, 16),
            (40, 48),
            (44, blob.len() as u32),
        ] {
            macho[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        macho.extend_from_slice(&blob);
        macho
    }
    #[test]
    fn reads_signed_xml_and_fat_binary_entitlements_before_signing() {
        let mut ent = Dictionary::new();
        ent.insert("aps-environment".into(), "development".into());
        let macho = signed_executable(&ent);
        assert_eq!(parse(&macho, 0).unwrap(), ent);
        let mut fat = Vec::new();
        for word in [0xcafebabe, 1, 0x0100000c, 0, 28, macho.len() as u32, 0] {
            fat.extend_from_slice(&word.to_be_bytes());
        }
        fat.extend_from_slice(&macho);
        assert_eq!(parse(&fat, 0).unwrap(), ent);
        fat[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse(&fat, 0).is_err());
    }
    #[test]
    fn rejects_der_only_and_out_of_bounds_signature_data() {
        let mut macho = signed_executable(&Dictionary::new());
        macho[68..72].copy_from_slice(&0xfade7172u32.to_be_bytes());
        assert!(
            parse(&macho, 0)
                .unwrap_err()
                .to_string()
                .contains("DER-only")
        );
        let mut macho = signed_executable(&Dictionary::new());
        macho[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&macho, 0).is_err());
    }
}
