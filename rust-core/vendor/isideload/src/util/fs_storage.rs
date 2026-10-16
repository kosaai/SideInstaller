use std::path::{Path, PathBuf};
use std::ffi::{c_char, CString};
use std::sync::OnceLock;
use rootcause::prelude::*;
use crate::util::storage::SideloadingStorage;

/// The app supplies Security.framework-backed, synchronous callbacks. No key
/// may fall back to the filesystem on iOS if Keychain is unavailable.
pub type KeyRead = extern "C" fn(*const c_char, *mut u8, usize, *mut usize) -> i32;
pub type KeyWrite = extern "C" fn(*const c_char, *const u8, usize) -> i32;
static KEYCHAIN: OnceLock<(KeyRead, KeyWrite)> = OnceLock::new();

pub fn set_signing_key_storage(read: KeyRead, write: KeyWrite) {
    let _ = KEYCHAIN.set((read, write));
}

pub struct FsStorage { path: PathBuf }
impl FsStorage {
    pub fn new(path: PathBuf) -> Self { Self { path } }
    fn is_signing_key(key: &str) -> bool {
        key.strip_suffix("/key").is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()))
    }
    fn callbacks(key: &str) -> Result<Option<&'static (KeyRead, KeyWrite)>, Report> {
        if !Self::is_signing_key(key) { return Ok(None); }
        if let Some(callbacks) = KEYCHAIN.get() { return Ok(Some(callbacks)); }
        if cfg!(target_os = "ios") { bail!("Signing Keychain is unavailable. Unlock this device and try again."); }
        Ok(None)
    }
    fn remove_file(&self, key: &str) -> Result<(), Report> {
        match std::fs::remove_file(self.path.join(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(report!(e).context("Could not remove legacy signing key").into()),
        }
    }
}
impl Default for FsStorage { fn default() -> Self { Self::new(PathBuf::from(".")) } }

impl SideloadingStorage for FsStorage {
    fn store_data(&self, key: &str, data: &[u8]) -> Result<(), Report> {
        if let Some((_, write)) = Self::callbacks(key)? {
            let name = CString::new(key)?;
            if write(name.as_ptr(), data.as_ptr(), data.len()) != 0 {
                bail!("Could not save signing key in Keychain.");
            }
            self.remove_file(key)?;
            return Ok(());
        }
        let path = self.path.join(key);
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
        std::fs::write(path, data).context("Failed to save data")?;
        Ok(())
    }
    fn retrieve_data(&self, key: &str) -> Result<Option<Vec<u8>>, Report> {
        if let Some((read, _)) = Self::callbacks(key)? {
            let name = CString::new(key)?;
            let mut bytes = vec![0u8; 16384];
            let mut len = 0usize;
            let status = read(name.as_ptr(), bytes.as_mut_ptr(), bytes.len(), &mut len);
            match status {
                0 if len <= bytes.len() => {
                    bytes.truncate(len);
                    self.remove_file(key)?;
                    return Ok(Some(bytes));
                }
                1 => { bytes.fill(0); }
                _ => { bytes.fill(0); bail!("Could not read signing Keychain. Unlock this device and try again."); }
            }
            // Migrate the original Application Support key only after Keychain
            // accepts it; never delete it on an authentication/storage failure.
            let legacy = match std::fs::read(self.path.join(key)) {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(report!(e).into()),
            };
            if let Some(mut data) = legacy {
                if let Err(error) = self.store_data(key, &data) { data.fill(0); return Err(error); }
                return Ok(Some(data));
            }
            return Ok(None);
        }
        match std::fs::read(self.path.join(key)) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(report!(e).context("Failed to read storage").into()),
        }
    }
    fn store(&self, key: &str, value: &str) -> Result<(), Report> { self.store_data(key, value.as_bytes()) }
    fn retrieve(&self, key: &str) -> Result<Option<String>, Report> {
        Ok(self.retrieve_data(key)?.map(|v| String::from_utf8_lossy(&v).into_owned()))
    }
    fn delete(&self, key: &str) -> Result<(), Report> {
        if let Some((_, write)) = Self::callbacks(key)? {
            let name = CString::new(key)?;
            if write(name.as_ptr(), std::ptr::null(), 0) != 0 { bail!("Could not remove the local Keychain key."); }
        }
        self.remove_file(key)
    }
}
