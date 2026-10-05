//! Profiles and the connection history, kept in `~/.wg-gui`.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use wg_common::config::{self, Summary};

use crate::format;

const DIR_NAME: &str = ".wg-gui";
const LOG_NAME: &str = "connections.log";
const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct Profile {
    /// The file name without ".conf"; shown as the profile name.
    pub name: String,
    pub path: PathBuf,
    /// Or why the file could not be read.
    pub summary: Result<Summary, String>,
}

/// Where profiles live.
#[derive(Debug, Clone)]
pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    /// Finds and creates `~/.wg-gui`.
    pub fn open() -> Result<Store, String> {
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        let store = Store { dir: PathBuf::from(home).join(DIR_NAME) };
        if !store.dir.exists() {
            DirBuilder::new()
                .mode(0o700)
                .create(&store.dir)
                .map_err(|e| format!("cannot create {}: {e}", store.dir.display()))?;
        }
        Ok(store)
    }

    /// Every `*.conf` in the directory, sorted by name.
    pub fn list(&self) -> Vec<Profile> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut profiles: Vec<Profile> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "conf"))
            .map(|path| Profile {
                name: path.file_stem().unwrap_or_default().to_string_lossy().into_owned(),
                summary: fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|t| config::summary(&t)),
                path,
            })
            .collect();
        profiles.sort_by_key(|p| p.name.to_lowercase());
        profiles
    }

    /// Saves a config as a new profile and returns its final name, which
    /// may differ from `name` after cleaning and de-duplication.
    pub fn import(&self, name: &str, text: &str) -> Result<String, String> {
        let base = sanitize_name(name);
        let name = (1..)
            .map(|n| if n == 1 { base.clone() } else { format!("{base} ({n})") })
            .find(|candidate| !self.path_of(candidate).exists())
            .expect("an unused name exists");
        let path = self.path_of(&name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        file.write_all(text.as_bytes()).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Ok(name)
    }

    pub fn delete(&self, name: &str) -> Result<(), String> {
        let path = self.path_of(name);
        fs::remove_file(&path).map_err(|e| format!("cannot delete {}: {e}", path.display()))
    }

    pub fn path_of(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.conf"))
    }

    /// Appends a timestamped line to `connections.log`. Failures are only
    /// reported; the history must never get in the way of the tunnel.
    pub fn log_event(&self, event: &str) {
        let path = self.dir.join(LOG_NAME);
        let result = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| writeln!(file, "{} {event}", format::utc_now()));
        if let Err(e) = result {
            eprintln!("warning: cannot write {}: {e}", path.display());
        }
    }
}

/// A file-system-safe profile name: letters, digits, space and `_-.()`,
/// no leading dot, at most 64 characters.
pub fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.' | '(' | ')'))
        .take(MAX_NAME_LEN)
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').trim();
    if cleaned.is_empty() { "profile".to_string() } else { cleaned.to_string() }
}

/// The name the import screen suggests for a file: "head_office.conf" ->
/// "head office".
pub fn suggested_name(path: &Path) -> String {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let spaced = stem.replace(['_', '-'], " ");
    let trimmed = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.is_empty() { "New profile".to_string() } else { trimmed }
}

/// The config with the values of PrivateKey and PresharedKey hidden, for
/// display.
pub fn mask_keys(text: &str) -> String {
    text.lines()
        .map(|line| match line.split_once('=') {
            Some((key, _)) if matches!(key.trim().to_lowercase().as_str(), "privatekey" | "presharedkey") => {
                format!("{} = [hidden]", key.trim_end())
            }
            _ => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned() {
        assert_eq!(sanitize_name("Head Office"), "Head Office");
        assert_eq!(sanitize_name("../../etc/passwd"), "etcpasswd");
        assert_eq!(sanitize_name("  .hidden "), "hidden");
        assert_eq!(sanitize_name("/"), "profile");
        assert_eq!(sanitize_name(&"x".repeat(100)).len(), MAX_NAME_LEN);
        assert_eq!(suggested_name(Path::new("/tmp/field_station-2.conf")), "field station 2");
    }

    #[test]
    fn keys_are_masked() {
        let text = "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.2/32\n[Peer]\n  presharedkey=xyz\nPublicKey = pub=";
        let masked = mask_keys(text);
        assert!(!masked.contains("abc") && !masked.contains("xyz"));
        assert!(masked.contains("PrivateKey = [hidden]"));
        assert!(masked.contains("  presharedkey = [hidden]"));
        assert!(masked.contains("PublicKey = pub="));
    }

    #[test]
    fn import_dedupes_and_deletes() {
        let dir = std::env::temp_dir().join(format!("wg-gui-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let store = Store { dir: dir.clone() };
        assert_eq!(store.import("Office", "a").unwrap(), "Office");
        assert_eq!(store.import("Office", "b").unwrap(), "Office (2)");
        assert_eq!(fs::read_to_string(store.path_of("Office (2)")).unwrap(), "b");
        let names: Vec<_> = store.list().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["Office", "Office (2)"]);
        store.delete("Office").unwrap();
        assert_eq!(store.list().len(), 1);
        store.log_event("connected \"Office (2)\"");
        assert!(fs::read_to_string(dir.join(LOG_NAME)).unwrap().contains("connected \"Office (2)\""));
        fs::remove_dir_all(dir).unwrap();
    }
}
