//! Profiles and the connection history, kept in `~/.config/wg-gui`.
//!
//! `wg-profiles.conf` is the index of every config file the app uses; the
//! app never looks for configs anywhere else. Imported profiles are copied
//! into `profiles/` and listed there, one section per profile:
//!
//! ```text
//! [Office]
//! config = /Users/me/.config/wg-gui/profiles/Office.conf
//! comment = Imported from /Users/me/Downloads/office.conf
//! added = 2026-10-06T15:41:00+06:00
//! ```

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use wg_common::config::{self, Summary};

use crate::format;

const CONFIG_DIR: &str = ".config/wg-gui";
/// Where older versions kept everything; moved to CONFIG_DIR on start.
const OLD_DIR: &str = ".wg-gui";
const INDEX_NAME: &str = "wg-profiles.conf";
const PROFILES_DIR: &str = "profiles";
const LOG_NAME: &str = "connections.log";
const MAX_NAME_LEN: usize = 64;
const INDEX_HEADER: &str = "\
# wg-gui index: every config file the app uses is listed here.
# One [profile name] section per profile; config is the file it uses.
";

#[derive(Debug, Clone)]
pub struct Profile {
    /// The section name in the index; unique, ignoring case.
    pub name: String,
    /// The copy in `profiles/` the app reads.
    pub path: PathBuf,
    /// Free text; the app puts where the file came from here.
    pub comment: Option<String>,
    /// When it was imported, as "2026-10-04T18:00:00+06:00".
    pub added: Option<String>,
    /// Or why the file could not be read.
    pub summary: Result<Summary, String>,
    /// The index lists it but its config file is gone; it can only be
    /// deleted.
    pub stale: bool,
}

/// One `[Section]` of the index with its `key = value` lines, in order.
/// Sections without a `config` key are not profiles and are kept as they
/// are.
#[derive(Debug, Clone, PartialEq)]
struct Section {
    name: String,
    entries: Vec<(String, String)>,
}

impl Section {
    fn get(&self, key: &str) -> Option<&str> {
        self.entries.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
    }

    fn profile_name(&self) -> Option<&str> {
        self.get("config").map(|_| self.name.as_str())
    }
}

/// Where profiles live.
#[derive(Debug, Clone)]
pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    /// Finds and creates `~/.config/wg-gui` (moving `~/.wg-gui` there if
    /// an older version left one), and lists any unlisted configs.
    pub fn open() -> Result<Store, String> {
        let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?);
        let store = Store { dir: home.join(CONFIG_DIR) };
        store.move_old_dir(&home.join(OLD_DIR))?;
        store.prepare()?;
        Ok(store)
    }

    /// Moves `~/.wg-gui` from older versions here, unless this folder
    /// already exists, and points the index at the moved files.
    fn move_old_dir(&self, old: &Path) -> Result<(), String> {
        if old.is_dir() {
            if self.dir.exists() {
                eprintln!("warning: {} is no longer used; profiles are in {}", old.display(), self.dir.display());
                return Ok(());
            }
            if let Some(parent) = self.dir.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            fs::rename(old, &self.dir)
                .map_err(|e| format!("cannot move {} to {}: {e}", old.display(), self.dir.display()))?;
        }
        // Also on every later start, in case this failed after the move.
        self.repoint_index(old)
    }

    /// Rewrites `config` paths under `old` (which is gone) to this folder.
    fn repoint_index(&self, old: &Path) -> Result<(), String> {
        if old.exists() || !self.index_path().exists() {
            return Ok(());
        }
        let mut sections = self.read_index()?;
        let mut changed = false;
        for (key, value) in sections.iter_mut().flat_map(|s| s.entries.iter_mut()) {
            if key.eq_ignore_ascii_case("config")
                && let Ok(rest) = Path::new(value.as_str()).strip_prefix(old)
            {
                *value = self.dir.join(rest).display().to_string();
                changed = true;
            }
        }
        if changed { self.write_index(&sections) } else { Ok(()) }
    }

    fn prepare(&self) -> Result<(), String> {
        // ~/.config is shared with other tools, so it keeps the usual mode.
        if let Some(parent) = self.dir.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        for dir in [self.dir.clone(), self.profiles_dir()] {
            if !dir.exists() {
                DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            }
        }
        self.sync_with_index()
    }

    pub fn index_path(&self) -> PathBuf {
        self.dir.join(INDEX_NAME)
    }

    fn profiles_dir(&self) -> PathBuf {
        self.dir.join(PROFILES_DIR)
    }

    /// Every profile in the index, sorted by name.
    pub fn list(&self) -> Vec<Profile> {
        let sections = match self.read_index() {
            Ok(sections) => sections,
            Err(e) => {
                eprintln!("warning: {e}");
                return Vec::new();
            }
        };
        let mut profiles: Vec<Profile> = sections
            .iter()
            .filter_map(|section| {
                let name = section.profile_name()?;
                let path = PathBuf::from(section.get("config")?);
                Some(Profile {
                    name: name.to_string(),
                    summary: fs::read_to_string(&path)
                        .map_err(|e| format!("cannot read {}: {e}", path.display()))
                        .and_then(|t| config::summary(&t)),
                    stale: !path.exists(),
                    path,
                    comment: section.get("comment").map(str::to_string),
                    added: section.get("added").map(str::to_string),
                })
            })
            .collect();
        profiles.sort_by_key(|p| p.name.to_lowercase());
        profiles
    }

    /// Copies a config into `profiles/`, adds it to the index and returns
    /// its final name, which may differ from `name` after cleaning and
    /// de-duplication. A config that is already saved is refused.
    pub fn import(&self, name: &str, text: &str, source: Option<&Path>) -> Result<String, String> {
        if let Some(existing) = self.find_duplicate(text) {
            return Err(format!("This configuration already exists as profile “{existing}”."));
        }
        let mut sections = self.read_index()?;
        let name = self.unused_name(&sections, &sanitize_name(name));
        let path = self.profiles_dir().join(format!("{name}.conf"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        file.write_all(text.as_bytes()).map_err(|e| format!("cannot write {}: {e}", path.display()))?;

        let comment = source.map(|source| format!("Imported from {}", source.display()));
        sections.push(profile_section(&name, &path, comment, &format::local_now()));
        if let Err(e) = self.write_index(&sections) {
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        Ok(name)
    }

    /// The name of a saved profile with the same tunnel as `text`, if any.
    pub fn find_duplicate(&self, text: &str) -> Option<String> {
        self.list()
            .into_iter()
            .find(|profile| fs::read_to_string(&profile.path).is_ok_and(|saved| config::same_tunnel(&saved, text)))
            .map(|profile| profile.name)
    }

    /// Removes a profile from the index, and its copy from `profiles/`.
    /// Files the index points to elsewhere are left alone.
    pub fn delete(&self, name: &str) -> Result<(), String> {
        let mut sections = self.read_index()?;
        let position = sections
            .iter()
            .position(|section| section.profile_name() == Some(name))
            .ok_or_else(|| format!("no profile named “{name}”"))?;
        let section = sections.remove(position);
        self.write_index(&sections)?;
        if let Some(path) = section.get("config").map(Path::new)
            && path.parent() == Some(self.profiles_dir().as_path())
        {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(format!("cannot delete {}: {e}", path.display())),
            }
        }
        Ok(())
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

    /// `base`, or "base (2)", "base (3)"... whichever is free both in the
    /// index and on disk (where names are case-insensitive).
    fn unused_name(&self, sections: &[Section], base: &str) -> String {
        first_free(base, |candidate| {
            name_taken(sections, candidate) || self.profiles_dir().join(format!("{candidate}.conf")).exists()
        })
    }

    /// Makes `profiles/` match the index, which is the source of truth:
    /// files saved straight into `~/.wg-gui` by older versions are moved
    /// into `profiles/` and listed, and files in `profiles/` the index does
    /// not list are deleted. Nothing is deleted if the index cannot be read.
    fn sync_with_index(&self) -> Result<(), String> {
        let mut sections = self.read_index()?;
        for old in conf_files(&self.dir) {
            let name = self.unused_name(&sections, &sanitize_name(&file_stem(&old)));
            let new = self.profiles_dir().join(format!("{name}.conf"));
            let added = modified(&old);
            fs::rename(&old, &new).map_err(|e| format!("cannot move {} to {}: {e}", old.display(), new.display()))?;
            let comment = format!("Moved from {}", old.display());
            sections.push(profile_section(&name, &new, Some(comment), &added));
            self.write_index(&sections)?;
        }

        // Compared after resolving links and "..", so a listed file is never
        // taken for an unlisted one because its path is spelt differently.
        let listed: Vec<PathBuf> =
            sections.iter().filter_map(|s| s.get("config")).filter_map(|path| fs::canonicalize(path).ok()).collect();
        for path in conf_files(&self.profiles_dir()) {
            if fs::canonicalize(&path).is_ok_and(|real| !listed.contains(&real)) {
                fs::remove_file(&path).map_err(|e| format!("cannot delete {}: {e}", path.display()))?;
                eprintln!("note: deleted {}, which is not in {INDEX_NAME}", path.display());
            }
        }
        Ok(())
    }

    fn read_index(&self) -> Result<Vec<Section>, String> {
        let path = self.index_path();
        match fs::read_to_string(&path) {
            Ok(text) => Ok(parse_index(&text)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    /// Replaces the index in one step, so a crash never leaves half of it.
    fn write_index(&self, sections: &[Section]) -> Result<(), String> {
        let path = self.index_path();
        let temp = self.dir.join(format!("{INDEX_NAME}.tmp"));
        let write = || -> std::io::Result<()> {
            let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temp)?;
            file.write_all(format_index(sections).as_bytes())?;
            file.sync_all()?;
            fs::rename(&temp, &path)
        };
        write().map_err(|e| format!("cannot write {}: {e}", path.display()))
    }
}

/// `base`, or "base (2)", "base (3)"... whichever is not `taken`.
fn first_free(base: &str, taken: impl Fn(&str) -> bool) -> String {
    (1..)
        .map(|n| if n == 1 { base.to_string() } else { format!("{base} ({n})") })
        .find(|candidate| !taken(candidate))
        .expect("an unused name exists")
}

fn name_taken(sections: &[Section], candidate: &str) -> bool {
    sections.iter().filter_map(Section::profile_name).any(|taken| taken.eq_ignore_ascii_case(candidate))
}

/// The `*.conf` files directly in `dir`, other than the index, by name.
fn conf_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "conf"))
        .filter(|path| path.file_name().is_some_and(|name| name != INDEX_NAME))
        .collect();
    paths.sort();
    paths
}

fn file_stem(path: &Path) -> String {
    path.file_stem().unwrap_or_default().to_string_lossy().into_owned()
}

/// When a file was last changed, in local time; now if that is unknown.
fn modified(path: &Path) -> String {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or_else(format::local_now, |d| format::local(d.as_secs()))
}

fn profile_section(name: &str, path: &Path, comment: Option<String>, added: &str) -> Section {
    let mut entries = vec![("config".to_string(), path.display().to_string())];
    // A value has to fit on one line.
    if let Some(comment) = comment.filter(|c| !c.contains('\n')) {
        entries.push(("comment".to_string(), comment));
    }
    entries.push(("added".to_string(), added.to_string()));
    Section { name: name.to_string(), entries }
}

/// `[Section]` headers and `key = value` lines; `#` starts a comment line.
/// Values run to the end of the line, so paths may contain `#` or `=`.
fn parse_index(text: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sections.push(Section { name: name.trim().to_string(), entries: Vec::new() });
        } else if let (Some(section), Some((key, value))) = (sections.last_mut(), line.split_once('=')) {
            section.entries.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    sections
}

fn format_index(sections: &[Section]) -> String {
    let mut out = INDEX_HEADER.to_string();
    for section in sections {
        out.push_str(&format!("\n[{}]\n", section.name));
        for (key, value) in &section.entries {
            out.push_str(&format!("{key} = {value}\n"));
        }
    }
    out
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

    const CONF: &str = "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/32\n\
                        [Peer]\nPublicKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nEndpoint = vpn.invalid:51820\nAllowedIPs = 0.0.0.0/0\n";

    fn temp_store(tag: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("wg-gui-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let store = Store { dir };
        store.prepare().unwrap();
        store
    }

    #[test]
    fn import_indexes_dedupes_and_deletes() {
        let store = temp_store("import");
        assert_eq!(store.import("Office", "a", Some(Path::new("/tmp/office.conf"))).unwrap(), "Office");
        assert_eq!(store.import("office", "b", None).unwrap(), "office (2)");
        let profiles = store.list();
        let names: Vec<_> = profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["Office", "office (2)"]);
        assert_eq!(profiles[0].path, store.dir.join("profiles/Office.conf"));
        assert_eq!(profiles[0].comment.as_deref(), Some("Imported from /tmp/office.conf"));
        assert!(profiles[0].added.as_deref().is_some_and(|a| a.len() == "2026-10-04T18:00:00+06:00".len()));
        assert_eq!(fs::read_to_string(&profiles[1].path).unwrap(), "b");

        let index = fs::read_to_string(store.index_path()).unwrap();
        assert!(index.contains("[Office]\nconfig = ") && index.contains("comment = Imported from /tmp/office.conf\nadded = "));

        store.delete("Office").unwrap();
        assert_eq!(store.list().len(), 1);
        assert!(!store.dir.join("profiles/Office.conf").exists());

        assert_eq!(store.import("Home", CONF, None).unwrap(), "Home");
        assert_eq!(store.find_duplicate(CONF).as_deref(), Some("Home"));
        assert!(store.import("Other", &format!("# copy\n{CONF}"), None).unwrap_err().contains("already exists"));

        store.log_event("connected \"Home\"");
        assert!(fs::read_to_string(store.dir.join(LOG_NAME)).unwrap().contains("connected \"Home\""));
        fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn loose_configs_are_adopted() {
        let store = temp_store("adopt");
        fs::write(store.dir.join("Jobaer.conf"), CONF).unwrap();
        store.prepare().unwrap();
        let profiles = store.list();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "Jobaer");
        assert_eq!(profiles[0].path, store.dir.join("profiles/Jobaer.conf"));
        assert!(profiles[0].summary.is_ok());
        assert!(!store.dir.join("Jobaer.conf").exists());
        // Opening again changes nothing.
        store.prepare().unwrap();
        assert_eq!(store.list().len(), 1);
        fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn unlisted_files_are_deleted() {
        let store = temp_store("unlisted");
        store.import("Kept", CONF, None).unwrap();
        fs::write(store.dir.join("profiles/Stray.conf"), CONF).unwrap();
        // An entry pointing elsewhere is stale and protects nothing.
        let index = fs::read_to_string(store.index_path()).unwrap().replace("Kept.conf", "Kept2.conf");
        fs::write(store.index_path(), format!("{index}\n[Linked]\nconfig = {}/../profiles/Linked.conf\n", store.profiles_dir().display())).unwrap();
        fs::write(store.dir.join("profiles/Linked.conf"), CONF).unwrap();
        store.prepare().unwrap();
        assert!(!store.dir.join("profiles/Stray.conf").exists());
        assert!(!store.dir.join("profiles/Kept.conf").exists());
        assert!(store.dir.join("profiles/Linked.conf").exists());
        let names: Vec<_> = store.list().into_iter().map(|p| (p.name, p.stale)).collect();
        assert_eq!(names, [("Kept".to_string(), true), ("Linked".to_string(), false)]);
        fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn unreadable_index_deletes_nothing() {
        let store = temp_store("unreadable");
        fs::write(store.dir.join("profiles/A.conf"), CONF).unwrap();
        fs::create_dir(store.index_path()).unwrap(); // reading it fails
        assert!(store.prepare().is_err());
        assert!(store.dir.join("profiles/A.conf").exists());
        fs::remove_dir_all(&store.dir).unwrap();
    }

    #[test]
    fn missing_config_is_stale_and_deletable() {
        let store = temp_store("stale");
        store.import("Gone", CONF, None).unwrap();
        fs::remove_file(store.dir.join("profiles/Gone.conf")).unwrap();
        let profiles = store.list();
        assert_eq!(profiles.len(), 1);
        assert!(profiles[0].stale && profiles[0].summary.is_err());
        store.delete("Gone").unwrap();
        assert!(store.list().is_empty());
        fs::remove_dir_all(&store.dir).unwrap();
    }

    /// A home folder with `.wg-gui` as an older version left it.
    fn old_home(tag: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!("wg-gui-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let old = home.join(OLD_DIR);
        fs::create_dir_all(old.join("profiles")).unwrap();
        fs::write(old.join("profiles/A.conf"), CONF).unwrap();
        let index = format!(
            "[A]\nconfig = {}\ncomment = mine\nadded = 2026-10-06T11:48:48+06:00\n",
            old.join("profiles/A.conf").display()
        );
        fs::write(old.join(INDEX_NAME), index).unwrap();
        home
    }

    #[test]
    fn old_folder_is_moved_and_paths_rewritten() {
        let home = old_home("move");
        let store = Store { dir: home.join(CONFIG_DIR) };
        store.move_old_dir(&home.join(OLD_DIR)).unwrap();
        store.prepare().unwrap();
        assert!(!home.join(OLD_DIR).exists());
        let profiles = store.list();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].path, home.join(".config/wg-gui/profiles/A.conf"));
        assert!(!profiles[0].stale);
        assert_eq!(profiles[0].comment.as_deref(), Some("mine"));
        assert_eq!(profiles[0].added.as_deref(), Some("2026-10-06T11:48:48+06:00"));
        // A second start changes nothing.
        store.move_old_dir(&home.join(OLD_DIR)).unwrap();
        assert_eq!(store.list()[0].path, profiles[0].path);
        fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn both_folders_leaves_old_alone() {
        let home = old_home("both");
        let store = Store { dir: home.join(CONFIG_DIR) };
        store.prepare().unwrap();
        store.move_old_dir(&home.join(OLD_DIR)).unwrap();
        assert!(home.join(".wg-gui/profiles/A.conf").exists());
        assert!(store.list().is_empty());
        fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn index_keeps_unknown_sections() {
        let text = "# note\n[Settings]\nTheme = dark\n\n[A]\nconfig = /x/a#1=b.conf\n";
        let sections = parse_index(text);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].profile_name(), None);
        assert_eq!(sections[1].profile_name(), Some("A"));
        assert_eq!(sections[1].get("Config"), Some("/x/a#1=b.conf"));
        assert_eq!(parse_index(&format_index(&sections)), sections);
    }
}
