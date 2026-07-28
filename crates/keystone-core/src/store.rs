//! Reading and writing Keystone's local files.
//!
//! Every write goes through [`write_atomic`], so an interrupted run cannot
//! leave a half-written config file or identity record behind.

use std::path::{Path, PathBuf};

use crate::config::{check_not_group_or_world_writable, Config, Paths, DIR_MODE, FILE_MODE};
use crate::error::{KeystoneError, Result};
use crate::identity::{IdentityMetadata, KeyId, Sha256Fingerprint};

/// A handle to Keystone's on-disk state.
#[derive(Debug, Clone)]
pub struct Store {
    paths: Paths,
    /// Set by `--allow-unsafe-permissions`; only relaxes the permission check,
    /// never the content validation.
    allow_unsafe_permissions: bool,
}

impl Store {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            allow_unsafe_permissions: false,
        }
    }

    pub fn allow_unsafe_permissions(mut self, allow: bool) -> Self {
        self.allow_unsafe_permissions = allow;
        self
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// Load `config.toml`, or an empty configuration if it does not exist yet.
    ///
    /// A missing file is not an error: `keystone init` and `keystone bootstrap`
    /// both have to work on a machine that has never run Keystone.
    pub fn load_config(&self) -> Result<Config> {
        let path = self.paths.config_file();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                if !self.allow_unsafe_permissions {
                    check_not_group_or_world_writable(&path)?;
                }
                Config::parse(&text).map_err(|e| match e {
                    KeystoneError::InvalidConfiguration(message) => {
                        KeystoneError::InvalidConfiguration(format!(
                            "{}: {message}",
                            path.display()
                        ))
                    }
                    other => other,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(KeystoneError::io(
                format!("cannot read {}", path.display()),
                e,
            )),
        }
    }

    pub fn save_config(&self, config: &Config) -> Result<()> {
        config.validate()?;
        let path = self.paths.config_file();
        self.write_owned(&path, config.render()?.as_bytes())
    }

    /// Write one of Keystone's own files, making its directory private first.
    ///
    /// [`write_atomic`] alone leaves the directory to the umask, because it also
    /// serves output paths the user named. Everything under Keystone's data
    /// directory is Keystone's, and a directory another user can list reveals
    /// which identities and profiles exist.
    fn write_owned(&self, path: &Path, contents: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent().filter(|parent| *parent != Path::new("")) {
            create_dir_all_private(parent)?;
        }
        write_atomic(path, contents)
    }

    pub fn load_identity(&self, key_id: &KeyId) -> Result<IdentityMetadata> {
        let path = self.paths.identity_file(key_id);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KeystoneError::KeyUnavailable
            } else {
                KeystoneError::io(format!("cannot read {}", path.display()), e)
            }
        })?;
        let metadata: IdentityMetadata = serde_json::from_str(&text)
            .map_err(|e| KeystoneError::InvalidConfiguration(format!("{}: {e}", path.display())))?;
        metadata.validate()?;
        if metadata.key_id != *key_id {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "{} records key id {} but was loaded as {key_id}",
                path.display(),
                metadata.key_id
            )));
        }
        Ok(metadata)
    }

    pub fn save_identity(&self, metadata: &IdentityMetadata) -> Result<()> {
        metadata.validate()?;
        let path = self.paths.identity_file(&metadata.key_id);
        let json = serde_json::to_string_pretty(metadata)
            .map_err(|e| KeystoneError::Other(format!("cannot serialize identity: {e}")))?;
        self.write_owned(&path, json.as_bytes())
    }

    /// List the identities present on this machine.
    pub fn list_identities(&self) -> Result<Vec<KeyId>> {
        let dir = self.paths.identities_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(KeystoneError::io(
                    format!("cannot list {}", dir.display()),
                    e,
                ))
            }
        };
        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry
                .map_err(|e| KeystoneError::io(format!("cannot list {}", dir.display()), e))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(stem) = name.strip_suffix(".json") {
                if let Ok(key_id) = KeyId::parse(stem) {
                    ids.push(key_id);
                }
            }
        }
        ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(ids)
    }

    /// Store a device certificate and the CA that issued it.
    ///
    /// Both are public DER. They live under the leaf's own fingerprint so that a
    /// rotation can write the new pair without disturbing the old one, which
    /// `keystone rotate` needs for its rollback window.
    pub fn save_certificates(
        &self,
        fingerprint: &Sha256Fingerprint,
        leaf_der: &[u8],
        ca_der: &[u8],
    ) -> Result<()> {
        let dir = self.paths.certificate_dir(fingerprint);
        self.write_owned(&dir.join("leaf.der"), leaf_der)?;
        self.write_owned(&dir.join("ca.der"), ca_der)
    }

    /// Read back the certificate pair recorded for `fingerprint`.
    ///
    /// Returns `(leaf, ca)` DER. A missing pair is
    /// [`KeystoneError::InvalidConfiguration`] naming the path rather than a bare
    /// I/O error, because the actionable cause is an unfinished enrollment.
    pub fn load_certificates(&self, fingerprint: &Sha256Fingerprint) -> Result<(Vec<u8>, Vec<u8>)> {
        let dir = self.paths.certificate_dir(fingerprint);
        let read = |name: &str| -> Result<Vec<u8>> {
            let path = dir.join(name);
            std::fs::read(&path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    KeystoneError::InvalidConfiguration(format!(
                        "{} is missing. Run `keystone bootstrap` or `keystone enroll install` \
                         to record the certificate.",
                        path.display()
                    ))
                } else {
                    KeystoneError::io(format!("cannot read {}", path.display()), e)
                }
            })
        };
        Ok((read("leaf.der")?, read("ca.der")?))
    }

    /// Remove a stored certificate pair.
    pub fn delete_certificates(&self, fingerprint: &Sha256Fingerprint) -> Result<()> {
        let dir = self.paths.certificate_dir(fingerprint);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeystoneError::io(
                format!("cannot remove {}", dir.display()),
                e,
            )),
        }
    }

    /// Remove an identity's metadata, which makes its Secure Enclave key unusable.
    pub fn delete_identity(&self, key_id: &KeyId) -> Result<()> {
        let path = self.paths.identity_file(key_id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeystoneError::io(
                format!("cannot remove {}", path.display()),
                e,
            )),
        }
    }
}

/// Create a directory and its parents with restrictive permissions.
///
/// For directories Keystone owns. Applying this to a directory the user named on
/// the command line would silently change who can read the rest of its contents,
/// so [`write_atomic`] uses [`create_dir_all`] instead.
pub fn create_dir_all_private(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| KeystoneError::io(format!("cannot create {}", path.display()), e))?;
    set_mode(path, DIR_MODE)
}

/// Create a directory and its parents, leaving permissions to the umask.
///
/// For output directories the user chose: `keystone bootstrap --output ./artifacts`
/// writes public certificates there, and the directory is theirs to share.
pub fn create_dir_all(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| KeystoneError::io(format!("cannot create {}", path.display()), e))
}

/// Write a file atomically, with owner-only permissions.
///
/// The temporary file is created in the destination directory so the rename
/// stays within one filesystem, and it is named after the process so two
/// concurrent Keystone runs cannot collide on it.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        KeystoneError::Other(format!("{} has no parent directory", path.display()))
    })?;
    // A bare relative path like `device.csr` has an empty parent, which names the
    // current directory rather than nothing at all — creating it is neither
    // possible nor needed.
    //
    // The directory's mode is left to the umask: `write_atomic` serves both
    // Keystone's own files and files the user asked for by path, and the callers
    // that own their directories (see [`Store`]) make them private themselves.
    // The file is 0600 either way, which is what protects the contents.
    if parent != Path::new("") {
        create_dir_all(parent)?;
    }

    let temp = temp_path_for(path);
    write_private(&temp, contents)?;

    match std::fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Leaving the temporary file behind would be worse than the error.
            std::fs::remove_file(&temp).ok();
            Err(KeystoneError::io(
                format!("cannot replace {}", path.display()),
                e,
            ))
        }
    }
}

fn temp_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "keystone".to_string());
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{name}.{}.tmp", std::process::id()))
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            // Set the mode at creation so the contents are never briefly
            // readable by another user.
            .mode(FILE_MODE)
            .open(path)
            .map_err(|e| KeystoneError::io(format!("cannot create {}", path.display()), e))?;
        file.write_all(contents)
            .map_err(|e| KeystoneError::io(format!("cannot write {}", path.display()), e))?;
        file.sync_all()
            .map_err(|e| KeystoneError::io(format!("cannot flush {}", path.display()), e))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
            .map_err(|e| KeystoneError::io(format!("cannot write {}", path.display()), e))
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
            KeystoneError::io(format!("cannot set permissions on {}", path.display()), e)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;
    use crate::identity::Sha256Fingerprint;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "keystone-store-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::remove_dir_all(&path).ok();
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn store(&self) -> Store {
            Store::new(Paths::rooted_at(&self.0))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn sample_identity() -> IdentityMetadata {
        let mut public_key = [0u8; 65];
        public_key[0] = 0x04;
        IdentityMetadata::new(
            KeyId::parse("019cabc").unwrap(),
            &public_key,
            b"opaque",
            time::macros::datetime!(2026-07-25 22:00:00 UTC),
        )
    }

    #[test]
    fn a_missing_configuration_reads_as_empty() {
        let dir = TempDir::new("missing");
        let config = dir.store().load_config().unwrap();
        assert!(config.profiles.is_empty());
        assert_eq!(config.version, crate::config::CONFIG_VERSION);
    }

    #[test]
    fn configuration_survives_a_save_and_load_cycle() {
        let dir = TempDir::new("roundtrip");
        let store = dir.store();
        let mut config = Config::default();
        config
            .profiles
            .insert("personal".to_string(), Profile::new("us-east-1"));
        store.save_config(&config).unwrap();

        let loaded = store.load_config().unwrap();
        assert_eq!(loaded.profile("personal").unwrap().region, "us-east-1");
    }

    #[test]
    fn a_saved_configuration_is_not_readable_by_other_users() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir = TempDir::new("perms");
            let store = dir.store();
            store.save_config(&Config::default()).unwrap();

            let path = store.paths().config_file();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, FILE_MODE, "config mode was {mode:04o}");

            let dir_mode = std::fs::metadata(store.paths().data_dir.as_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, DIR_MODE, "directory mode was {dir_mode:04o}");
        }
    }

    #[test]
    fn a_world_writable_configuration_is_refused_unless_overridden() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir = TempDir::new("unsafe");
            let store = dir.store();
            store.save_config(&Config::default()).unwrap();
            std::fs::set_permissions(
                store.paths().config_file(),
                std::fs::Permissions::from_mode(0o666),
            )
            .unwrap();

            assert!(store.load_config().is_err());
            // The override exists for users who know what they are doing.
            assert!(dir
                .store()
                .allow_unsafe_permissions(true)
                .load_config()
                .is_ok());
        }
    }

    #[test]
    fn a_malformed_configuration_names_the_file_in_the_error() {
        let dir = TempDir::new("malformed");
        let store = dir.store();
        create_dir_all_private(&store.paths().data_dir).unwrap();
        std::fs::write(store.paths().config_file(), "this is not toml {{{").unwrap();
        let error = store.load_config().unwrap_err().to_string();
        assert!(error.contains("config.toml"), "{error}");
    }

    #[test]
    fn identities_survive_a_save_and_load_cycle() {
        let dir = TempDir::new("identity");
        let store = dir.store();
        let metadata = sample_identity();
        store.save_identity(&metadata).unwrap();

        let loaded = store.load_identity(&metadata.key_id).unwrap();
        assert_eq!(loaded.key_id, metadata.key_id);
        assert_eq!(loaded.opaque_key_reference_bytes().unwrap(), b"opaque");
    }

    #[test]
    fn a_missing_identity_reports_the_key_as_unavailable() {
        let dir = TempDir::new("noidentity");
        let error = dir.store().load_identity(&KeyId::parse("nope").unwrap());
        assert!(matches!(error, Err(KeystoneError::KeyUnavailable)));
    }

    #[test]
    fn an_identity_file_holding_the_wrong_key_id_is_refused() {
        let dir = TempDir::new("mismatch");
        let store = dir.store();
        let metadata = sample_identity();
        // Write the record under a different name than it claims.
        let other = KeyId::parse("019cother").unwrap();
        let json = serde_json::to_string_pretty(&metadata).unwrap();
        write_atomic(&store.paths().identity_file(&other), json.as_bytes()).unwrap();
        assert!(store.load_identity(&other).is_err());
    }

    #[test]
    fn identities_are_listed_in_a_stable_order() {
        let dir = TempDir::new("list");
        let store = dir.store();
        assert!(store.list_identities().unwrap().is_empty());

        for id in ["019cccc", "019caaa", "019cbbb"] {
            let mut metadata = sample_identity();
            metadata.key_id = KeyId::parse(id).unwrap();
            store.save_identity(&metadata).unwrap();
        }
        let ids: Vec<String> = store
            .list_identities()
            .unwrap()
            .iter()
            .map(|k| k.to_string())
            .collect();
        assert_eq!(ids, ["019caaa", "019cbbb", "019cccc"]);
    }

    #[test]
    fn deleting_an_identity_is_idempotent() {
        let dir = TempDir::new("delete");
        let store = dir.store();
        let metadata = sample_identity();
        store.save_identity(&metadata).unwrap();
        store.delete_identity(&metadata.key_id).unwrap();
        // Deleting again is not an error: rotation may resume after a partial run.
        store.delete_identity(&metadata.key_id).unwrap();
        assert!(store.list_identities().unwrap().is_empty());
    }

    #[test]
    fn an_atomic_write_replaces_content_without_leaving_temporary_files() {
        let dir = TempDir::new("atomic");
        let path = dir.0.join("nested/deeper/file.txt");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");

        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    }

    #[test]
    fn a_bare_relative_path_writes_to_the_current_directory() {
        // `keystone enroll csr --output device.csr` produces a path whose parent
        // is the empty string, which names the current directory rather than a
        // directory to create.
        let dir = TempDir::new("relative");
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir.0).unwrap();
        let result = write_atomic(Path::new("device.csr"), b"csr");
        let written = std::fs::read(dir.0.join("device.csr"));
        std::env::set_current_dir(previous).unwrap();

        result.unwrap();
        assert_eq!(written.unwrap(), b"csr");
    }

    #[test]
    fn an_output_directory_the_user_named_keeps_its_own_permissions() {
        // `keystone bootstrap --output ./artifacts` writes public certificates to a
        // directory the user chose. Tightening it would quietly change who can read
        // the rest of its contents; the file itself is still private, which is what
        // protects the contents Keystone wrote.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let dir = TempDir::new("output-perms");
            let output = dir.0.join("artifacts");
            std::fs::create_dir(&output).unwrap();
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755)).unwrap();

            write_atomic(&output.join("ca.pem"), b"pem").unwrap();

            let mode = std::fs::metadata(&output).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "the user's directory mode changed");
            let file_mode = std::fs::metadata(output.join("ca.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, FILE_MODE);
        }
    }

    #[test]
    fn keystones_own_directories_are_private_even_under_a_lax_umask() {
        // The identities directory reveals which devices are enrolled, so it must
        // not be listable by another user regardless of the umask in effect.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let dir = TempDir::new("owned-perms");
            let store = dir.store();
            store.save_identity(&sample_identity()).unwrap();

            let mode = std::fs::metadata(store.paths().identities_dir())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, DIR_MODE, "identities directory mode was {mode:04o}");
        }
    }

    #[test]
    fn certificate_paths_are_namespaced_by_fingerprint() {
        let dir = TempDir::new("certs");
        let store = dir.store();
        let fingerprint = Sha256Fingerprint::of(b"leaf");
        let path = store.paths().certificate_dir(&fingerprint);
        assert!(path.ends_with(fingerprint.as_str()));
    }

    #[test]
    fn a_certificate_pair_round_trips() {
        let dir = TempDir::new("cert-roundtrip");
        let store = dir.store();
        let fingerprint = Sha256Fingerprint::of(b"leaf");
        store
            .save_certificates(&fingerprint, b"leaf-der", b"ca-der")
            .unwrap();

        let (leaf, ca) = store.load_certificates(&fingerprint).unwrap();
        assert_eq!(leaf, b"leaf-der");
        assert_eq!(ca, b"ca-der");

        store.delete_certificates(&fingerprint).unwrap();
        assert!(store.load_certificates(&fingerprint).is_err());
        // Deleting twice is not an error: rotation cleanup may run after a
        // partially completed switch.
        store.delete_certificates(&fingerprint).unwrap();
    }

    #[test]
    fn rotation_can_hold_two_certificate_pairs_at_once() {
        // The design's rollback window: the old anchor is retained briefly, so the
        // old certificate must still be readable after the new one is written.
        let dir = TempDir::new("cert-two");
        let store = dir.store();
        let old = Sha256Fingerprint::of(b"old-leaf");
        let new = Sha256Fingerprint::of(b"new-leaf");
        store.save_certificates(&old, b"old", b"old-ca").unwrap();
        store.save_certificates(&new, b"new", b"new-ca").unwrap();

        assert_eq!(store.load_certificates(&old).unwrap().0, b"old");
        assert_eq!(store.load_certificates(&new).unwrap().0, b"new");
    }

    #[test]
    fn a_missing_certificate_says_which_command_records_one() {
        let dir = TempDir::new("cert-missing");
        let store = dir.store();
        let error = store
            .load_certificates(&Sha256Fingerprint::of(b"absent"))
            .unwrap_err();
        let message = format!("{error}");
        assert!(message.contains("bootstrap"), "{message}");
        assert!(message.contains("leaf.der"), "{message}");
    }
}
