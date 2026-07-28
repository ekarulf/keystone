//! Shared access to the OpenSSL-generated fixtures in `tests/fixtures/`.
//!
//! The fixtures are produced by `tests/fixtures/generate.sh`, an independent
//! implementation, so a test that reads them is comparing Keystone against
//! OpenSSL rather than against itself. Loading them from disk (rather than
//! embedding them with `include_str!`) keeps the fixture set editable by
//! re-running the script.

use std::path::{Path, PathBuf};

/// The `tests/fixtures/` directory.
///
/// `CARGO_MANIFEST_DIR` points at `crates/keystone-tests`, so the fixtures are
/// two levels up. Resolved at compile time, which means a test binary run from
/// any working directory finds them.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .canonicalize()
        .expect("tests/fixtures exists; run tests/fixtures/generate.sh if it does not")
}

/// Read a fixture as text.
pub fn fixture(name: &str) -> String {
    let path = fixtures_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read fixture {}: {error}", path.display()))
}

/// The key ID carried by every device fixture's URI SAN.
///
/// Fixed in `generate.sh`, and repeated here because the golden expectations
/// depend on the exact SAN string.
pub const FIXTURE_KEY_ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The URI SAN the device fixtures carry.
pub const FIXTURE_SAN: &str = "urn:keystone:device:0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The valid device leaf's serial number, in the decimal form AWS expects in the
/// `Credential=` field.
pub const FIXTURE_LEAF_SERIAL_DECIMAL: &str = "88664422113355779";

/// The key ID as a [`keystone_core::identity::KeyId`].
pub fn fixture_key_id() -> keystone_core::identity::KeyId {
    keystone_core::identity::KeyId::parse(FIXTURE_KEY_ID).expect("fixture key id is well formed")
}

/// A directory under the system temporary directory, removed on drop.
///
/// The workspace has no `tempfile` dependency, and the crates' own tests each
/// hand-roll this; one copy here serves the suites that need a scratch tree.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        // The pointer address is unique among live allocations in this process,
        // and the process ID separates concurrent test binaries. No randomness is
        // needed: this only has to not collide.
        let marker = Box::new(0u8);
        let path = std::env::temp_dir().join(format!(
            "keystone-tests-{label}-{}-{:p}",
            std::process::id(),
            marker
        ));
        std::fs::create_dir_all(&path).expect("can create a scratch directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best effort: a leftover directory under /tmp is noise, not a failure,
        // and panicking here would mask the assertion that actually failed.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
