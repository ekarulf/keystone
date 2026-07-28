//! Locate the Swift runtime's compatibility shims.
//!
//! `cryptokit-rs` compiles a Swift bridge and links it statically. Swift emits
//! `__swift_FORCE_LOAD_$_swiftCompatibility*` references into every object file,
//! which resolve against `libswiftCompatibility*.a`. `cryptokit-rs`'s own build
//! script only searches `<developer-dir>/Toolchains/XcodeDefault.xctoolchain/...`,
//! which exists in a full Xcode install but not in Command Line Tools — there the
//! archives are at `<developer-dir>/usr/lib/swift/macosx`. Without this the link
//! fails with "Could not find or use auto-linked library 'swiftCompatibility56'",
//! which says nothing about Xcode layout.
//!
//! Adding a search path is additive: if `cryptokit-rs` already found the
//! libraries, this changes nothing.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        // Nothing to link: the crate compiles to a fail-closed stub off macOS.
        return;
    }

    let Some(developer_dir) = developer_dir() else {
        // Not fatal here. If the Swift toolchain is genuinely missing,
        // `cryptokit-rs`'s build script reports it with a better message.
        println!("cargo:warning=xcode-select -p failed; not adding a Swift runtime search path");
        return;
    };

    for candidate in [
        // Command Line Tools layout.
        format!("{developer_dir}/usr/lib/swift/macosx"),
        // Full Xcode layout, for completeness.
        format!("{developer_dir}/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx"),
    ] {
        if Path::new(&candidate).is_dir() {
            println!("cargo:rustc-link-search=native={candidate}");
        }
    }
}

fn developer_dir() -> Option<String> {
    let output = Command::new("xcode-select").arg("-p").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!path.is_empty()).then_some(path)
}
