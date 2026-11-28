//! Records which commit this build was made from, for the Status page.
//!
//! The commit comes from `RETTUI_COMMIT` (and the tag from `RETTUI_TAG`)
//! when set, for builds that have no `.git` (Docker, packages). Otherwise
//! it is asked of git. With neither, it is left empty and the Status page
//! says "unknown": a build from a source tarball works as before.

use std::path::Path;
use std::process::Command;

/// What git prints for `args` in this package's folder, if it works.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    Some(text.trim().to_string())
}

/// Whether this package is itself tracked by the git repository around it
/// (not a copy unpacked inside some other checkout).
fn in_own_repository() -> bool {
    git(&["ls-files", "--error-unmatch", "Cargo.toml"]).is_some()
}

fn main() {
    println!("cargo:rerun-if-env-changed=RETTUI_COMMIT");
    println!("cargo:rerun-if-env-changed=RETTUI_TAG");
    println!("cargo:rerun-if-changed=build.rs");

    let given = |name: &str| std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let (mut commit, mut tag, mut dirty) = (given("RETTUI_COMMIT"), given("RETTUI_TAG"), false);

    if commit.is_none() && in_own_repository() {
        commit = git(&["rev-parse", "HEAD"]);
        if tag.is_none() {
            tag = git(&["describe", "--exact-match", "--tags", "HEAD"]);
        }
        // Changes to tracked files (the build is then not that commit).
        dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_none_or(|s| !s.is_empty());
        // A new commit, branch switch or tag changes the build; so does an edit.
        if let Some(dir) = git(&["rev-parse", "--git-dir"]) {
            println!("cargo:rerun-if-changed={}", Path::new(&dir).join("HEAD").display());
        }
        if let Some(dir) = git(&["rev-parse", "--git-common-dir"]) {
            for name in ["refs", "packed-refs"] {
                println!("cargo:rerun-if-changed={}", Path::new(&dir).join(name).display());
            }
        }
        println!("cargo:rerun-if-changed=src");
        println!("cargo:rerun-if-changed=Cargo.toml");
        println!("cargo:rerun-if-changed=Cargo.lock");
    }

    println!("cargo:rustc-env=RETTUI_BUILD_COMMIT={}", commit.unwrap_or_default());
    println!("cargo:rustc-env=RETTUI_BUILD_TAG={}", tag.unwrap_or_default());
    println!("cargo:rustc-env=RETTUI_BUILD_DIRTY={}", if dirty { "1" } else { "0" });
}
