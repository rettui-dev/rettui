//! Which commit this build was made from (see `build.rs`), for the Status
//! page: a short hash that links to the commit on GitHub, or to the release
//! when the build is exactly a tagged one.

use serde_json::{Value, json};

/// The first characters of the hash shown.
const SHORT: usize = 7;

/// A commit and tag as the build recorded them, and the version they are
/// checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    commit: String,
    tag: String,
    dirty: bool,
    version: String,
}

/// This build.
pub fn current() -> Build {
    Build::new(env!("RETTUI_BUILD_COMMIT"), env!("RETTUI_BUILD_TAG"), env!("RETTUI_BUILD_DIRTY") == "1", env!("CARGO_PKG_VERSION"))
}

impl Build {
    pub fn new(commit: &str, tag: &str, dirty: bool, version: &str) -> Self {
        // Whatever isn't a full hash (it may come from an environment
        // variable) is not used, so no broken link is made from it.
        let commit = commit.trim().to_ascii_lowercase();
        let known = matches!(commit.len(), 40 | 64) && commit.bytes().all(|b| b.is_ascii_hexdigit());
        Self { commit: if known { commit } else { String::new() }, tag: tag.trim().to_string(), dirty, version: version.to_string() }
    }

    /// The full hash, if known.
    pub fn commit(&self) -> Option<&str> {
        (!self.commit.is_empty()).then_some(self.commit.as_str())
    }

    /// The first 7 characters of the hash, with `-dirty` after them if the
    /// source had changes, or "unknown".
    pub fn short(&self) -> String {
        match self.commit() {
            Some(commit) if self.dirty => format!("{}-dirty", &commit[..SHORT]),
            Some(commit) => commit[..SHORT].to_string(),
            None => "unknown".to_string(),
        }
    }

    /// Whether this is exactly the tagged release of its version.
    pub fn is_release(&self) -> bool {
        !self.dirty && self.tag == format!("v{}", self.version)
    }

    /// Where to read about this build on GitHub: the release if it is one,
    /// else its commit (with `len` characters of the hash at most; GitHub
    /// takes a short one too). None when it's unknown or changed.
    pub fn url_with(&self, len: usize) -> Option<String> {
        let project = crate::config::PROJECT_URL;
        if self.is_release() {
            return Some(format!("{project}/releases/tag/{}", self.tag));
        }
        let commit = self.commit().filter(|_| !self.dirty)?;
        Some(format!("{project}/commit/{}", &commit[..len.clamp(SHORT, commit.len())]))
    }

    /// The link with the whole hash.
    pub fn url(&self) -> Option<String> {
        self.url_with(usize::MAX)
    }

    /// For the web UI.
    pub fn json(&self) -> Value {
        json!({ "commit": self.commit(), "short": self.short(), "url": self.url(), "release": self.is_release(), "dirty": self.dirty })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn a_commit_gets_a_short_hash_and_a_link() {
        let build = Build::new(SHA, "", false, "2.1.0");
        assert_eq!(build.short(), "0123456");
        assert!(!build.is_release());
        assert_eq!(build.url().unwrap(), format!("{}/commit/{SHA}", crate::config::PROJECT_URL));
        assert!(build.url_with(7).unwrap().ends_with("/commit/0123456"));
        assert!(build.url_with(3).unwrap().ends_with("/commit/0123456"));
        assert_eq!(build.url_with(1000), build.url());
    }

    #[test]
    fn the_tag_of_this_version_links_to_the_release() {
        let build = Build::new(SHA, "v2.1.0", false, "2.1.0");
        assert!(build.is_release());
        assert_eq!(build.short(), "0123456");
        assert_eq!(build.url().unwrap(), format!("{}/releases/tag/v2.1.0", crate::config::PROJECT_URL));
        // Any other tag, or none at all, is only a commit.
        assert!(!Build::new(SHA, "v2.0.0", false, "2.1.0").is_release());
        assert!(!Build::new(SHA, "2.1.0", false, "2.1.0").is_release());
        assert!(Build::new(SHA, "v2.0.0", false, "2.1.0").url().unwrap().contains("/commit/"));
    }

    #[test]
    fn changed_or_unknown_sources_have_no_link() {
        let dirty = Build::new(SHA, "v2.1.0", true, "2.1.0");
        assert_eq!((dirty.short().as_str(), dirty.url(), dirty.is_release()), ("0123456-dirty", None, false));
        let unknown = Build::new("", "", false, "2.1.0");
        assert_eq!((unknown.short().as_str(), unknown.url(), unknown.commit()), ("unknown", None, None));
        // A tag without a commit still names its release.
        assert!(Build::new("", "v2.1.0", false, "2.1.0").url().unwrap().ends_with("/releases/tag/v2.1.0"));
    }

    #[test]
    fn what_is_not_a_hash_is_not_used() {
        for bad in ["abc", "0123456", "zz23456789abcdef0123456789abcdef01234567", &format!("{SHA}0"), "../../x"] {
            let build = Build::new(bad, "", false, "2.1.0");
            assert_eq!((build.commit(), build.url()), (None, None), "{bad}");
        }
        let upper = Build::new(&SHA.to_uppercase(), "", false, "2.1.0");
        assert_eq!(upper.commit(), Some(SHA));
        assert_eq!(Build::new(&format!(" {SHA}\n"), "", false, "2.1.0").commit(), Some(SHA));
    }

    #[test]
    fn it_says_what_the_web_ui_needs() {
        let json = Build::new(SHA, "v2.1.0", false, "2.1.0").json();
        assert_eq!(json["commit"], SHA);
        assert_eq!(json["short"], "0123456");
        assert_eq!(json["release"], true);
        assert!(json["url"].as_str().unwrap().ends_with("/releases/tag/v2.1.0"));
        let none = Build::new("", "", false, "2.1.0").json();
        assert!(none["commit"].is_null() && none["url"].is_null());
    }

    #[test]
    fn this_build_is_consistent() {
        let build = current();
        assert_eq!(build.short() == "unknown", build.commit().is_none());
    }
}
