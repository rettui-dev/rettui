//! One rettui at a time per data directory. A second one would put back a
//! Reticulum config change (see `remote_manage`) that the first still has on
//! probation, and both would write the same files. A file system with no file
//! locks (some network and FUSE mounts, some volume drivers) can't hold the
//! lock: that is said in the log, and rettui carries on without it.

use anyhow::{Context, Result, bail};
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

/// The lock file's name, in the data directory itself.
const FILE: &str = "rettui.lock";

/// The data directory, locked for as long as this is kept (the operating
/// system lets go of it if the process ends in any way).
#[derive(Debug)]
pub struct InstanceLock {
    /// `None` where the file system takes no locks.
    _file: Option<File>,
    /// Why there is no lock, to say once the log is set up (it isn't yet when
    /// the lock is taken).
    warning: Option<String>,
}

/// Whether `e` says the file system can't lock files at all (as opposed to
/// the file being locked by another process).
fn no_locks_here(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        if matches!(e.raw_os_error(), Some(code) if [libc::ENOLCK, libc::ENOSYS, libc::EOPNOTSUPP, libc::ENOTSUP].contains(&code)) {
            return true;
        }
    }
    e.kind() == std::io::ErrorKind::Unsupported
}

impl InstanceLock {
    /// Lock the data directory `root` (`Paths::root`), or say that another
    /// rettui has it.
    pub fn take(root: &Path) -> Result<Self> {
        let path: PathBuf = root.join(FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(&path).with_context(|| format!("opening {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: Some(file), warning: None }),
            Err(TryLockError::WouldBlock) => bail!(
                "Another rettui is using the data directory {}. Stop it first, or give this one its own with --data-dir.",
                root.display()
            ),
            Err(TryLockError::Error(e)) if no_locks_here(&e) => Ok(Self::unlocked(&path, root, &e)),
            Err(TryLockError::Error(e)) => Err(e).with_context(|| format!("locking {}", path.display())),
        }
    }

    /// A lock that couldn't be had because `e` says the file system takes none.
    fn unlocked(path: &Path, root: &Path, e: &std::io::Error) -> Self {
        let warning = format!(
            "{} can't be locked ({e}), so rettui can't tell whether another one uses {}: don't run two on it",
            path.display(),
            root.display()
        );
        Self { _file: None, warning: Some(warning) }
    }

    /// What to say of the lock, if it couldn't be taken.
    pub fn warning(&self) -> Option<&str> {
        self.warning.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rettui-lock-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_second_instance_is_turned_away_until_the_first_is_gone() {
        let dir = temp("second");
        let first = InstanceLock::take(&dir).unwrap();
        let said = InstanceLock::take(&dir).unwrap_err().to_string();
        assert!(said.contains("Another rettui is using the data directory"), "{said}");
        assert!(said.contains(&dir.display().to_string()), "{said}");
        drop(first);
        InstanceLock::take(&dir).expect("free again once the first is dropped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn other_data_directories_are_not_affected() {
        let (a, b) = (temp("a"), temp("b"));
        let _first = InstanceLock::take(&a).unwrap();
        InstanceLock::take(&b).unwrap();
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn a_file_system_without_locks_is_carried_on_without_one() {
        let unsupported = std::io::Error::from(std::io::ErrorKind::Unsupported);
        assert!(no_locks_here(&unsupported));
        #[cfg(unix)]
        for code in [libc::ENOLCK, libc::EOPNOTSUPP, libc::ENOSYS] {
            assert!(no_locks_here(&std::io::Error::from_raw_os_error(code)), "{code}");
        }
        // Other failures, and a lock held, aren't that.
        assert!(!no_locks_here(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)));
        assert!(!no_locks_here(&std::io::Error::from(std::io::ErrorKind::WouldBlock)));
        // The warning is kept for after the log is set up, and a real lock has none.
        let lock = InstanceLock::unlocked(Path::new("/data/rettui.lock"), Path::new("/data"), &unsupported);
        assert!(lock.warning().unwrap().contains("/data/rettui.lock") && lock.warning().unwrap().contains("don't run two"));
        let dir = temp("warning");
        assert!(InstanceLock::take(&dir).unwrap().warning().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_directory_is_an_error_not_a_panic() {
        let dir = temp("missing").join("nope");
        assert!(InstanceLock::take(&dir).is_err());
    }
}
