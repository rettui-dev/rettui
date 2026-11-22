//! Whether the node's announce stamp exists yet, so a Reticulum config change
//! is not tested before Reticulum can answer.
//!
//! rsReticulum puts a proof-of-work stamp on every announce, and on every
//! path response, which is what the self-test waits for ([`super::selftest`]).
//! One worker makes the stamp of the node's LXMF address; until it has, the
//! announces and path responses of that address are held. Once made it is
//! saved in Reticulum's storage folder (`stamps/<address>.dstamp`) and a
//! Reticulum that restarts, in this run or the next, loads it from there. A
//! restart that comes before the stamp is done throws the work away, so a
//! change applied in the meantime is tested against a Reticulum that can't
//! answer yet, and put back, however good it is.
//!
//! The saved file is the only thing rsReticulum's public interface shows of
//! this: there is no call that says a stamp is being made or how far it is.

use std::fs::OpenOptions;
use std::future::Future;
use std::io::Read;
use std::path::Path;
use std::pin::Pin;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};

use rns_identity::destination::{DestType, Destination, Direction, STAMP_FILE_VERSION, destination_stamp_path};
use rns_identity::identity::Identity;
use rns_identity::stamps::{NETWORK_STAMP_SIZE, stamp_valid};
use rns_runtime::config::Config;
use rns_runtime::destination_stamper::{self, DestinationStamp};
use rns_runtime::platform::StoragePaths;
use rns_runtime::reticulum::ReticulumConfig;
use rns_transport::stamps::StampPolicy;

/// A stamp of this value or less (bits of work, about 2^18 = 260,000 hashes)
/// is made within seconds even on a small device (at 50,000 hashes a second
/// it takes 5 seconds, and four times that is still a quarter of the 90
/// seconds a restart has to come back and answer), so a Reticulum restarted
/// with it needs no waiting for. The default of 25 is 128 times that.
pub const CHEAP_VALUE: f64 = 18.0;

/// A stamp being made for the node's address, ahead of the restart that needs
/// it. Dropping it stops the work if it isn't done.
pub struct Making {
    job: Job,
    /// The job was seen to have ended. A future is not polled again after it
    /// has finished (an `async` one panics when it is), so this is kept.
    done: bool,
}

enum Job {
    /// The stamper's own job, as a future that is looked at without waiting.
    Real(Pin<Box<dyn Future<Output = Option<DestinationStamp>> + Send>>),
    /// A job a test says has ended when the flag is `true`.
    #[cfg(test)]
    Test(Arc<AtomicBool>),
}

impl std::fmt::Debug for Making {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Making")
    }
}

impl Making {
    /// Whether the job has ended, with the stamp saved or without (it failed
    /// or was cancelled): a job that has ended makes nothing more, so a stamp
    /// that is still not saved needs another.
    pub fn ended(&mut self) -> bool {
        if self.done {
            return true;
        }
        self.done = match &mut self.job {
            Job::Real(job) => job.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_ready(),
            #[cfg(test)]
            Job::Test(ended) => ended.load(Ordering::SeqCst),
        };
        self.done
    }
}

/// How the node finds out whether its stamp is made (fixed answers, in tests).
///
/// A test that starts Reticulum itself makes its stamps cheap, but not before
/// its first request, so a test asks for the check it wants and has none by
/// default.
#[derive(Debug, Clone, Default)]
pub enum StampCheck {
    /// Look for the saved stamp.
    #[cfg_attr(not(test), default)]
    Saved,
    /// Always made.
    #[cfg(test)]
    #[default]
    Skip,
    /// Made while the first flag is `true`; counts the times a stamp was
    /// started, and the job started ends when the last flag is `true`.
    #[cfg(test)]
    Fixed(Arc<AtomicBool>, Arc<AtomicUsize>, Arc<AtomicBool>),
    /// Never made; the job started ends at once, as a real future that has finished (counted).
    #[cfg(test)]
    Finishing(Arc<AtomicUsize>),
}

impl StampCheck {
    /// Whether a Reticulum restarted with the config `after` can answer a
    /// path request for `address` (the node's LXMF address, of the identity
    /// with `public_key`) without waiting for a stamp. `config` is the
    /// Reticulum config file in use.
    pub fn ready(&self, config: &Path, address: &[u8; 16], public_key: &[u8; 64], after: &str) -> bool {
        match self {
            Self::Saved => saved(&destination_stamper::policy(), config, address, public_key, after, CHEAP_VALUE),
            #[cfg(test)]
            Self::Skip => true,
            #[cfg(test)]
            Self::Fixed(made, ..) => made.load(Ordering::SeqCst),
            #[cfg(test)]
            Self::Finishing(_) => false,
        }
    }

    /// Make sure a stamp for the address is being made: Reticulum starts one
    /// only when it announces or is asked for a path, which a node that
    /// doesn't announce may not do for a long time. The work is the running
    /// Reticulum's own (its policy and storage folder), and a job already
    /// running for the address makes the new one find the saved stamp at once.
    /// `None` where nothing was started (no stamps, a full queue, something in the stamp's place that
    /// isn't a plain file, a test).
    pub fn start(&self, config: &Path, address: &[u8; 16], public_key: &[u8; 64]) -> Option<Making> {
        match self {
            Self::Saved => {
                let (identity, destination) = destination_of(address, public_key)?;
                // Reticulum's one stamper thread opens the stamp file and waits there if it is a pipe:
                // nothing is queued for it while something that is not a plain file is in the way.
                if blocked(config, &destination) {
                    return None;
                }
                destination_stamper::prepare(&destination, &identity)
                    .map(|job| Making { job: Job::Real(Box::pin(job.ready())), done: false })
            }
            #[cfg(test)]
            Self::Skip => None,
            #[cfg(test)]
            Self::Finishing(starts) => {
                starts.fetch_add(1, Ordering::SeqCst);
                Some(Making { job: Job::Real(Box::pin(async { None })), done: false })
            }
            #[cfg(test)]
            Self::Fixed(_, starts, ended) => {
                starts.fetch_add(1, Ordering::SeqCst);
                Some(Making { job: Job::Test(ended.clone()), done: false })
            }
        }
    }
}

/// The node's LXMF destination, from its public key, if `address` is its hash.
fn destination_of(address: &[u8; 16], public_key: &[u8; 64]) -> Option<(Identity, Destination)> {
    let identity = Identity::from_public_key(public_key).ok()?;
    let destination = Destination::new(Some(&identity), Direction::Out, DestType::Single, crate::lxmf::LXMF_ASPECT).ok()?;
    (destination.hash == *address).then_some((identity, destination))
}

/// [`StampCheck::ready`] by the saved stamp, with the stamp policy of the
/// Reticulum that runs now, and `cheap` the value up to which no stamp is
/// waited for.
///
/// Where this can't tell, or waiting could not help, it says yes: a
/// Reticulum that makes no stamps has none to wait for, and one that does
/// not now makes none that would be saved for the next. So does a config
/// whose value is `cheap` or less: the restarted Reticulum makes that stamp
/// in seconds, well inside the self-test, saved or not. (A remote change
/// can't set `[stamps]`: that value is set in the node's own config, from the
/// terminal, and then a change isn't waited for.) Otherwise the stamp must be
/// at least as strong as the lower of the two policies' values: the running
/// Reticulum only ever makes its own, so a change that raises the value is
/// not held for one that nothing is making.
fn saved(running: &StampPolicy, config: &Path, address: &[u8; 16], public_key: &[u8; 64], after: &str, cheap: f64) -> bool {
    if !running.stamp_destinations {
        return true;
    }
    let Ok(parsed) = Config::parse(after) else { return true };
    let Ok(next) = ReticulumConfig::try_from_config(&parsed) else { return true };
    if !next.stamps.stamp_destinations || next.stamps.destination_value <= cheap {
        return true;
    }
    let Some((_, destination)) = destination_of(address, public_key) else { return true };
    let Some(path) = stamp_path(config, &destination) else { return true };
    let target = destination.target_value(running.destination_value.min(next.stamps.destination_value));
    let Stamp::Bytes(data) = read_stamp(&path) else { return false };
    valid_stamp(&data, &destination.stamp_material(public_key), target)
}

/// Where Reticulum saves the stamp of `destination`, for the Reticulum config `config`.
fn stamp_path(config: &Path, destination: &Destination) -> Option<std::path::PathBuf> {
    let storage = StoragePaths::from_config_dir(config.parent()?).storage_dir;
    Some(destination_stamp_path(&storage, &destination.hash))
}

/// Whether something that isn't a plain file is at the stamp's place.
fn blocked(config: &Path, destination: &Destination) -> bool {
    stamp_path(config, destination).is_some_and(|path| read_stamp(&path) == Stamp::Other)
}

/// What is at a stamp's place.
#[derive(Debug, PartialEq, Eq)]
enum Stamp {
    Missing,
    /// A link, a pipe, a folder, a file that is too big or can't be read.
    Other,
    /// The bytes of a plain file.
    Bytes(Vec<u8>),
}

/// The longest stamp file rsReticulum reads.
const MAX_STAMP_FILE: usize = 1024;

/// Read what is at `path`, with one open of it and no wait: a link isn't followed
/// and a pipe doesn't block the open (the owner loop calls this), and what was
/// opened must be a plain file, whatever is put at the path afterwards.
fn read_stamp(path: &Path) -> Stamp {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Stamp::Missing,
        Err(_) => return Stamp::Other,
    };
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        return Stamp::Other;
    }
    let mut data = Vec::new();
    if file.take(MAX_STAMP_FILE as u64 + 1).read_to_end(&mut data).is_err() || data.len() > MAX_STAMP_FILE {
        return Stamp::Other;
    }
    Stamp::Bytes(data)
}

/// Whether `data` is a stamp file holding a stamp of `target` bits or more for
/// `material`: rsReticulum's `load_destination_stamp` (which opens the file
/// itself, and so can't be given what was read) on bytes already read.
fn valid_stamp(data: &[u8], material: &[u8], target: f64) -> bool {
    use rmpv::Value;
    let Ok(Value::Map(entry)) = rmpv::decode::read_value(&mut std::io::Cursor::new(data)) else { return false };
    let field = |name: &str| entry.iter().find(|(key, _)| key.as_str() == Some(name)).map(|(_, value)| value);
    let version_ok = match field("v") {
        Some(Value::Integer(v)) => v.as_u64() == Some(STAMP_FILE_VERSION),
        Some(Value::Boolean(v)) => *v,
        Some(Value::F64(v)) => *v == STAMP_FILE_VERSION as f64,
        Some(Value::F32(v)) => *v == STAMP_FILE_VERSION as f32,
        _ => false,
    };
    let Some(Value::Binary(stamp)) = field("stamp") else { return false };
    version_ok && stamp.len() == NETWORK_STAMP_SIZE && stamp_valid(stamp, target, material).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rns_identity::destination::{destination_stamp_path, store_destination_stamp};
    use rns_identity::stamps::{NETWORK_STAMP_SIZE, StampControl, generate_stamp, stamp_value};

    use super::*;

    /// Where a value counts as cheap in these tests: below the 8 to 10 bits they make stamps of.
    const CHEAP: f64 = 4.0;
    const RNS: &str = "[reticulum]\n  share_instance = No\n\n[interfaces]\n";

    struct Setup {
        dir: PathBuf,
        identity: Identity,
        destination: Destination,
    }

    impl Setup {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("rettui-manage-stamps-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let identity = Identity::new();
            let public = Identity::from_public_key(&identity.get_public_key()).unwrap();
            let destination =
                Destination::new(Some(&public), Direction::Out, DestType::Single, crate::lxmf::LXMF_ASPECT).expect("a destination");
            Self { dir, identity, destination }
        }

        fn config(&self) -> PathBuf {
            self.dir.join("config")
        }

        fn key(&self) -> [u8; 64] {
            self.identity.get_public_key()
        }

        fn ready(&self, running: &StampPolicy, after: &str) -> bool {
            saved(running, &self.config(), &self.destination.hash, &self.key(), after, CHEAP)
        }

        fn material(&self) -> Vec<u8> {
            self.destination.stamp_material(&self.key()).to_vec()
        }

        fn save(&self, stamp: [u8; NETWORK_STAMP_SIZE], value: f64) {
            let storage = StoragePaths::from_config_dir(&self.dir).storage_dir;
            store_destination_stamp(&storage, &self.destination.hash, &stamp, value).unwrap();
        }

        /// Save a stamp of at least `cost` bits, as the stamper does.
        fn make_stamp(&self, cost: f64) {
            let (stamp, value) =
                generate_stamp(&self.material(), cost, 0, NETWORK_STAMP_SIZE, &StampControl::default()).unwrap().expect("a stamp");
            self.save(stamp.try_into().unwrap(), value);
        }

        /// Save a stamp worth less than `below` bits: the first of a row that is (as a stamp
        /// found for a cost may be worth more than it, by luck).
        fn make_weak_stamp(&self, below: f64) {
            let material = self.material();
            let (stamp, value) = (0..=u8::MAX)
                .map(|n| [n; NETWORK_STAMP_SIZE])
                .map(|stamp| (stamp, stamp_value(&material, &stamp)))
                .find(|(_, value)| *value < below)
                .expect("one of 256 stamps is worth less than 8 bits");
            self.save(stamp, value);
        }
    }

    impl Drop for Setup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn policy(value: f64) -> StampPolicy {
        StampPolicy { destination_value: value, ..StampPolicy::default() }
    }

    fn after(value: f64) -> String {
        format!("{RNS}\n[stamps]\n  destination_value = {value}\n")
    }

    #[test]
    fn a_stamp_is_ready_once_it_is_saved_and_strong_enough() {
        let setup = Setup::new("saved");
        assert!(!setup.ready(&policy(8.0), &after(8.0)), "none saved yet");
        setup.make_weak_stamp(8.0);
        assert!(!setup.ready(&policy(8.0), &after(8.0)), "one below the value is no use");
        setup.make_stamp(10.0);
        assert!(setup.ready(&policy(8.0), &after(8.0)));
        // A change that lowers the value is covered by the stronger stamp.
        assert!(setup.ready(&policy(8.0), &after(6.0)));
    }

    #[test]
    fn a_change_to_a_cheap_value_is_not_waited_for_when_nothing_is_saved() {
        let setup = Setup::new("cheap");
        // Nothing saved: a value at or under the cut-off is made in seconds after the restart...
        assert!(setup.ready(&policy(30.0), &after(CHEAP)));
        assert!(setup.ready(&policy(30.0), &after(0.0)));
        // ...one over it is waited for.
        assert!(!setup.ready(&policy(30.0), &after(CHEAP + 1.0)));
        assert!(!setup.ready(&policy(30.0), &after(CHEAP + 0.5)));
        // The real cut-off is the same: 18 goes, 19 waits (25 is what Reticulum has by default).
        let real = |value: f64| saved(&policy(25.0), &setup.config(), &setup.destination.hash, &setup.key(), &after(value), CHEAP_VALUE);
        assert!(real(CHEAP_VALUE) && !real(CHEAP_VALUE + 1.0) && !real(25.0));
        // No value in the config is the default, which waits.
        assert!(!real(25.0) && !saved(&policy(25.0), &setup.config(), &setup.destination.hash, &setup.key(), RNS, CHEAP_VALUE));
    }

    #[test]
    fn a_stamp_made_for_the_running_value_is_enough_for_a_change_that_raises_it() {
        let setup = Setup::new("raised");
        setup.make_stamp(10.0);
        // Nothing makes a stronger one before the restart, so it isn't waited for.
        assert!(setup.ready(&policy(8.0), &after(30.0)));
    }

    #[test]
    fn nothing_is_waited_for_where_no_stamp_is_made_or_it_cannot_be_judged() {
        let setup = Setup::new("none");
        let off = StampPolicy { stamp_destinations: false, ..policy(8.0) };
        assert!(setup.ready(&off, &after(8.0)), "the running Reticulum makes no stamps");
        assert!(setup.ready(&policy(8.0), "[reticulum]\n  share_instance = maybe\n"), "a config that doesn't parse");
        // Another address than the identity's, a key that is none, a config with no folder.
        assert!(saved(&policy(8.0), &setup.config(), &[1; 16], &setup.key(), &after(8.0), CHEAP));
        assert!(saved(&policy(8.0), &setup.config(), &setup.destination.hash, &[0; 64], &after(8.0), CHEAP));
        assert!(saved(&policy(8.0), Path::new(""), &setup.destination.hash, &setup.key(), &after(8.0), CHEAP));
    }

    #[test]
    fn the_test_checks_answer_as_told() {
        let setup = Setup::new("fixed");
        let key = setup.key();
        let made = Arc::new(AtomicBool::new(false));
        let starts = Arc::new(AtomicUsize::new(0));
        let check = StampCheck::Fixed(made.clone(), starts.clone(), Arc::default());
        assert!(!check.ready(&setup.config(), &setup.destination.hash, &key, RNS));
        made.store(true, Ordering::SeqCst);
        assert!(check.ready(&setup.config(), &setup.destination.hash, &key, RNS));
        assert!(StampCheck::default().ready(&setup.config(), &setup.destination.hash, &key, RNS));
        assert!(check.start(&setup.config(), &setup.destination.hash, &key).is_some() && starts.load(Ordering::SeqCst) == 1);
        assert!(StampCheck::Skip.start(&setup.config(), &setup.destination.hash, &key).is_none());
    }

    #[test]
    fn the_node_makes_its_stamp_through_the_stamper() {
        // The real start is the stamper's own `prepare`, with the process policy and storage:
        // here only that it asks for nothing of a key that isn't the address's.
        let setup = Setup::new("start");
        assert!(StampCheck::Saved.start(&setup.config(), &[1; 16], &setup.key()).is_none());
        assert!(StampCheck::Saved.start(&setup.config(), &setup.destination.hash, &[0; 64]).is_none());
    }

    #[test]
    fn a_job_is_ended_once_its_answer_is_there_and_looking_does_not_wait_or_stop_it() {
        let mut going = Making { job: Job::Real(Box::pin(std::future::pending())), done: false };
        assert!(!going.ended() && !going.ended());
        let mut done = Making { job: Job::Real(Box::pin(async { None })), done: false };
        // An `async` block panics when it is polled after it has finished: asking again must not poll.
        for _ in 0..10 {
            assert!(done.ended());
        }
    }

    /// `saved` and `blocked` for a stamp file that is `make`d at its path (given the good one's), and
    /// that both came back at once.
    fn checked_with_file_made_by(name: &str, make: impl FnOnce(&Path, &Path)) -> (bool, bool) {
        let setup = Setup::new(name);
        setup.make_stamp(10.0);
        let storage = StoragePaths::from_config_dir(&setup.dir).storage_dir;
        let path = destination_stamp_path(&storage, &setup.destination.hash);
        let good = setup.dir.join("good.dstamp");
        std::fs::rename(&path, &good).unwrap();
        make(&path, &good);
        let (config, hash, key) = (setup.config(), setup.destination.hash, setup.key());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (_, destination) = destination_of(&hash, &key).unwrap();
            let _ = tx.send((saved(&policy(8.0), &config, &hash, &key, &after(8.0), CHEAP), blocked(&config, &destination)));
        });
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the check came back at once")
    }

    #[test]
    fn only_a_plain_file_is_a_saved_stamp() {
        assert_eq!(checked_with_file_made_by("plain", |path, good| std::fs::copy(good, path).map(drop).unwrap()), (true, false));
        assert_eq!(checked_with_file_made_by("none-there", |_, _| {}), (false, false), "nothing there blocks nothing");
        // Not a stamp, but a plain file: it is overwritten when a stamp is made.
        assert_eq!(checked_with_file_made_by("garbage", |path, _| std::fs::write(path, b"not a stamp").unwrap()), (false, false));
        // Over the 1024 bytes a stamp file has, though it starts as a good one.
        let big = |path: &Path, good: &Path| {
            let mut bytes = std::fs::read(good).unwrap();
            bytes.resize(MAX_STAMP_FILE + 1, 0);
            std::fs::write(path, bytes).unwrap();
        };
        assert_eq!(checked_with_file_made_by("big", big), (false, true));
        // A folder.
        assert_eq!(checked_with_file_made_by("folder", |path, _| std::fs::create_dir(path).unwrap()), (false, true));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_at_the_stamp_path_is_not_a_saved_stamp() {
        // The link points at a good stamp, which a plain file there would pass for.
        let link = |path: &Path, good: &Path| std::os::unix::fs::symlink(good, path).unwrap();
        assert_eq!(checked_with_file_made_by("link", link), (false, true), "and nothing is queued for it");
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_at_the_stamp_path_is_not_a_saved_stamp_and_does_not_hold_the_check() {
        let made = |path: &Path, _: &Path| {
            let status = std::process::Command::new("mkfifo").arg(path).status().expect("mkfifo");
            assert!(status.success());
        };
        assert_eq!(checked_with_file_made_by("pipe", made), (false, true), "and nothing is queued for it");
    }

    /// A pipe and a good file put at the stamp path in turn, as fast as one thread can, while the
    /// check runs: it never opens what it has not looked at, so it never waits.
    #[cfg(unix)]
    #[test]
    fn a_pipe_swapped_in_while_the_check_runs_does_not_hold_it() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let setup = Setup::new("swap");
        setup.make_stamp(10.0);
        let storage = StoragePaths::from_config_dir(&setup.dir).storage_dir;
        let path = destination_stamp_path(&storage, &setup.destination.hash);
        let (good, pipe, scratch) = (setup.dir.join("good"), setup.dir.join("pipe"), setup.dir.join("scratch"));
        std::fs::copy(&path, &good).unwrap();
        assert!(std::process::Command::new("mkfifo").arg(&pipe).status().unwrap().success());
        let stop = Arc::new(AtomicBool::new(false));
        let swapper = {
            let (stop, path) = (stop.clone(), path.clone());
            std::thread::spawn(move || {
                // A link to either one, put over the path in one step.
                while !stop.load(Ordering::SeqCst) {
                    for from in [&pipe, &good] {
                        let _ = std::fs::remove_file(&scratch);
                        if std::fs::hard_link(from, &scratch).is_ok() {
                            let _ = std::fs::rename(&scratch, &path);
                        }
                    }
                }
            })
        };
        let (config, hash, key) = (setup.config(), setup.destination.hash, setup.key());
        let (tx, rx) = std::sync::mpsc::channel();
        let checker = std::thread::spawn(move || {
            for _ in 0..2000 {
                saved(&policy(8.0), &config, &hash, &key, &after(8.0), CHEAP);
            }
            let _ = tx.send(());
        });
        let done = rx.recv_timeout(std::time::Duration::from_secs(60));
        stop.store(true, Ordering::SeqCst);
        swapper.join().unwrap();
        assert!(done.is_ok(), "the check was held by a pipe");
        checker.join().unwrap();
    }
}
