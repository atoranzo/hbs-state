//! # hbs-state -- the signature index guard
//!
//! XMSS is a **stateful** scheme: every signature consumes an index, and
//! **reusing one leaks the key**. That is not a degradation: it is
//! compromise.
//!
//! ## Why it lives in a crate of its own
//!
//! The design decision: **a counter of our own, persisted with `fsync` and
//! isolated from the rest of the system** -- not a WAL. Signing is the
//! OPERATOR's duty; what this crate protects is the INVARIANT, not anyone's
//! policy.
//!
//! Isolated means isolated: **it touches no database and reimplements
//! nothing**. One file, eight bytes, and an order.
//!
//! ## WARNING: XMSS changes the durability premise
//!
//! A system without a WAL is usually justified like this: *"losing one
//! operation is recoverable: you send it again"*.
//!
//! **With XMSS that stops being true.** If the process dies after signing
//! with an index and before persisting it, that index is **burnt into a
//! published signature** and the counter does not know: on restart it is
//! reused. That is why the order is deliberately inverted: **persist first,
//! sign afterwards.**
//!
//! ## The invariant, in one line
//!
//! > **No signature may exist with an index greater than the persisted
//! > counter.**
//!
//! The opposite -- counter ahead, index burnt with no signature -- is the
//! **safe** case, and it is the one [`Reconciliation`] resolves. Measured:
//! it happens in **13 of 25** process kills. **It is not the exception: it
//! is the normal path after a crash.**
//!
//! ## WARNING: the self-check, and why it is not paranoia
//!
//! `fsync` was measured on two filesystems of the same machine:
//!
//! | | cost of `fsync` | against not persisting |
//! |---|---|---|
//! | ext4 | 0.907 ms | **382x** |
//! | tmpfs (`/tmp`) | 0.002 ms | **1x** |
//!
//! On `tmpfs`, `fsync` **returns success without persisting anything** --
//! there is no disk. A guard whose file ends up there is a **no-op**, and
//! the key is at risk with every call that returns `Ok`.
//!
//! And `/tmp` is a perfectly plausible home for a file somebody considers
//! auxiliary.
//!
//! That is why [`IndexGuard::open`] **measures its own `fsync` at start-up
//! and refuses to operate** if the cost is indistinguishable from not
//! persisting. It is the only signal available from inside the process.
//!
//! WARNING: **the thresholds come from ONE machine** -- WSL2 on an
//! i5-1135G7 -- and are declared, not derived. A fast NVMe may legitimately
//! do `fsync` in ~100 us; that is why the main discriminant is the **ratio**
//! against not persisting, not the absolute value.
//!
//! ## WARNING: what this does NOT guarantee
//!
//! **Nothing against a power cut.** *"`fsync` can lie"* is about disks that
//! confirm writes still sitting in volatile cache. What was measured is
//! durability against **process death** -- 25 of 25 with not one signature
//! ahead -- and that **is not the same thing**. Measuring it requires really
//! cutting the power, and that has not been done.
//!
//! ## WARNING: and this piece has no consumer yet
//!
//! This piece was extracted from a research prototype where it has been
//! signing since August 2026 (it said "production ... for a year": false,
//! withdrawn 2026-09-30). It travels ALONE, with its bench: see HBS-STATE.
//!
//! (Until this revision the line above published a test count. It said 26
//! and there were 27: a figure on the crate's front page that nothing
//! re-derived. It is gone rather than corrected -- the bench is what counts,
//! and `tests/vectors.rs` ties it to the specification.)

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Bytes of the OID at the start of the SK, in the reference format.
const OID_BYTES: usize = 4;
/// Hash length of the `_256` parameter set.
const N: usize = 32;
/// Index width in bytes: ceil(h/8) = 5 for `h = 40`.
const fn index_width() -> usize {
    5
}

/// How many writes the start-up self-check uses.
const SELFCHECK_SAMPLES: u32 = 20;

/// WARNING: **DECLARED threshold, not derived.** `fsync` has to cost at
/// least this ratio against writing without persisting. Measured: ext4 gave
/// **382x** and tmpfs **1x**, so 10 separates the two cases with two orders
/// of margin on the safe side.
const MIN_RATIO: f64 = 10.0;

/// Absolute floor, as a second net. A fast NVMe does `fsync` in ~100 us
/// legitimately, so this stays well below it: it only catches the "there is
/// no disk" case.
const FLOOR_MICROS: f64 = 20.0;

/// Reads the index out of the SK: bytes `[4, 9)` in **big-endian**.
///
/// WARNING: **the offset and the width are MEASURED**, not deduced: the SK
/// is **137 bytes** = OID(4) + index(5) + 4x32, and signing changes byte 8
/// -- the least significant one of a big-endian integer occupying [4, 9).
///
/// WARNING: an evaluation once recorded "SK = 136 B, 4-byte index": that
/// belongs to the **single-tree** parameter set. For the chosen one they are
/// **137 and 5**.
///
/// WARNING: **this lives here and not in the signer.** What was shareable
/// was not the counter but **the whole invariant**: reserving, checking the
/// layout and reconciling are one piece. Leaving it split forced a SECOND
/// SIGNER to reimplement the layout read -- two readings of the same format
/// that can disagree -- or to sign without that protection.
///
/// WARNING: it drags no `xmss` in: it is offset arithmetic over `&[u8]`.
/// This crate still has not one dependency.
pub fn index_from_sk(sk: &[u8]) -> Result<u64, GuardError> {
    let expected = OID_BYTES + index_width() + 4 * N;
    if sk.len() != expected {
        return Err(GuardError::UnexpectedLayout { sk_len: sk.len(), expected });
    }
    let mut v = 0u64;
    for b in &sk[OID_BYTES..OID_BYTES + index_width()] {
        v = (v << 8) | *b as u64;
    }
    Ok(v)
}

/// Writes the index INTO the SK bytes. Exact mirror of [`index_from_sk`]:
/// same layout, same width, same byte order.
///
/// WARNING: **it is CONSERVATIVE, not risky.** The counter is persisted
/// BEFORE signing, so at most leaf `counter - 1` was spent. Putting the key
/// at `counter` uses a leaf that was NEVER reserved: it cannot be burnt. The
/// leaves below are LOST, and **a lost index is better than an
/// indeterminate one**.
///
/// WARNING: it fails CLOSED on the FIELD WIDTH: the ceiling is
/// `2^(8 * index_width())`, DERIVED and not typed.
///
/// WARNING: it is not a third copy of the layout: it uses `index_width()`,
/// the same source as the reader.
pub fn set_index_in_sk(sk: &mut [u8], index: u64) -> Result<(), GuardError> {
    let expected = OID_BYTES + index_width() + 4 * N;
    if sk.len() != expected {
        return Err(GuardError::UnexpectedLayout { sk_len: sk.len(), expected });
    }
    let width = index_width();
    if width < 8 && index >= (1u64 << (8 * width)) {
        return Err(GuardError::IndexOutOfField { index, width });
    }
    for i in 0..width {
        let offset = 8 * (width - 1 - i);
        sk[OID_BYTES + i] = ((index >> offset) & 0xff) as u8;
    }
    Ok(())
}

/// WARNING: a module of ITS OWN and not inside the one below: a Rust item
/// begins at its ATTRIBUTES, and putting tests between a `#[test]` and its
/// `fn` leaves them orphaned -- a real defect, measured.
#[cfg(test)]
mod index_in_the_sk {
    use super::*;

    fn test_sk() -> Vec<u8> {
        vec![0u8; OID_BYTES + index_width() + 4 * N]
    }

    /// WARNING: reader and writer are TWO producers of the same layout: they
    /// are TIED here, rather than trusted to agree.
    #[test]
    fn what_is_written_is_what_is_read() {
        let width = index_width();
        let cap = 1u64 << (8 * width);
        for n in [0u64, 1, 2, 255, 256, cap - 1] {
            let mut sk = test_sk();
            set_index_in_sk(&mut sk, n).expect("write");
            let read_back = index_from_sk(&sk).expect("read");
            assert_eq!(read_back, n, "the reader does not return what the writer put");
        }
    }

    /// WARNING: THE RED PATH of the ceiling. The limit is DERIVED from
    /// `index_width()`.
    #[test]
    fn an_index_that_does_not_fit_fails_closed_and_touches_nothing() {
        let width = index_width();
        let cap = 1u64 << (8 * width);
        let mut sk = test_sk();
        match set_index_in_sk(&mut sk, cap) {
            Err(GuardError::IndexOutOfField { index, width: w }) => {
                assert_eq!(index, cap, "the error names the index that did not fit");
                assert_eq!(w, width, "and the width it did not fit into");
            }
            other => panic!("an index that does not fit MUST NOT be written: {other:?}"),
        }
        assert!(sk.iter().all(|b| *b == 0), "and it touches not one byte when failing");
    }

    #[test]
    fn an_sk_of_another_length_is_not_touched() {
        let mut short = vec![0u8; 10];
        assert!(matches!(
            set_index_in_sk(&mut short, 1),
            Err(GuardError::UnexpectedLayout { .. })
        ));
    }
}

#[derive(Debug)]
pub enum GuardError {
    Io(String),
    /// WARNING: the index does not fit in the SK FIELD. The width is fixed
    /// by `index_width()`, and here it coincides with the tree height
    /// because h = 40 = 8 x 5; with an `h` that were not a multiple of 8 the
    /// ceiling would be loose from above and would have to be tied to the
    /// real height. It fails CLOSED: a corrupt counter does not slip into an
    /// SK.
    IndexOutOfField { index: u64, width: usize },
    /// The file exists but does not hold eight bytes.
    Corrupt { bytes: usize },
    /// WARNING: `fsync` costs nothing: almost certainly `tmpfs` or a mount
    /// with no real persistence. **Operating here would put the key at
    /// risk.**
    FakePersistence { with_fsync_us: f64, without_fsync_us: f64, ratio: f64 },
    /// WARNING: the seed file is readable by group or others. Creating it
    /// with `0600` does not stop someone loosening it afterwards: it is
    /// checked ON READ.
    PermissionsTooOpen { path: String, mode: u32 },
    /// WARNING: the RAW binary seed is not the size it must be. `looks_hex`
    /// tells apart the mistake people actually make: handing the RAW reader
    /// the HEX file.
    SeedLength { expected: usize, found: usize, looks_hex: bool },
    /// WARNING: the HEX seed is not the size it must be. CHARACTERS are
    /// counted: a byte derived with integer division made 193 say "96".
    SeedHexLength { expected_chars: usize, found_chars: usize },
    /// The HEX seed carries something that is not a hex digit.
    SeedNotHex { detail: String },
    UnexpectedLayout { sk_len: usize, expected: usize },
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::IndexOutOfField { index, width } => write!(
                f,
                "index guard: index {index} does not fit in a field of \
                 {width} byte(s). The counter is corrupt, or the parameter \
                 set changed"
            ),
            GuardError::Io(e) => write!(f, "index guard: {e}"),
            GuardError::Corrupt { bytes } => write!(
                f,
                "index guard: the counter file holds {bytes} bytes, not 8"
            ),
            GuardError::FakePersistence { with_fsync_us, without_fsync_us, ratio } => write!(
                f,
                "index guard: `fsync` persists nothing here \
                 ({with_fsync_us:.1} us with fsync against {without_fsync_us:.1} us without it, \
                 ratio {ratio:.1}x, minimum {MIN_RATIO:.0}x). \
                 Almost certainly tmpfs or a diskless mount. \
                 Reusing an XMSS index leaks the key: this does NOT start"
            ),
            GuardError::PermissionsTooOpen { path, mode } => write!(
                f,
                "{path} has mode {mode:04o}: it is readable by group or others. \
                 A secret readable by the group is everyone's secret. `chmod 600`"
            ),
            GuardError::SeedLength { expected, found, looks_hex } => {
                write!(
                    f,
                    "the RAW binary seed must be {expected} bytes and is {found}"
                )?;
                if *looks_hex {
                    write!(
                        f,
                        ". Those are {found} hexadecimal characters: this looks \
                         like the HEX file, and this reader wants the RAW bytes"
                    )?;
                }
                Ok(())
            }
            GuardError::SeedHexLength { expected_chars, found_chars } => write!(
                f,
                "the seed must be {} bytes ({expected_chars} hex characters) and has \
                 {found_chars} characters",
                expected_chars / 2
            ),
            GuardError::SeedNotHex { detail } => {
                write!(f, "the seed is not hexadecimal: {detail}")
            }
            GuardError::UnexpectedLayout { sk_len, expected } => write!(
                f,
                "index guard: the SK is {sk_len} bytes and {expected} were \
                 expected. The `xmss` serialisation changed: the index is NOT \
                 read blindly"
            ),
        }
    }
}

/// **An error type carries `Debug`, `Display` and `Error` from birth.**
impl std::error::Error for GuardError {}

/// **The signer's seed, read and checked in one single place.**
pub mod seed;

/// What is found when comparing the counter against the key's real index,
/// after a restart.
#[derive(Debug, PartialEq, Eq)]
pub enum Reconciliation {
    /// Everything agrees.
    InSync { index: u64 },
    /// WARNING: **the normal case after a crash** -- 13 of 25, measured --:
    /// the index was persisted and the process died before signing. There
    /// are indices **burnt with no signature**. It is not a failure: it is
    /// the price of the order.
    ///
    /// WARNING: **this was measured INSIDE one process** -- a child that
    /// persists and signs, killed at a random instant -- **not after a
    /// RESTART**. On restart the key goes back to zero and the case is
    /// [`Reconciliation::KeyAtZero`]. The figure is correct; what it does
    /// not cover is the restart.
    CounterAhead { counter: u64, key: u64, orphans: u64 },
    /// WARNING: **the key comes from the seed and the counter says signing
    /// already happened.** The SK is **not persisted**: on restart
    /// `from_seed` returns it at ZERO. No signatures are missing: what
    /// happens is that **0..counter-1 are left INDETERMINATE**, and signing
    /// again would reuse them -- QRL curve: at the second reuse, ~2^34
    /// hashes.
    ///
    /// WARNING: **it fails closed, and not out of prudence but because it
    /// cannot be told apart**: with counter 1 and key 0, dying inside the
    /// [`IndexGuard::reserve`] window and dying after signing leave the
    /// **same state on disk**. **An indeterminate index is worse than a lost
    /// one: it invites reuse.**
    KeyAtZero { counter: u64, indeterminate: u64 },
    /// WARNING: **WHAT MUST NEVER HAPPEN.** The key has signed with indices
    /// the counter never recorded: either the order was inverted, or `fsync`
    /// did not do what it said. **The key must be considered compromised.**
    KeyAhead { counter: u64, key: u64, unrecorded: u64 },
}

/// The one case that **ADMITS NO NUANCE**, no matter who is asking.
///
/// WARNING: **the invariant belongs to the guard; the policy, to each
/// owner.** Two different signers decide different things faced with
/// `CounterAhead` or with `KeyAtZero` -- and rightly so: that is policy --
/// but neither of them may start with the key ahead of the counter. That
/// part is not theirs: it is decided here, in the crate they share.
///
/// WARNING: **production does not call it, and that is on purpose.** To
/// build its message each policy needs the variant's FIELDS, so its `match`
/// is unavoidable and an `if` in front would suggest a restriction that does
/// not exist. What consumes it is **each crate's test**, and that test
/// enumerates the variants with a wildcard-free `match`: the day a fifth one
/// is born, both crates stop compiling until somebody decides.
pub fn is_fatal(r: &Reconciliation) -> bool {
    match r {
        Reconciliation::InSync { .. } => false,
        Reconciliation::CounterAhead { .. } => false,
        Reconciliation::KeyAtZero { .. } => false,
        Reconciliation::KeyAhead { .. } => true,
    }
}

#[cfg(test)]
mod start_up_invariant {
    use super::*;

    /// The four values, written as literals and not derived from the `match`
    /// itself: a test that reproduces the implementation proves nothing.
    #[test]
    fn only_key_ahead_is_fatal() {
        assert!(!is_fatal(&Reconciliation::InSync { index: 7 }));
        assert!(!is_fatal(&Reconciliation::CounterAhead {
            counter: 9,
            key: 7,
            orphans: 2
        }));
        assert!(!is_fatal(&Reconciliation::KeyAtZero {
            counter: 5,
            indeterminate: 5
        }));
        assert!(is_fatal(&Reconciliation::KeyAhead {
            counter: 3,
            key: 9,
            unrecorded: 6
        }));
    }
}

/// The reconciliation, as a **pure function of two numbers**.
///
/// WARNING: extracted from the method so that it can be measured without
/// touching disk: it is what HBS-STATE says it is -- `(counter, key) ->
/// state` -- and what the conformance bench consumes.
/// [`IndexGuard::reconcile`] calls it; the two paths are TIED by a test,
/// rather than trusted to agree.
pub fn reconcile_values(counter: u64, key: u64) -> Reconciliation {
    use std::cmp::Ordering::*;
    match counter.cmp(&key) {
        Equal => Reconciliation::InSync { index: counter },
        Greater if key == 0 => Reconciliation::KeyAtZero {
            counter,
            indeterminate: counter,
        },
        Greater => Reconciliation::CounterAhead {
            counter,
            key,
            orphans: counter - key,
        },
        Less => Reconciliation::KeyAhead {
            counter,
            key,
            unrecorded: key - counter,
        },
    }
}

/// Monotonic counter of signature indices, persisted before every use.
///
/// WARNING: `Debug` because it shows up in a `Result` the tests inspect with
/// `{:?}`: **if the error derives it and the success does not, the `Result`
/// still does not derive it**. The rule that avoids this is to look at BOTH
/// halves of the `Result`, not only the one that fails.
#[derive(Debug)]
pub struct IndexGuard {
    path: PathBuf,
    current: u64,
}

impl IndexGuard {
    /// Opens -- or creates -- the counter, **and checks that `fsync` really
    /// persists** on that filesystem.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GuardError> {
        let path = path.as_ref().to_path_buf();
        let folder = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        std::fs::create_dir_all(&folder).map_err(|e| GuardError::Io(e.to_string()))?;

        Self::check_persistence(&folder)?;

        let current = if path.exists() {
            let mut buf = Vec::new();
            File::open(&path)
                .and_then(|mut f| f.read_to_end(&mut buf))
                .map_err(|e| GuardError::Io(e.to_string()))?;
            if buf.len() != 8 {
                return Err(GuardError::Corrupt { bytes: buf.len() });
            }
            u64::from_le_bytes(buf.try_into().expect("8 bytes"))
        } else {
            0
        };

        let g = IndexGuard { path, current };
        // The start-up value is written so that the file exists and is in
        // sync, even when it is 0.
        g.persist(current)?;
        Ok(g)
    }

    /// WARNING: **the only function that must be used before signing.** It
    /// persists `current + 1`, returns it, and **only then** may the caller
    /// sign with it.
    ///
    /// If the process dies between this call and the signature, the index is
    /// left **orphaned** -- burnt with no signature. That is correct and
    /// expected; [`Self::reconcile`] resolves it.
    pub fn reserve(&mut self) -> Result<u64, GuardError> {
        let next_one = self.current.checked_add(1).ok_or_else(|| {
            GuardError::Io("the index counter has overflowed".into())
        })?;
        self.persist(next_one)?;
        self.current = next_one;
        Ok(next_one)
    }

    /// The last persisted index. **It never goes back.**
    pub fn current(&self) -> u64 {
        self.current
    }

    /// Compares the counter against the index the key says it holds.
    ///
    /// WARNING: the key's index **is read by the caller**, because today the
    /// signing library's API **usually does not expose it**: the SK has to
    /// be interpreted at the reference format's offset, and in multi-tree
    /// that offset depends on the parameter set (ceil(h/8)).
    pub fn reconcile(&self, key_index: u64) -> Reconciliation {
        reconcile_values(self.current, key_index)
    }

    fn persist(&self, value: u64) -> Result<(), GuardError> {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.path)
            .map_err(|e| GuardError::Io(e.to_string()))?;
        f.seek(SeekFrom::Start(0)).map_err(|e| GuardError::Io(e.to_string()))?;
        f.write_all(&value.to_le_bytes()).map_err(|e| GuardError::Io(e.to_string()))?;
        // `sync_all` is `fsync(2)`: data AND metadata. That is what was
        // measured.
        f.sync_all().map_err(|e| GuardError::Io(e.to_string()))?;
        Ok(())
    }

    /// Measures `fsync` against no-`fsync` and decides whether this place
    /// persists.
    fn check_persistence(folder: &Path) -> Result<(), GuardError> {
        let probe = folder.join(".hbs-state-selfcheck");
        let measure = |with_fsync: bool| -> Result<f64, GuardError> {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&probe)
                .map_err(|e| GuardError::Io(e.to_string()))?;
            let t0 = Instant::now();
            for n in 0..SELFCHECK_SAMPLES {
                f.seek(SeekFrom::Start(0)).map_err(|e| GuardError::Io(e.to_string()))?;
                f.write_all(&(n as u64).to_le_bytes())
                    .map_err(|e| GuardError::Io(e.to_string()))?;
                if with_fsync {
                    f.sync_all().map_err(|e| GuardError::Io(e.to_string()))?;
                }
            }
            Ok(t0.elapsed().as_secs_f64() * 1e6 / SELFCHECK_SAMPLES as f64)
        };
        let without = measure(false)?;
        let with = measure(true)?;
        let _ = std::fs::remove_file(&probe);

        let ratio = if without > 0.0 { with / without } else { f64::INFINITY };
        if ratio < MIN_RATIO && with < FLOOR_MICROS {
            return Err(GuardError::FakePersistence {
                with_fsync_us: with,
                without_fsync_us: without,
                ratio,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // WARNING: the tests that are NOT about the self-check force the working
    // location, because `std::env::temp_dir()` is usually **tmpfs** and
    // there `open` refuses -- rightly. A directory under the project's own
    // tree is used instead, which is on disk.
    fn on_disk(name: &str) -> PathBuf {
        let d = std::path::Path::new("target").join(format!("guard_{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("create");
        d.join("index.bin")
    }

    #[test]
    fn starts_at_zero_and_advances_by_one() {
        let p = on_disk("advances");
        let mut g = IndexGuard::open(&p).expect("open");
        assert_eq!(g.current(), 0, "a fresh counter starts at 0");
        assert_eq!(g.reserve().expect("reserve"), 1);
        assert_eq!(g.reserve().expect("reserve"), 2);
        assert_eq!(g.current(), 2);
    }

    #[test]
    fn the_counter_survives_close_and_never_goes_back() {
        // WARNING: the test that gives the piece its point: if this fails, a
        // restart reuses indices and **leaks the key**.
        let p = on_disk("survives");
        {
            let mut g = IndexGuard::open(&p).expect("open");
            for _ in 0..5 {
                g.reserve().expect("reserve");
            }
            assert_eq!(g.current(), 5);
        }
        let g2 = IndexGuard::open(&p).expect("reopen");
        assert_eq!(g2.current(), 5, "CRITICAL: the counter went back on reopen");
    }

    #[test]
    fn reopening_many_times_loses_none() {
        let p = on_disk("many");
        for expected in 1..=6u64 {
            let mut g = IndexGuard::open(&p).expect("open");
            assert_eq!(g.reserve().expect("reserve"), expected);
        }
        assert_eq!(IndexGuard::open(&p).expect("open").current(), 6);
    }

    #[test]
    fn counter_ahead_is_the_normal_case_and_is_recognised() {
        // Measured: 13 of 25 process kills leave the counter ahead.
        let p = on_disk("ahead");
        let mut g = IndexGuard::open(&p).expect("open");
        for _ in 0..7 {
            g.reserve().expect("reserve");
        }
        // The key only got as far as signing 5 of the 7 reserved indices.
        assert_eq!(
            g.reconcile(5),
            Reconciliation::CounterAhead { counter: 7, key: 5, orphans: 2 }
        );
    }

    #[test]
    fn key_ahead_is_distinguished_and_is_the_grave_one() {
        // WARNING: this means the key signed with indices the counter never
        // recorded: the order was inverted, or `fsync` lied.
        let p = on_disk("key_ahead");
        let mut g = IndexGuard::open(&p).expect("open");
        g.reserve().expect("reserve");
        assert_eq!(
            g.reconcile(9),
            Reconciliation::KeyAhead { counter: 1, key: 9, unrecorded: 8 }
        );
    }

    #[test]
    fn key_at_zero_with_a_live_counter_is_not_an_orphan() {
        // WARNING: the SK is not persisted: on restart the key goes back to
        // ZERO and 0..counter-1 are left INDETERMINATE, not orphaned.
        // WARNING: the RELATION is asserted, not a number: the counter is
        // DERIVED from `current()`. Typed, it would depend on the state the
        // fixture brings -- an earlier revision died of exactly that: it
        // asked for 4 and the file already had 4 in it.
        let p = on_disk("key_at_zero");
        let mut g = IndexGuard::open(&p).expect("open");
        for _ in 0..4 {
            g.reserve().expect("reserve");
        }
        let n = g.current();
        assert!(n >= 4, "the counter must have advanced and is at {n}");
        match g.reconcile(0) {
            Reconciliation::KeyAtZero { counter, indeterminate } => {
                assert_eq!(counter, n, "it reports the counter that is there");
                assert_eq!(indeterminate, counter, "ALL of them are indeterminate");
            }
            other => panic!("a key at zero with a live counter is NOT an orphan: {other:?}"),
        }
    }

    #[test]
    fn counter_one_key_zero_fails_closed() {
        // WARNING: THE CASE THAT CANNOT BE TOLD APART: dying inside the
        // `reserve` window and dying after signing leave the SAME state on
        // disk. That is why nothing is guessed: it is resolved on the safe
        // side.
        let p = on_disk("closed");
        let mut g = IndexGuard::open(&p).expect("open");
        let before = g.current();
        g.reserve().expect("reserve");
        let n = g.current();
        assert_eq!(n, before + 1, "one reservation advances exactly one");
        match g.reconcile(0) {
            Reconciliation::KeyAtZero { counter, indeterminate } => {
                assert_eq!(counter, n);
                assert_eq!(indeterminate, n, "with counter 1 and key 0 nothing is guessed either");
            }
            other => panic!("nothing is guessed: it fails closed. And it gave: {other:?}"),
        }
    }

    #[test]
    fn a_clean_start_is_not_the_new_variant() {
        // WARNING: counter 0 and key 0 are IN SYNC: the guard must not steal
        // the good case from the ordinary start-up.
        let p = on_disk("zero_zero");
        let g = IndexGuard::open(&p).expect("open");
        assert_eq!(g.current(), 0, "the fixture must give a clean counter");
        assert_eq!(g.reconcile(0), Reconciliation::InSync { index: 0 });
    }

    #[test]
    fn matching_is_matching() {
        let p = on_disk("in_sync");
        let mut g = IndexGuard::open(&p).expect("open");
        g.reserve().expect("reserve");
        g.reserve().expect("reserve");
        assert_eq!(g.reconcile(2), Reconciliation::InSync { index: 2 });
    }

    #[test]
    fn a_file_of_another_size_is_rejected_not_interpreted() {
        let p = on_disk("corrupt");
        std::fs::write(&p, b"this is not eight bytes").expect("write");
        match IndexGuard::open(&p) {
            Err(GuardError::Corrupt { bytes }) => assert_eq!(bytes, 23),
            other => panic!("it should be rejected as corrupt, and it gave: {other:?}"),
        }
    }

    #[test]
    fn the_index_reader_handles_carry() {
        // WARNING: THE LAYOUT TEST, half synthetic. Signing 256 times
        // against the real key would cost **37 s measured** (256 x 144.5
        // ms). Carry is a property of the READER, and here it is tested
        // exhaustively.
        let long = OID_BYTES + index_width() + 4 * N;
        let mut sk = vec![0u8; long];
        for (bytes, expected) in [
            ([0, 0, 0, 0, 1u8], 1u64),
            ([0, 0, 0, 1, 0], 256),
            ([0, 0, 1, 0, 0], 65_536),
            ([0, 1, 0, 0, 0], 16_777_216),
            ([1, 0, 0, 0, 0], 4_294_967_296),
            ([0xff, 0xff, 0xff, 0xff, 0xff], (1u64 << 40) - 1),
        ] {
            sk[OID_BYTES..OID_BYTES + 5].copy_from_slice(&bytes);
            assert_eq!(index_from_sk(&sk).expect("read"), expected, "bytes {bytes:02x?}");
        }
        assert_eq!((1u64 << 40) - 1, 1_099_511_627_775);
    }

    #[test]
    fn an_sk_of_another_size_is_rejected_not_read() {
        // WARNING: the other half of the layout test: if upstream changes
        // the serialisation, **it fails here and not in production**.
        match index_from_sk(&[0u8; 136]) {
            Err(GuardError::UnexpectedLayout { sk_len, expected }) => {
                assert_eq!(sk_len, 136);
                assert_eq!(expected, 137, "OID(4) + index(5) + 4x32 = 137");
            }
            other => panic!("an SK of 136 bytes must be rejected, and it gave: {other:?}"),
        }
    }

    #[test]
    fn on_tmpfs_it_refuses_to_operate() {
        // WARNING: THE TEST THAT JUSTIFIES THE SELF-CHECK. It was measured
        // that on tmpfs `fsync` costs the SAME as not doing it (ratio 1x,
        // against 382x on ext4): it returns success without persisting
        // anything.
        //
        // If the test machine has neither /dev/shm nor a temp_dir on tmpfs,
        // the test skips OUT LOUD instead of pretending it passed.
        let candidates = [PathBuf::from("/dev/shm"), std::env::temp_dir()];
        let mut probed = false;
        for base in candidates {
            if !base.is_dir() {
                continue;
            }
            let out = std::process::Command::new("df")
                .args(["-T", "--output=fstype"])
                .arg(&base)
                .output();
            let is_tmpfs = match out {
                Ok(o) => String::from_utf8_lossy(&o.stdout).contains("tmpfs"),
                Err(_) => false,
            };
            if !is_tmpfs {
                continue;
            }
            probed = true;
            let d = base.join(format!("hbs_state_tmpfs_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).expect("create");
            let r = IndexGuard::open(d.join("index.bin"));
            let _ = std::fs::remove_dir_all(&d);
            match r {
                Err(GuardError::FakePersistence { ratio, .. }) => {
                    assert!(ratio < MIN_RATIO, "ratio {ratio} should be below the minimum");
                }
                other => panic!(
                    "in {} -- which is tmpfs -- the guard MUST refuse, and it gave: {other:?}",
                    base.display()
                ),
            }
            break;
        }
        if !probed {
            eprintln!(
                "WARNING: no tmpfs was found to test the refusal on. \
                 The self-check has NOT been exercised in this environment."
            );
        }
    }

    /// WARNING: TWO PRODUCERS OF THE SAME CONTRACT: the method and the free
    /// function. They are tied here, over the edges and over the four
    /// states.
    #[test]
    fn the_method_and_the_free_function_agree() {
        let p = on_disk("free_tie");
        let mut g = IndexGuard::open(&p).expect("open");
        for _ in 0..3 {
            g.reserve().expect("reserve");
        }
        for key in [0u64, 1, 2, 3, 4, 9, u64::MAX] {
            assert_eq!(
                g.reconcile(key),
                reconcile_values(g.current(), key),
                "the method and the free function disagree at key={key}"
            );
        }
    }

    #[test]
    fn on_a_real_disk_it_does_operate() {
        // The other half: where `fsync` costs something, the guard starts.
        let p = on_disk("real_disk");
        IndexGuard::open(&p).expect("on a real disk the guard must start");
    }
}
