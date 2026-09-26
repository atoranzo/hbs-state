//! **The signer's seed: read, checked and decoded in ONE place.**
//!
//! WARNING: this used to live inside a BINARY, so a second signer **could
//! not reuse it even if it wanted to**: it did `fs::read` and handed the
//! constructor whatever was in the file, **without looking at permissions or
//! length**, while its own documentation called that "key material".
//!
//! WARNING: **TWO FORMATS coexist in practice**: HEX and RAW binary. What
//! cannot differ is **what gets checked**.
//!
//! WARNING: the order matters: **permissions and length BEFORE opening the
//! guard**, which creates the counter file when it opens. A start-up that
//! dies on the seed must not have left anything written.

use crate::GuardError;
use std::path::Path;

/// Length of the XMSS seed: **96 = 3x32** (`SK_SEED || SK_PRF ||
/// PUB_SEED`).
///
/// It is not this house's choice: `xmss` requires it and rejects it with
/// `InvalidSeedLength` when it does not match (read in `xmss-0.1.0-pre.0`,
/// `params.rs:1177`). Here it is checked **before**, so that the error can
/// say WHICH format was expected -- upstream only knows about lengths.
pub const SEED_LEN: usize = 96;

/// A key-material file must not be readable by group or by others.
///
/// WARNING: creating it with `0600` does not stop someone loosening it
/// afterwards: **it is checked on READ**, not on write. Keystores have been
/// seen that create correctly and then nobody looks again.
pub fn check_permissions(path: &Path) -> Result<(), GuardError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| GuardError::Io(e.to_string()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(GuardError::PermissionsTooOpen {
                path: path.display().to_string(),
                mode,
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Are these bytes the HEX representation of a seed?
///
/// This exists **only so that the error can say you got confused**: 192
/// characters, all hex digits, is almost certainly the HEX file handed to a
/// second signer. It is the mistake people actually make.
fn looks_hex(bytes: &[u8]) -> bool {
    bytes.len() == SEED_LEN * 2 && bytes.iter().all(|b| b.is_ascii_hexdigit())
}

/// Decodes a hexadecimal seed. It accepts a leading `0x` and surrounding
/// whitespace.
///
/// WARNING: the error counts **CHARACTERS, not derived bytes**: with integer
/// division, a hex string of 193 characters used to say "and has 96", which
/// is exactly the figure it was demanding. What is measured is what gets
/// reported.
pub fn decode_hex(hex: &str) -> Result<Vec<u8>, GuardError> {
    let h = hex.trim().trim_start_matches("0x");
    if h.len() != SEED_LEN * 2 {
        return Err(GuardError::SeedHexLength {
            expected_chars: SEED_LEN * 2,
            found_chars: h.len(),
        });
    }
    (0..SEED_LEN)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| GuardError::SeedNotHex {
            detail: e.to_string(),
        })
}

/// Reads a **HEX** seed from a file, checking the permissions first.
pub fn read_hex(path: &Path) -> Result<Vec<u8>, GuardError> {
    check_permissions(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| GuardError::Io(e.to_string()))?;
    decode_hex(&text)
}

/// Reads a **RAW BINARY** seed from a file, checking the permissions first.
pub fn read_raw(path: &Path) -> Result<Vec<u8>, GuardError> {
    check_permissions(path)?;
    let bytes = std::fs::read(path).map_err(|e| GuardError::Io(e.to_string()))?;
    if bytes.len() != SEED_LEN {
        return Err(GuardError::SeedLength {
            expected: SEED_LEN,
            found: bytes.len(),
            looks_hex: looks_hex(&bytes),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own per test: the crate has no dependencies, so no
    /// `tempfile` either.
    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hbs-seed-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("create dir");
        d
    }

    fn write_value(d: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = d.join(name);
        std::fs::write(&p, bytes).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 600");
        }
        p
    }

    fn test_hex() -> String {
        "5b".repeat(SEED_LEN)
    }

    fn test_raw() -> Vec<u8> {
        (0..SEED_LEN).map(|i| ((i * 31 + 9) % 256) as u8).collect()
    }

    #[test]
    fn hex_of_192_chars_yields_96_bytes() {
        let b = decode_hex(&test_hex()).expect("valid hex");
        assert_eq!(b.len(), SEED_LEN);
        assert!(b.iter().all(|x| *x == 0x5b));
    }

    #[test]
    fn hex_accepts_0x_and_surrounding_blanks() {
        let with_decoration = format!("  0x{}\n", test_hex());
        assert_eq!(
            decode_hex(&with_decoration).expect("valid hex"),
            decode_hex(&test_hex()).expect("valid hex")
        );
    }

    /// WARNING: the defect this repairs: with integer division, 193
    /// characters reported "96", which is the very figure being demanded.
    /// The message contradicted itself.
    #[test]
    fn a_hex_of_193_chars_does_not_say_96() {
        let bad = format!("{}a", test_hex());
        match decode_hex(&bad) {
            Err(e @ GuardError::SeedHexLength { .. }) => {
                let msg = format!("{e}");
                assert!(msg.contains("193"), "it must say what was MEASURED: {msg}");
                assert!(
                    !msg.contains("has 96"),
                    "it cannot say it has exactly what it demands: {msg}"
                );
            }
            other => panic!("it should have been SeedHexLength and gave: {other:?}"),
        }
    }

    #[test]
    fn a_non_hex_char_is_rejected_without_panicking() {
        let mut bad = test_hex();
        bad.replace_range(0..1, "z");
        assert!(matches!(
            decode_hex(&bad),
            Err(GuardError::SeedNotHex { .. })
        ));
    }

    #[test]
    fn a_raw_seed_of_96_bytes_passes() {
        let d = dir("raw-ok");
        let p = write_value(&d, "seed.bin", &test_raw());
        assert_eq!(read_raw(&p).expect("valid raw"), test_raw());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// WARNING: **the mistake people actually make**: handing the RAW reader
    /// the HEX file. Without this check it reaches the constructor and out
    /// comes an upstream `Debug` dump that names no format at all.
    #[test]
    fn hex_given_where_raw_is_expected_reports_looks_hex() {
        let d = dir("hex-to-a-raw-reader");
        let p = write_value(&d, "seed.hex", test_hex().as_bytes());
        match read_raw(&p) {
            Err(e @ GuardError::SeedLength { .. }) => {
                let msg = format!("{e}");
                assert!(msg.contains("RAW"), "it must say it wants raw bytes: {msg}");
                assert!(msg.contains("HEX"), "and that it was given hex: {msg}");
            }
            other => panic!("it should have been SeedLength and gave: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// WARNING: the two formats are **two producers of the same contract**:
    /// they are tied with a test, not with prose.
    #[test]
    fn both_formats_give_exactly_the_same_bytes() {
        let d = dir("tie");
        let raw_bytes = test_raw();
        let hex: String = raw_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let ph = write_value(&d, "s.hex", hex.as_bytes());
        let pb = write_value(&d, "s.bin", &raw_bytes);
        assert_eq!(
            read_hex(&ph).expect("hex"),
            read_raw(&pb).expect("raw"),
            "the same material in both formats gives the same bytes"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_file_is_rejected_on_read() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("permissions");
        let p = write_value(&d, "seed.bin", &test_raw());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).expect("chmod 640");
        match read_raw(&p) {
            Err(e @ GuardError::PermissionsTooOpen { .. }) => {
                assert!(format!("{e}").contains("chmod 600"));
            }
            other => panic!("a group-readable secret is rejected, and it gave: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
