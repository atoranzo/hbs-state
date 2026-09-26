//! **The TIE between the specification and the code.**
//!
//! `spec/state-vectors-v0.3.json` and this crate are TWO PRODUCERS of the
//! same contract. If one moves without the other, this goes red.
//!
//! WARNING: the JSON reader is written BY HAND, without `serde`: this
//! crate's promise is ZERO dependencies, and slipping them in through
//! `[dev-dependencies]` would break it by the back door. It is not a general
//! JSON parser: it is a reader of OURS, and that is why it **asserts how
//! many rows it finds**. If the format changes, the count changes and the
//! test falls.

use hbs_state::{reconcile_values, Reconciliation};

const VECTORS_PATH: &str = "spec/state-vectors-v0.3.json";

/// How many rows the `reconciliation` collection must carry. DECLARED: if
/// the file grows, this number is moved by hand and shows up in the diff.
const EXPECTED_ROWS_A: usize = 12;

/// Likewise for `index_read`.
const EXPECTED_ROWS_B: usize = 6;

/// Likewise for `out_of_field_write`. It had ONE vector and ZERO
/// executors: the behaviour was asserted inside `lib.rs`, so the JSON and
/// that test were TWO PRODUCERS of the same contract with nothing tying
/// them together. This ties them.
const EXPECTED_ROWS_C: usize = 1;

/// Returns the slice between `"<key>": [` and the `]` that closes it at the
/// same bracket depth.
fn collection<'a>(doc: &'a str, key: &str) -> &'a str {
    let mark = format!("\"{key}\": [");
    let i = doc
        .find(&mark)
        .unwrap_or_else(|| panic!("collection {key} is not in {VECTORS_PATH}"))
        + mark.len();
    let rest = &doc[i..];
    let mut depth = 1usize;
    for (n, c) in rest.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[..n];
                }
            }
            _ => {}
        }
    }
    panic!("collection {key} never closes");
}

/// The top-level `{...}` objects inside a collection.
fn objects(col: &str) -> Vec<&str> {
    let mut v = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (n, c) in col.char_indices() {
        match c {
            '{' => {
                if depth == 0 {
                    start = n;
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    v.push(&col[start..=n]);
                }
            }
            _ => {}
        }
    }
    v
}

fn number(obj: &str, field: &str) -> Option<u64> {
    let m = format!("\"{field}\": ");
    let i = obj.find(&m)? + m.len();
    let rest = &obj[i..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    rest[..end].parse().ok()
}

fn text(obj: &str, field: &str) -> Option<String> {
    let m = format!("\"{field}\": \"");
    let i = obj.find(&m)? + m.len();
    let rest = &obj[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn name_of(r: &Reconciliation) -> &'static str {
    match r {
        Reconciliation::InSync { .. } => "InSync",
        Reconciliation::CounterAhead { .. } => "CounterAhead",
        Reconciliation::KeyAtZero { .. } => "KeyAtZero",
        Reconciliation::KeyAhead { .. } => "KeyAhead",
    }
}

fn derived_of(r: &Reconciliation) -> (&'static str, u64) {
    match r {
        Reconciliation::InSync { index } => ("index", *index),
        Reconciliation::CounterAhead { orphans, .. } => ("orphans", *orphans),
        Reconciliation::KeyAtZero { indeterminate, .. } => ("indeterminate", *indeterminate),
        Reconciliation::KeyAhead { unrecorded, .. } => ("unrecorded", *unrecorded),
    }
}

fn doc() -> String {
    std::fs::read_to_string(VECTORS_PATH).unwrap_or_else(|e| {
        panic!("cannot read {VECTORS_PATH}: {e}. The test runs from the crate root.")
    })
}

#[test]
fn the_json_reader_sees_every_row() {
    // WARNING: the liveness probe of the reader itself: without this, a
    // broken reader returning zero rows would make every other test pass on
    // an empty universe.
    let d = doc();
    assert_eq!(
        objects(collection(&d, "reconciliation")).len(),
        EXPECTED_ROWS_A,
        "the reader does not see the rows the file declares"
    );
    assert_eq!(
        objects(collection(&d, "index_read")).len(),
        EXPECTED_ROWS_B
    );
}

#[test]
fn family_a_in_the_spec_matches_the_code() {
    let d = doc();
    let rows = objects(collection(&d, "reconciliation"));
    assert_eq!(rows.len(), EXPECTED_ROWS_A);
    let mut seen = 0;
    for o in rows {
        let id = text(o, "id").expect("id");
        let c = number(o, "counter").expect("counter");
        let k = number(o, "key").expect("key");
        let expected = text(o, "state").expect("state");
        let r = reconcile_values(c, k);
        assert_eq!(name_of(&r), expected, "{id}: ({c},{k}) gives another state");
        let (field, value) = derived_of(&r);
        let in_json = number(o, field)
            .unwrap_or_else(|| panic!("{id}: the vector does not declare `{field}`"));
        assert_eq!(value, in_json, "{id}: field `{field}` disagrees");
        seen += 1;
    }
    assert_eq!(seen, EXPECTED_ROWS_A);
}

#[test]
fn the_judge_in_the_spec_matches_the_code() {
    let d = doc();
    for o in objects(collection(&d, "reconciliation")) {
        let id = text(o, "id").expect("id");
        let c = number(o, "counter").expect("counter");
        let k = number(o, "key").expect("key");
        let fatal_in_json = o.contains("\"fatal\": true");
        assert_eq!(
            hbs_state::is_fatal(&reconcile_values(c, k)),
            fatal_in_json,
            "{id}: the judge disagrees with the vector"
        );
    }
}

#[test]
fn family_b_in_the_spec_matches_the_code() {
    // The SK is assembled as the verifier assembles it: OID + index + zeros.
    let d = doc();
    let rows = objects(collection(&d, "index_read"));
    assert_eq!(rows.len(), EXPECTED_ROWS_B);
    for o in rows {
        let id = text(o, "id").expect("id");
        let hex = text(o, "bytes_hex").expect("bytes_hex");
        let value = number(o, "value").expect("value");
        let mut sk = vec![0u8, 0, 0, 5];
        for i in 0..hex.len() / 2 {
            sk.push(u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"));
        }
        sk.extend(std::iter::repeat(0u8).take(4 * 32));
        assert_eq!(
            hbs_state::index_from_sk(&sk).expect("read"),
            value,
            "{id}: the reader does not give the vector's value"
        );
    }
}

/// The TIE for vector B7. WARNING: `index_width()` is NOT public, so the
/// width is taken from the JSON and checked AGAINST THE CODE by behaviour,
/// not against another copy of the number.
#[test]
fn out_of_field_write_in_the_spec_matches_the_code() {
    let d = doc();
    let rows = objects(collection(&d, "out_of_field_write"));
    assert_eq!(
        rows.len(),
        EXPECTED_ROWS_C,
        "the out_of_field_write collection changed size"
    );
    for o in rows {
        let id = text(o, "id").expect("id");
        let write_value = number(o, "write").expect("write");
        let err = text(o, "error").expect("error");
        let expected_index =
            number(o, "index").expect("error_fields.index");
        let expected_width =
            number(o, "width").expect("error_fields.width");
        // The SK is assembled as the verifier assembles it: 137 = OID(4)
        // + index(5) + 4*32. If that sum moves, the test falls by itself.
        let mut sk = vec![0u8; 4 + expected_width as usize + 4 * 32];
        let before = sk.clone();
        match hbs_state::set_index_in_sk(&mut sk, write_value) {
            Err(hbs_state::GuardError::IndexOutOfField {
                index,
                width,
            }) => {
                assert_eq!(
                    err, "IndexOutOfField",
                    "{id}: the vector names another error"
                );
                assert_eq!(
                    index, expected_index,
                    "{id}: the error does not name the vector's index"
                );
                assert_eq!(
                    width as u64, expected_width,
                    "{id}: the error does not name the vector's width"
                );
            }
            other => panic!(
                "{id}: writing {write_value} into a field of \
                 {expected_width} byte(s) MUST NOT succeed: {other:?}"
            ),
        }
        // The vector's "and_also": not one byte of the key material is
        // modified. FAIL-CLOSED: rejecting is not enough.
        assert_eq!(
            sk, before,
            "{id}: it rejected, but it touched the key material"
        );
    }
}

/// WARNING: THE CONTROL for the tie above. If `set_index_in_sk` accepted
/// anything at all, the B7 test would go through the error branch with
/// nothing proving that the GOOD path works. A falsifier that does not
/// discriminate proves nothing.
#[test]
fn control_for_b7_the_largest_index_that_fits_is_written_and_read() {
    let d = doc();
    let o = objects(collection(&d, "out_of_field_write"))[0];
    let width = number(o, "width").expect("width") as usize;
    let mut sk = vec![0u8; 4 + width + 4 * 32];
    let fits = number(o, "write").expect("write") - 1;
    hbs_state::set_index_in_sk(&mut sk, fits)
        .expect("the largest index that fits MUST be written");
    assert_eq!(
        hbs_state::index_from_sk(&sk).expect("read"),
        fits,
        "writer and reader disagree at the field ceiling"
    );
}

#[test]
fn the_parameter_set_the_spec_names_is_the_one_this_crate_implements() {
    // WARNING: if somebody changes `index_width()` and not the JSON, this falls.
    let d = doc();
    assert!(d.contains("\"sk_bytes\": 137"), "the JSON declares another SK");
    assert!(d.contains("\"index_width\": 5"), "the JSON declares another width");
    // Checked against the CODE, not against another copy of the number:
    // an SK of 137 is read and one of 136 is rejected.
    assert!(hbs_state::index_from_sk(&vec![0u8; 137]).is_ok());
    assert!(hbs_state::index_from_sk(&vec![0u8; 136]).is_err());
}


/// **The TIE for the figure the README PUBLISHES.**
///
/// This was paid for by a published figure the tree did not re-derive: the
/// README said 487 -- which is the ORIGINAL ARQUEO guardian, a different
/// file -- while this `lib.rs` measures something else. Fixing the text
/// without tying it leaves it one commit away from happening again, because
/// nothing would warn.
///
/// IT DECLARES ITS OWN BLINDNESS: the count here is the NAIVE one, not the
/// state scanner that produced the figure. What is checked is exactly the
/// claim the README makes ABOUT ITSELF -- "a naive counter gives the same
/// figure on this file" -- and not the scanner's semantics. If the two ever
/// stop agreeing this falls, and rightly so: at that moment the published
/// sentence would have stopped being true.
#[test]
fn the_figure_the_readme_publishes_is_rederived_from_the_source() {
    const README_MD: &str = include_str!("../README.md");
    const SOURCE: &str = include_str!("../src/lib.rs");

    let (published_file_lines, published_code_lines) = published_figures(README_MD);
    let file_lines = SOURCE.matches('\n').count();
    let code_lines = naive(SOURCE);

    assert_eq!(
        published_file_lines, file_lines,
        "the README publishes {published_file_lines} file lines and src/lib.rs has {file_lines}"
    );
    assert_eq!(
        published_code_lines, code_lines,
        "the README publishes {published_code_lines} lines with code and the naive \
         counter gives {code_lines} over src/lib.rs"
    );

    // CONTROL: the extractor has to READ the text, not return a constant.
    // On a probe with different figures it must give different figures; if
    // it gave the same ones, the assert above would prove nothing.
    let probe_line = format!("`src/lib.rs`: {} file lines, {} with code.\n",
                        file_lines + 1, code_lines + 7);
    assert_eq!(
        published_figures(&probe_line),
        (file_lines + 1, code_lines + 7),
        "the extractor is not reading the text it is given"
    );
}

/// The two figures the README publishes about `src/lib.rs`, in order.
fn published_figures(t: &str) -> (usize, usize) {
    let line = t
        .lines()
        .find(|l| l.starts_with("`src/lib.rs`: "))
        .expect("the README does not publish the figures line for `src/lib.rs`");
    let mut ns = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<usize>().expect("unreadable figure in the README"));
    (
        ns.next().expect("the file-lines figure is missing"),
        ns.next().expect("the code-lines figure is missing"),
    )
}

/// The NAIVE counter, on purpose: it is the one the README names.
fn naive(src: &str) -> usize {
    src.lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with("//")
        })
        .count()
}
