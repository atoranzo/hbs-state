//! `hbs-state-subject` -- this crate as a SUBJECT of the HBS-STATE bench.
//!
//! It speaks the protocol `verify-state.py` expects, so that this
//! implementation can be measured exactly like any other. It is not an
//! operational tool: it is the bench's mouthpiece.
//!
//! ```text
//!   hbs-state-subject <counter> <key>   -> {"state":"...", ..., "fatal":b}
//!   hbs-state-subject --sk <hex>        -> {"index": N}
//!   hbs-state-subject --model           -> {"sk_model":"..."}
//! ```
//!
//! Every invocation writes ONE JSON line on stdout and exits 0. A non-zero
//! exit, empty stdout, or a last line that is not JSON all count as a failed
//! row -- never as an absent one.
//!
//! WARNING: **it touches neither disk nor keys.** Family A is a pure function
//! of two numbers and family B is offset arithmetic, which is why the subject
//! can run the whole bench without real key material.

use hbs_state::{index_from_sk, reconcile_values, Reconciliation};

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn out_a(r: &Reconciliation) -> String {
    // By hand and not with serde: this crate has no dependencies, and the
    // binary that measures it cannot have any either without breaking that
    // promise through the back door.
    match r {
        Reconciliation::InSync { index } => format!(
            "{{\"state\":\"InSync\",\"index\":{index},\"fatal\":false}}"
        ),
        Reconciliation::CounterAhead { counter, key, orphans } => format!(
            "{{\"state\":\"CounterAhead\",\"counter\":{counter},\
             \"key\":{key},\"orphans\":{orphans},\"fatal\":false}}"
        ),
        Reconciliation::KeyAtZero { counter, indeterminate } => format!(
            "{{\"state\":\"KeyAtZero\",\"counter\":{counter},\
             \"indeterminate\":{indeterminate},\"fatal\":false}}"
        ),
        Reconciliation::KeyAhead { counter, key, unrecorded } => format!(
            "{{\"state\":\"KeyAhead\",\"counter\":{counter},\
             \"key\":{key},\"unrecorded\":{unrecorded},\"fatal\":true}}"
        ),
    }
}

fn from_hex(h: &str) -> Result<Vec<u8>, String> {
    let h = h.trim().trim_start_matches("0x");
    if h.len() % 2 != 0 {
        return Err(format!("hex of odd length: {}", h.len()));
    }
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();

    if a.len() == 1 && a[0] == "--model" {
        // WARNING: the ZERO QUESTION of HBS-STATE. This guard does not
        // persist the SK: the key is derived from the seed, so on restart it
        // comes back at index 0.
        println!("{{\"sk_model\":\"seed_derived\"}}");
        return;
    }

    if a.len() == 2 && a[0] == "--sk" {
        match from_hex(&a[1]) {
            Ok(b) => match index_from_sk(&b) {
                Ok(i) => println!("{{\"index\":{i}}}"),
                Err(e) => {
                    println!("{{\"error\":\"{}\"}}", escape(&e.to_string()));
                    std::process::exit(1);
                }
            },
            Err(e) => {
                println!("{{\"error\":\"{}\"}}", escape(&e));
                std::process::exit(1);
            }
        }
        return;
    }

    if a.len() == 2 {
        match (a[0].parse::<u64>(), a[1].parse::<u64>()) {
            (Ok(c), Ok(k)) => println!("{}", out_a(&reconcile_values(c, k))),
            _ => {
                println!("{{\"error\":\"both arguments must be u64 integers\"}}");
                std::process::exit(2);
            }
        }
        return;
    }

    eprintln!(
        "usage:\n  hbs-state-subject <counter> <key>\n  \
         hbs-state-subject --sk <hex>\n  hbs-state-subject --model"
    );
    std::process::exit(2);
}
