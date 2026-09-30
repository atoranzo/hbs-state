# hbs-state

**The index guard for stateful hash-based signatures** (XMSS, XMSS^MT).
A monotonic counter persisted with `fsync`, a self-check that refuses to
operate where `fsync` does not really persist, and the reconciliation of the
state after a restart.

It is the **reference implementation of [HBS-STATE](spec/HBS-STATE-v0.3.md)**,
and it ships the binary that turns it into a subject its conformance bench
can measure.

## Why this exists

XMSS is a **stateful** scheme: every signature consumes an index, and
**reusing one leaks the key**.
[NIST SP 800-208](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)
approves the scheme and at the same time requires key and signature
generation to be validated only inside hardware modules, precisely because
the security depends on state management.

[RFC 10033](https://www.rfc-editor.org/rfc/rfc10033.html) picks that up: its
section 4 demands the four ACID properties over the state and recommends
dedicated hardware, verbatim, *"in particular, this enables implementing
rollback resistant counters, which can be difficult to achieve in a
software-only fashion"*; its section 5 gives nine state-management
strategies.

**And here is the gap this crate exists for: not one of the nine ships a
single executable vector.** Neither document offers anything with which an
implementation can say whether its reconciliation is correct. That is what
HBS-STATE is: not a post-quantum library, but the bench for the state.

This crate is that operational knowledge **in code, extracted from a
single-operator research prototype where it has been signing since August
2026**, with the vector bench that `spec/` defines and `tests/vectors.rs`
executes.

## Zero dependencies

```toml
[dependencies]
# none
[dev-dependencies]
# none either
```

One file, eight bytes and an order. The vector reader in
`tests/vectors.rs` is written by hand so that `serde` does not come in
through the back door. **If a line ever appears there, the promise is
broken.**

## What it does

```rust
use hbs_state::{IndexGuard, Reconciliation, reconcile_values};

let mut g = IndexGuard::open("state/index.bin")?;  // refuses on tmpfs
let i = g.reserve()?;                 // persists BEFORE returning
// ... sign with `i` ...

match g.reconcile(index_read_from_the_key) {
    Reconciliation::InSync { .. }       => {} // nothing to do
    Reconciliation::CounterAhead { .. } => {} // normal: orphans
    Reconciliation::KeyAtZero { .. }    => {} // indeterminate
    Reconciliation::KeyAhead { .. }     => {} // DO NOT START
}
```

The invariant, in one line:

> **No signature may exist with an index greater than the persisted
> counter.**

And the judge: of the four states, **only `KeyAhead` admits no nuance**. The
other three are each owner's policy.

## The self-check

`IndexGuard::open` **measures its own `fsync` at start-up** and refuses if
the cost is indistinguishable from not persisting. Measured on two
filesystems of the same machine:

| | cost of `fsync` | against not persisting |
|---|---|---|
| ext4 | 0.907 ms | **382x** |
| tmpfs | 0.002 ms | **1x** |

On `tmpfs`, `fsync` returns success without persisting anything. A guard
whose file ends up there is a no-op, and `/tmp` is a perfectly plausible
home for a file somebody considers auxiliary.

WARNING: the thresholds come from **one** machine and are **declared, not
derived**. The main discriminant is the ratio, not the absolute value.

## What it does NOT guarantee

**Nothing against a power cut.** *"`fsync` can lie"* is about disks that
confirm writes still sitting in volatile cache. What was measured is
durability against **process death** -- 25 of 25 with not one signature
ahead. That is not the same thing, and measuring it requires really cutting
the power.

## Running the bench against your own implementation

Any executable that speaks three invocations is a subject. The full contract
is in the specification's *subject protocol* section, and `--help` on the
verifier prints it too:

```
<subject> --model             -> {"sk_model": "persisted" | "seed_derived"}
<subject> <counter> <key>     -> {"state": "...", "<derived>": N, "fatal": b}
<subject> --sk <hex>          -> {"index": N}
```

One JSON line on stdout per invocation; only the **last** line is parsed. A
non-zero exit, empty stdout or a last line that is not JSON count as a
**failed** row, never as an absent one.

To run it against this crate:

```
cargo build --release
python3 spec/verify-state.py \
    --vectors spec/state-vectors-v0.3.json \
    --subject ./target/release/hbs-state-subject
```

The four conformance levels are **N0** declares its model, **N1**
classifies, **N2** derives, **N3** judges. N0 is not decoration: this guard
**does not persist the SK**, so after a real restart its state is always
`KeyAtZero`, while an implementation that does persist it will reach other
states and **will not be wrong** -- it will be in the other model. Without
knowing which model you are in, the other three levels are read wrongly.

## The specification-to-code tie

`spec/state-vectors-v0.3.json` and this crate are **two producers of the
same contract**, and `tests/vectors.rs` crosses them: the four states, their
derived fields, the judge, the index read and the parameter set. If one
moves without the other, `cargo test` goes red.

## Parameter set

`XMSSMT-SHA2_40/8_256` -- identifier `0x00000005` in SP 800-208, table 11.
**SK = 137 B = OID(4) + index(5, big-endian) + 4x32.** The index width is
`ceil(h/8)` and **depends on the parameter set**: in single-tree it is 4 and
the SK is 136.

WARNING: `index_width()` is fixed at 5. The ceiling of `set_index_in_sk` is
the **field's**, not the **tree's**, and they coincide only because
`h = 40 = 8x5`. For `h = 20` the field would admit 2^24-1 with only 2^20
leaves available: that is vector **B8**, which the specification declares
and this crate **does not cover yet**.

## A defect in a dependency of the ecosystem, declared

The **persisted SK** branch of the specification cannot be exercised
end-to-end against the Rust library available today: `xmss` resolves the OID
by trying single-tree first, and 21 of the 56 XMSSMT parameter sets load
wrongly because of it. Reported in
[RustCrypto/signatures#1442](https://github.com/RustCrypto/signatures/issues/1442).

It does not invalidate anything here -- the family A vectors are a pure
function of `(counter, key)` and never touch that path -- but it is declared
rather than hidden. And it must be said in full: `pq-xmss`, the same
author's continuation, **no longer carries** that defect.

## Provenance

Extracted from [ARQUEO][arqueo] (open conservation proofs for closed
ledgers), a single-operator research prototype -- no real money, no external
audit -- where the state guard has been signing since August 2026. This
crate is that piece, relabelled to the domain and with no dependencies.

(Until 2026-09-30 this section, the front page, `src/lib.rs` and the
specification said "in production for a year". Measured against the ARQUEO
record: the project's first session is dated 2026-07-29, XMSS entered its
tree in August 2026, and ARQUEO describes itself as a research prototype
with no real money and no external audit. The claim was false and is
withdrawn, cited here rather than deleted.)

`src/lib.rs`: 823 file lines, 505 with code. The method: line comments and
nested block comments, strings with escapes, raw strings `r#"..."#` and
character literals are all skipped; a naive counter gives the same figure on
this file, so it does not depend on the criterion. `tests/vectors.rs`
re-derives both figures from the source and falls if this README lags
behind.

## License

MIT OR Apache-2.0. The vectors under `spec/`, CC0-1.0.

[arqueo]: https://github.com/atoranzo/Arqueo-open-conservation-proofs-for-closed-ledgers
