# HBS-STATE v0.3 -- state reconciliation for stateful hash-based signatures

**What it is.** A minimal specification of ONE single property: how you
decide, after a restart, whether the state of a stateful hash-based
signature (XMSS, XMSS^MT, LMS, HSS) is still safe to use. Four states, one
judge, and numeric vectors any implementation can consume.

**What it is NOT.** It is not an XMSS implementation. It is not a parameter
profile. It does not replace NIST SP 800-208 or RFC 8391: it presupposes
them.

**Why it exists.** SP 800-208 approves XMSS and LMS and at the same time
requires key and signature generation to be validated only inside hardware
modules, because the security depends on state management. RFC 10033
(informational, September 2026) demands in its section 4 the four ACID
properties over the state and recommends dedicated hardware, verbatim, "in
particular, this enables implementing rollback resistant counters, which can
be difficult to achieve in a software-only fashion"; its section 5 gives
nine state-management strategies. **Not one of the nine ships a single
executable vector**, and neither document offers anything with which an
implementation can say whether its reconciliation is correct.

**Provenance.** MEASURED = taken byte by byte from a production
implementation (the ARQUEO index guard, XMSSMT-SHA2_40/8_256). DEDUCED =
this document's inference. In the v0.2 **the five deductions of the v0.1
were resolved against the source: all five CONFIRMED** (section 8). The v0.3
**moves not one row**: it grows in document and in conformance. The
`MEASURED v0.2` labels are kept because they say WHEN each row was measured,
and that does not expire.

---

## 0. CORRECTIONS -- they are cited, not deleted

### From the v0.2: a level that was declared and never measured

The v0.2 declared **N0** in its section 4 and wrote in its vectors file
`"sk_model": {"declaration_required": true, ...}` alongside
`"levels": {"N0": "declares its sk_model", ...}`. Its verifier **never asked
for the model**: zero occurrences of "model" in its 289 lines, and its own
help enumerated N1, N2 and N3. The reference subject answered `--model` to a
question nobody was asking.

**It was not an error of the text: it was a published contract with zero
executors**, and in the level its own section 4 calls foundational. It is
written down here, and from the v0.3 the verifier enforces N0: a subject
that does not declare its model is left WITHOUT LEVEL even if it classifies
all twelve rows.

### From the v0.1: a figure that measured something else

The v0.1 said, in its section 1:

> *"The mandatory order is reserve and persist, then sign. Hence the normal
> thing after a crash is for the counter to be ahead, not behind. MEASURED:
> 13 of 25 process deaths leave the counter ahead."*

**The second sentence is FALSE and stays written down as false.** The 13 of
25 is well measured, but it measures SOMETHING ELSE: deaths **inside a live
process**, not restarts. The source said so and it was not read -- the
specification was written from the body of a test without opening the enum
that explains it:

> *"This was measured INSIDE a process -- a child that persists and signs,
> killed at a random instant -- not after a RESTART. On restart the key goes
> back to zero and the case is `KeyAtZero`. The figure is correct; what it
> does not cover is the restart."*

Out of that correction comes the new section 1, which is the v0.2's main
contribution.

---

## 1. THE MISSING AXIS: where the key's index lives

Before classifying anything you have to answer **the zero question**:

> **After a restart, where does the index carried by the private key come
> from?**

There are two architectures, and they **determine which states are even
reachable**:

| | **SK PERSISTED** | **SK SEED-DERIVED** |
|---|---|---|
| what is on disk | the key material with its index inside | only the seed |
| on restart | the index survives | `from_seed` returns **index 0** |
| after a restart | `InSync`, `CounterAhead` or `KeyAhead` | **always `KeyAtZero`** |
| `CounterAhead` | the normal case after a crash | **INTRA-PROCESS only** |
| example | RustCrypto's `xmss` serialises the state to the caller | the ARQUEO guard |

MEASURED: *"The key comes from the seed and the counter says signing already
happened. The SK is not persisted: on restart, `from_seed` returns it at
ZERO."*

**Consequence for the bench:** a subject must DECLARE its model before
running the vectors. The same `(counter, key)` pairs describe different
moments depending on the model, and a seed-derived implementation that never
produces `CounterAhead` after a restart **is not incomplete: it is right**.

The model does not change the table in section 2 -- the classification is the
same -- but it changes **which rows can really be provoked in a real
restart**.

---

## 2. The four states

Let `counter` be what the project reserved and persisted, and `key` the
index carried inside the private key material.

| state | condition | derived field | fatal |
|---|---|---|---|
| `InSync` | `key == counter` | `index = counter` | no |
| `KeyAtZero` | `counter > key` **and** `key == 0` | `indeterminate = counter` | no |
| `CounterAhead` | `counter > key` and `key != 0` | `orphans = counter - key` | no |
| `KeyAhead` | `key > counter` | `unrecorded = key - counter` | **YES** |

**The four conditions, the four fields and the precedence are MEASURED**
against the source (section 8). The reference implementation resolves it
with a three-arm `match` on `counter.cmp(&key)` and **one guard**:
`Greater if key == 0`. That guard is the precedence.

### What each one means

- **`InSync`** -- nothing to reconcile.
- **`KeyAtZero`** -- the key was born again while the counter remembers prior
  use. Indices `0..counter-1` are left **INDETERMINATE**.
- **`CounterAhead`** -- indices were reserved that never got signed. The
  `orphans` are burnt or recorded; **the counter never goes back**.
- **`KeyAhead`** -- the key signed with indices the counter never recorded.
  **There are only two causes: the order was inverted, or `fsync` lied.**

### Why `KeyAtZero` cannot be resolved, only failed closed

It is not prudence: it is **indistinguishability**. MEASURED:

> *"with counter 1 and key 0, dying inside the reserve window and dying
> after signing leave the SAME state on disk"*

No datum on disk separates the innocent case from the dangerous one. It is
the sibling of the reason SP 800-208 requires hardware: a restored state is
indistinguishable from a legitimate one.

**Cost of getting it wrong** (MEASURED, QRL curve): at the **second reuse**
of an index, forging a signature costs on the order of **2^34 hashes**.

---

## 3. The judge

```
fatal(state) = (state is KeyAhead)
```

MEASURED: a four-arm `match`, three to `false` and one to `true`.

---

## 4. Conformance

An implementation **MEETS HBS-STATE v0.3** if it declares its model
(section 1) and, given `(counter, key)`, produces the state of section 2
with its exact derived field, and its judge marks exactly `KeyAhead` as
fatal.

- **N0 -- declares.** Says whether its SK is persisted or derived from a
  seed. Without this the other levels are read wrongly. **From the v0.3 the
  verifier enforces it**: whoever does not declare it is left without a
  level even if it classifies correctly.
- **N1 -- classifies.** Tells the four states apart.
- **N2 -- derives.** Gets `indeterminate`, `orphans`, `unrecorded` right.
- **N3 -- judges.** Refuses to operate on `KeyAhead`, and only there.

An implementation that merges `CounterAhead` with `KeyAhead` into a single
"state error" **does not meet N1**: it treats the normal case as the
catastrophic one, and whoever uses it will end up disabling the check.

### The subject protocol -- how an implementation presents itself for the exam

Until the v0.2 this lived ONLY in the verifier's docstring. A specification
that gives the conformance levels and does not say how to present yourself
repeats, one floor down, the very gap it holds against RFC 10033.

A **subject** is an executable. The verifier invokes it and reads **the LAST
line** of `stdout`, which must be JSON. It may print whatever it likes
before that.

| level | invocation | expected answer |
|---|---|---|
| N0 | `<subject> --model` | `{"sk_model": "persisted"` or `"seed_derived"}` |
| N1-N3 | `<subject> <counter> <key>` | `{"state": "<one of the four>", "<derived field>": N, "fatal": true\|false}` |
| family B | `<subject> --sk <hex of the key material>` | `{"index": N}` |

Contract rules, all fail-closed:

- a non-zero exit code, empty `stdout`, or a last line that is not JSON:
  **the row counts as failed**, never as absent;
- derived fields that do not apply **are omitted**; `fatal` is optional, but
  without it **N3 cannot be scored**;
- the value of `sk_model` must be one of those the vectors file declares in
  `sk_model.values`: an invented one **fails N0**;
- each invocation has at most 60 seconds.

**The model does NOT change the exam.** It excuses the OPERATIONAL ABSENCE
of a state after a restart -- a seed-derived implementation that never
produces `CounterAhead` after restarting is not incomplete -- but it excuses
no classification error: family A is scored the same for both models,
because the rule is a pure function of `(counter, key)`.

---

## 5. Family A -- reconciliation

| # | counter | key | state | derived | provenance |
|---|---|---|---|---|---|
| A1 | 0 | 0 | `InSync` | `index=0` | **MEASURED v0.2** |
| A2 | 7 | 7 | `InSync` | `index=7` | MEASURED |
| A3 | 2 | 2 | `InSync` | `index=2` | MEASURED |
| A4 | 7 | 5 | `CounterAhead` | `orphans=2` | MEASURED |
| A5 | 9 | 7 | `CounterAhead` | `orphans=2` | MEASURED |
| A6 | 1 | 0 | `KeyAtZero` | `indeterminate=1` | **MEASURED v0.2** |
| A7 | 5 | 0 | `KeyAtZero` | `indeterminate=5` | MEASURED |
| A8 | 1 | 9 | `KeyAhead` | `unrecorded=8` | MEASURED |
| A9 | 3 | 9 | `KeyAhead` | `unrecorded=6` | MEASURED |
| A10 | 0 | 1 | `KeyAhead` | `unrecorded=1` | **MEASURED v0.2** |
| A11 | 2^40-1 | 2^40-1 | `InSync` | `index=2^40-1` | **MEASURED v0.2** |
| A12 | 2^40-2 | 2^40-1 | `KeyAhead` | `unrecorded=1` | **MEASURED v0.2** |

The five marked **v0.2** were DEDUCED in the v0.1 and are resolved.

---

## 6. Family B -- reading the index out of the format (RFC 8391)

`XMSSMT-SHA2_40/8_256` (id `0x00000005`, SP 800-208 table 11):
**SK = 137 B = OID(4) + index(5, big-endian) + 4x32**. The width is
`ceil(h/8)` and **depends on the parameter set**: in single-tree it is 4 and
the SK is 136.

| # | bytes (BE) | value |
|---|---|---|
| B1 | `00 00 00 00 01` | 1 |
| B2 | `00 00 00 01 00` | 256 |
| B3 | `00 00 01 00 00` | 65 536 |
| B4 | `00 01 00 00 00` | 16 777 216 |
| B5 | `01 00 00 00 00` | 4 294 967 296 |
| B6 | `ff ff ff ff ff` | 1 099 511 627 775 |

| # | write | result |
|---|---|---|
| B7 | 2^40 | error `IndexOutOfField{index, width:5}` **and not one byte is touched** |

B7 is a **fail-closed** vector: rejecting is not enough, you must not write.

### BOUND on B7, measured in the v0.2

B7's ceiling belongs to the **FIELD, not to the TREE**. The source:
`if width < 8 && index >= (1u64 << (8 * width))`. The two coincide **only if
`h` is a multiple of 8**, and here it is: `h = 40 = 8 x 5`.

> MEASURED: *"with an `h` that were not a multiple of 8 the ceiling would be
> loose from above and would have to be tied to the real height"*

So for `h = 20` the width is 3 bytes: the field admits up to 2^24-1 while
the tree has only 2^20 leaves. **There is a gap of indices that fit in the
field and do not exist in the tree.** No known implementation covers it.

**B8 (CANDIDATE, unmeasured)**: in a parameter set with `h` not a multiple
of 8, writing `2^h` must fail even though it fits in the field. It is the
first row this specification asks for that its own originating
implementation **does not have**.

---

## 7. Family C -- CANDIDATE: the on-disk state before reading it

Not specified yet. The reference implementation declares seven further
errors that are, each of them, a bench row:

| error | why it is a row |
|---|---|
| `PermissionsTooOpen{path,mode}` | **checked ON READ**: creating with `0600` does not stop someone loosening it later |
| `FakePersistence{with_fsync_us,without_fsync_us,ratio}` | measures whether `fsync` costs anything; if not, it does not persist (tmpfs) |
| `Corrupt{bytes}` | the counter file exists and does not hold the bytes it must |
| `UnexpectedLayout{sk_len,expected}` | the serialisation of the library underneath changed |
| `SeedLength{...,looks_hex}` | tells apart **the mistake people actually make** |
| `SeedHexLength{expected_chars,found_chars}` | CHARACTERS are counted: with integer division **193 said 96** |
| `SeedNotHex{detail}` | -- |

`FakePersistence` is the most interesting one for a standard: **it is the
only one that checks the world, not the format.**

---

## 8. The five deductions of the v0.1: RESOLVED

| # | v0.1 claim | verdict | source |
|---|---|---|---|
| D1 | `KeyAtZero` wins over `CounterAhead` when `key == 0` | **CONFIRMED** | `Greater if key == 0` before the general `Greater` |
| D2 | `(0,0)` is `InSync` | **CONFIRMED** | `cmp` gives `Equal` |
| D3 | `indeterminate == counter` | **CONFIRMED** | `indeterminados: self.actual` -- one term, not a subtraction |
| D4 | `(0,1)` is `KeyAhead` | **CONFIRMED** | `cmp` gives `Less`; `counter == 0` gets no special treatment |
| D5 | there is no exhaustion variant | **CONFIRMED** | four variants, none about exhaustion |

D3 was **undecidable by vectors** (with `key == 0`, `counter` and
`counter - key` give the same number). It was resolved by reading, which is
what the v0.1 said would have to be done.

---

## 9. What this specification does NOT cover

- **How the counter is persisted**: `fsync`, ordering, locks, copies.
- **Policy**: what to do with the orphans belongs to the owner; here the
  only requirement is not going back.
- **Multiple signers** over the same public key.
- **LMS/HSS**: the table ought to hold; it has not been tested.
- **Family C** (section 7) and **B8** (section 6): declared, without
  vectors.

### What a FOREIGN defect prevents from being exercised today

The **SK PERSISTED** branch of section 1 is specified and **cannot be
exercised end-to-end** against the Rust library available today. Measured on
`xmss` main `72ebaa1` (2026-09-14), `xmss/src/xmss.rs:21`:

```rust
let oid = XmssOid::try_from(raw_oid)
              .or_else(|_| XmssOid::from_xmssmt_raw_oid(raw_oid))?;
```

RFC 8391 keeps TWO separate OID registries and both start at 1, so four
bytes on their own are ambiguous. Single-tree is tried first; when the raw
OID of a multi-tree key also names a single-tree parameter set, the
`try_from` succeeds, the `or_else` is never reached, and the load fails
against `expected_oid`. **Measured scope: 21 of the 56 XMSSMT parameter
sets.** Published as `RustCrypto/signatures` issue 1442.

This **does not invalidate the specification**: it bounds it. The section 5
vectors are a pure function of `(counter, key)` and never touch that path.
What cannot be measured today is the full cycle of a **persisted** subject
loading its own multi-tree SK. It is declared, not hidden.

**And it must be said in full**: `pq-xmss`, the same author's continuation,
**no longer carries** that defect -- it compares the raw OID against the
parameter's instead of guessing by order of attempt. Presenting the defect
without saying so would be arriving badly informed.

---

## 10. Status

**v0.3 -- DRAFT.** Derived from **one single** implementation. The v0.1 had
five unchecked claims and they are resolved; the v0.2 declared a level its
own verifier did not measure, and from the v0.3 it measures it. What is
still missing is the only thing that turns this into a standard: **a second
INDEPENDENT subject measured against these vectors.** Until then it
describes a programme.

### The second subject: what is measured, with its universe in the same sentence

The candidate the v0.2 declared, `oxicrypt-xmss`, is **EXPIRED**: measured on
crates.io, versions 0.22.0 to 0.23.2 are **yanked** and 0.24.0 is
**verification only**, so it has no state to reconcile.

The candidate that applies today is **`pq-xmss` 0.2.0** (repository
`mikelodder7/pq-xmss`, Apache-2.0 OR MIT, published 2026-08-25, not yanked).
It has `TryFrom<&[u8]> for SigningKey`, XMSSMT parameter sets and
`KeyPair::generate`, so family B applies to it. It exposes neither `index()`
nor `remaining()`.

**BUT it would not be a second IMPLEMENTER.** Measured by cloning both
sources: the same author in both `Cargo.toml` files, and `hash_address.rs`
(65 lines) and `utils.rs` (19 lines) **identical byte for byte**. It is the
same lineage moved to another repository and extended: there is a second
**crate**, not a second **implementer**, and a bench with two subjects by
the same author **gives no comparative verdict**.

**Universe, in the same sentence:** of the 19 results of the `xmss` query on
crates.io, TWO sources have been opened, a third was measured yanked, and
**SIXTEEN remain unopened**.

### License

The vectors under `spec/`, CC0-1.0. Everything else, MIT OR Apache-2.0. It
is no longer a suggestion: the files are in the tree.

# END-HBS-STATE-v0.3
