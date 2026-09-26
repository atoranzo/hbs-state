#!/usr/bin/env python3
"""verify-state -- runs the HBS-STATE vectors against an implementation.

Without --subject it runs against the REFERENCE implementation carried
inside (the rule from the "four states" section of the document). That
proves NOTHING about anyone: it proves the vectors and the rule agree with
each other. The value is in --subject.

SUBJECT PROTOCOL (N0, the zero question):
  invoked as:  <command> --model
  must write ONE JSON line on stdout: {"sk_model": "<value>"}
  where <value> is one of those the vectors file declares in
  `sk_model.values`. The file marks it `declaration_required`, and the
  document says that without it the other levels are read wrongly.
  NOTE: the model does NOT change the exam. It excuses the OPERATIONAL
  ABSENCE of a state after a restart, never a classification error.

SUBJECT PROTOCOL (family A, reconciliation):
  invoked as:  <command> <counter> <key>
  must write ONE JSON line on stdout:
     {"state": "InSync|CounterAhead|KeyAtZero|KeyAhead",
      "index": N | "orphans": N | "indeterminate": N | "unrecorded": N,
      "fatal": true|false}
  Derived fields that do not apply are omitted. `fatal` is optional, but
  without it N3 cannot be scored.

SUBJECT PROTOCOL (family B, reading the index):
  invoked as:  <command> --sk <hex of the private key material>
  must write ONE JSON line on stdout: {"index": N}

IN ALL THREE, fail-closed: a non-zero exit code, empty stdout, or a last
line that is not JSON count as a FAILED row, never as an absent one. Only
the LAST line of stdout is parsed, so a subject may print whatever it likes
before it. Each invocation has 60 seconds.

LEVELS
  N0 declares its sk_model
  N1 classifies the four states
  N2 also gets the derived fields right
  N3 also marks exactly KeyAhead as fatal

rc: 0 the subject meets N0 and N3 | 1 meets less | 2 usage or vectors error
"""

import argparse
import glob
import json
import os
import subprocess
import sys


def reference(counter, key):
    """The rule from the "four states" section.

    The precedence of KeyAtZero over CounterAhead when key == 0 is MEASURED,
    not deduced: it is deduction D1 of the v0.1, CONFIRMED in the document's
    resolved-deductions section against the source guard `Greater if key ==
    0` placed before the general `Greater` arm. (Until the v0.2 this comment
    said it was still a deduction and pointed at the wrong section.)
    """
    if key == counter:
        return {"state": "InSync", "index": counter, "fatal": False}
    if key == 0 and counter > 0:
        return {"state": "KeyAtZero", "indeterminate": counter,
                "fatal": False}
    if key < counter:
        return {"state": "CounterAhead", "orphans": counter - key,
                "fatal": False}
    return {"state": "KeyAhead", "unrecorded": key - counter,
            "fatal": True}


def reference_index(sk_hex, offset, width):
    b = bytes.fromhex(sk_hex)
    if len(b) < offset + width:
        return {"error": "sk shorter than offset+width"}
    return {"index": int.from_bytes(b[offset:offset + width], "big")}


def call(command, args):
    try:
        r = subprocess.run(command + args, capture_output=True, text=True,
                           timeout=60)
    except Exception as e:                                    # noqa: BLE001
        return None, "could not invoke: " + str(e)
    if r.returncode != 0:
        return None, "rc=%d  stderr: %s" % (r.returncode,
                                            (r.stderr or "").strip()[:200])
    out = (r.stdout or "").strip()
    if not out:
        return None, "empty stdout"
    line = out.split("\n")[-1].strip()
    try:
        return json.loads(line), ""
    except Exception as e:                                    # noqa: BLE001
        return None, "stdout is not JSON: " + str(e) + " | " + line[:120]


def main():
    ap = argparse.ArgumentParser(
        add_help=True, description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vectors", default=None)
    ap.add_argument("--subject", default=None,
                    help="the subject's command; without it, the reference runs")
    ap.add_argument("--only", choices=["A", "B", "AB"], default="AB")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    # The default is DERIVED from this script's directory, never typed. The
    # typed line used to name a vectors file that is not in the crate, so
    # running without --vectors exited with code 2. A typed version expires
    # at every v0.N+1; the file that IS THERE does not.
    # With two or more candidates there is NO choosing by order: --vectors
    # becomes mandatory. That is deliberate: picking the newest by name
    # would silently run a subject against vectors it never saw.
    if a.vectors is None:
        here = os.path.dirname(os.path.abspath(__file__))
        cand = sorted(glob.glob(os.path.join(
            here, "state-vectors-v*.json")))
        if len(cand) != 1:
            print("rc=2  next to this script there are " + str(len(cand)) +
                  " state-vectors-v*.json files; pass --vectors")
            return 2
        a.vectors = cand[0]

    try:
        with open(a.vectors, encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:                                    # noqa: BLE001
        print("rc=2  cannot read the vectors: " + str(e))
        return 2
    if doc.get("schema") not in ("hbs-state/0.2", "hbs-state/0.3"):
        print("rc=2  unknown schema: " + str(doc.get("schema")))
        return 2

    command = a.subject.split() if a.subject else None
    who = " ".join(command) if command else "(REFERENCE implementation)"
    ps = doc["reference_parameter_set"]

    print("=" * 74)
    # The version is DERIVED from the file's schema, never typed: the header
    # used to say v0.1 while running v0.2 vectors. A label that does not look
    # at the data it accompanies is the class of defect this bench exists to
    # catch in others.
    ver = str(doc.get("schema", "?")).split("/")[-1]
    print("HBS-STATE v" + ver +
          " -- conformance of state reconciliation")
    print("=" * 74)
    print("  subject  : " + who)
    print("  vectors  : " + a.vectors)
    print("  set      : " + ps["name"] + "  (id " +
          ps["sp800_208_identifier"] + ", SK " + str(ps["sk_bytes"]) +
          " B, index in [" + str(4) + "," + str(4 + ps["index_width"]) +
          ") BE)")
    if not command:
        print("  WARNING: without --subject this only checks that the")
        print("           vectors and the document's rule agree. It says")
        print("           nothing about any real implementation.")
    print()

    # N0 -- THE ZERO QUESTION. The vectors file declares it MANDATORY and
    # this verifier did not ask it: the JSON, the document and the reference
    # subject all had it, and the executor did not.
    mdl = doc.get("sk_model", {})
    values = mdl.get("values", [])
    n0_ok = None            # None = BLIND: there is no subject to ask
    n0_model = None
    n0_reason = ""
    if command and mdl.get("declaration_required"):
        got, err = call(command, ["--model"])
        if got is None:
            n0_ok, n0_reason = False, err
        elif "sk_model" not in got:
            n0_ok, n0_reason = False, "the answer carries no 'sk_model'"
        elif got["sk_model"] not in values:
            n0_ok = False
            n0_reason = ("declares '%s', which is not one of %s"
                         % (got["sk_model"], values))
        else:
            n0_ok, n0_model = True, got["sk_model"]

    if mdl:
        print("-" * 74)
        print("N0 -- THE ZERO QUESTION: " + mdl.get("question", "the SK model"))
        print("-" * 74)
        if n0_ok is None:
            print("  BLIND: without --subject there is nobody to ask.")
            print("  N0 is not scored, and it is not taken as passed.")
        elif n0_ok:
            reach = mdl.get(n0_model, {}).get("reachable_after_restart", [])
            print("  declares : " + n0_model)
            if reach:
                print("  after a restart this model reaches: " + ", ".join(reach))
            note = mdl.get(n0_model, {}).get("note")
            if note:
                print("  note     : " + note)
            print("  NOTE: the model does NOT change the exam. It excuses the")
            print("  OPERATIONAL absence of a state, not a classification")
            print("  error: family A is scored the same for both models.")
        else:
            print("  FAILS: " + n0_reason)
            print("  The vectors file declares it mandatory, and the document")
            print("  says that without it the other levels are read wrongly.")
        print()

    n1 = n2 = n3 = 0
    total_a = 0
    failures = []

    if a.only in ("A", "AB"):
        print("-" * 74)
        print("FAMILY A -- reconciliation")
        print("-" * 74)
        print("  %-4s %-15s %-15s %-38s %-32s %s" %
              ("id", "counter", "key", "expected", "seen", "lvl"))
        for v in doc["reconciliation"]:
            total_a += 1
            c, k = v["counter"], v["key"]
            if command:
                got, err = call(command, [str(c), str(k)])
                if got is None:
                    print("  %-4s %-15d %-15d %-38s %-32s FAILED: %s" %
                          (v["id"], c, k, v["state"], "-", err[:40]))
                    failures.append((v["id"], "invocation", err))
                    continue
            else:
                got = reference(c, k)

            state_ok = got.get("state") == v["state"]
            derived_ok = state_ok and all(got.get(x) == y
                                          for x, y in v["derived"].items())
            fatal_ok = (derived_ok and "fatal" in got and
                        got["fatal"] == v["fatal"])
            n1 += 1 if state_ok else 0
            n2 += 1 if derived_ok else 0
            n3 += 1 if fatal_ok else 0

            mark = "N3" if fatal_ok else ("N2" if derived_ok else
                                          ("N1" if state_ok else "FAILS"))
            derived_txt = ",".join("%s=%s" % (x, y)
                                   for x, y in v["derived"].items())
            seen_txt = got.get("state", "?")
            extra = [x for x in ("index", "orphans", "indeterminate",
                                 "unrecorded") if x in got]
            if extra:
                seen_txt += "/" + ",".join("%s=%s" % (x, got[x])
                                           for x in extra)
            print("  %-4s %-15d %-15d %-38s %-32s %s%s" %
                  (v["id"], c, k, v["state"] + "/" + derived_txt,
                   seen_txt[:32], mark,
                   "  [" + v["provenance"] + "]" if a.verbose else ""))
            if not fatal_ok:
                failures.append((v["id"], v["state"] + "/" + derived_txt,
                                 json.dumps(got)))

    nb = 0
    total_b = 0
    if a.only in ("B", "AB"):
        print()
        print("-" * 74)
        print("FAMILY B -- reading the index out of the format (RFC 8391)")
        print("-" * 74)
        oid = b"\x00\x00\x00\x05"
        padding = b"\x00" * (4 * ps["n"])
        for v in doc["index_read"]:
            total_b += 1
            sk = (oid + bytes.fromhex(v["bytes_hex"]) + padding).hex()
            if command:
                got, err = call(command, ["--sk", sk])
                if got is None:
                    print("  %-5s %-12s FAILED: %s" % (v["id"],
                                                       v["bytes_hex"], err))
                    failures.append((v["id"], "invocation", err))
                    continue
            else:
                got = reference_index(sk, 4, ps["index_width"])
            ok = got.get("index") == v["value"]
            nb += 1 if ok else 0
            print("  %-5s %-12s expected %-16d seen %-16s %s" %
                  (v["id"], v["bytes_hex"], v["value"],
                   str(got.get("index")), "OK" if ok else "FAILS"))
            if not ok:
                failures.append((v["id"], str(v["value"]), json.dumps(got)))
        print()
        print("  NOTE: the SK is assembled as OID 0x00000005 + index + zeros.")
        print("  A subject that requires genuine key material should skip")
        print("  family B and run it with its own key; the vector is the")
        print("  OFFSET, not the key.")

    print()
    print("=" * 74)
    print("RESULT")
    print("=" * 74)
    if total_a:
        print("  family A (%d vectors):  N1 %d/%d   N2 %d/%d   N3 %d/%d" %
              (total_a, n1, total_a, n2, total_a, n3, total_a))
    if total_b:
        print("  family B (%d vectors):  %d/%d" % (total_b, nb, total_b))
    if mdl:
        if n0_ok is None:
            print("  N0 (the zero question):  BLIND -- no subject")
        elif n0_ok:
            print("  N0 (the zero question):  declares '%s'" % n0_model)
        else:
            print("  N0 (the zero question):  FAILS -- " + n0_reason)

    if failures:
        print()
        print("  FAILURES (%d):" % len(failures))
        for i, exp, seen in failures:
            print("    %-5s expected %-34s seen %s" % (i, exp, seen[:60]))

    level = "none"
    if total_a:
        if n3 == total_a:
            level = "N3 -- classifies, derives and judges"
        elif n2 == total_a:
            level = "N2 -- classifies and derives, does not mark fatal"
        elif n1 == total_a:
            level = "N1 -- classifies"
    if n0_ok is False and level != "none":
        level = ("NONE -- it would classify " + level.split(" ")[0] +
                 ", but it does not declare its model (N0), and without "
                 "that the other levels are read wrongly")
    print()
    print("  LEVEL REACHED: " + level)
    print("  (family B scores no level: it is FORMAT conformance)")

    # This note is DERIVED from the vectors, never typed: the v0.1 had
    # DEDUCED rows and a failure could belong to the specification; since
    # the v0.2 none are left. And the section is named by its TITLE, not by
    # its number: a pointer to "section N" expires on its own.
    ded = [v["id"] for v in doc.get("reconciliation", [])
           if v.get("provenance") == "DEDUCED"]
    ded += [v["id"] for v in doc.get("index_read", [])
            if v.get("provenance") == "DEDUCED"]
    print()
    if ded:
        print("  PROVENANCE: %d of %d rows are DEDUCED and are not checked" %
              (len(ded), total_a + total_b))
        print("  against any implementation: " + ", ".join(ded))
        print("  A subject that fails ONLY on those rows is not wrong: this")
        print("  specification may be. See the resolved-deductions section.")
    else:
        print("  PROVENANCE: all %d rows are MEASURED against a source." %
              (total_a + total_b))
        print("  None is DEDUCED any more, so a failure belongs to the")
        print("  SUBJECT, not to this specification.")
        pending = doc.get("candidates_without_vectors", [])
        if pending:
            print("  (there are %d CANDIDATE families with no vectors yet: %s"
                  % (len(pending), ", ".join(x["id"] for x in pending)))
            print("   -- they score nothing, and their absence is not")
            print("   conformance)")

    print()
    print("# END-VERIFY-" + "STATE")
    if (total_a and n3 == total_a and (not total_b or nb == total_b)
            and n0_ok is not False):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
