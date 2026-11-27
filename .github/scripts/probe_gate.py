"""CI gate over `silo probe --json` output.

    python3 probe_gate.py RESULTS.json MODE [--allow PROBE=REASON ...]

Fails if any probe is FAIL or WARN without an --allow naming it, if a status is unknown or a probe is
reported twice, if fewer probes passed than expected, or, in kill mode, if a call the seccomp filter
denies was refused with an errno instead of SIGSYS (which would mean something other than the
filter stopped it).
"""

import argparse
import json
import sys

MIN_PROBES = 60
STATUSES = {"PASS", "FAIL", "WARN", "SKIP", "INFO"}
# Probes of calls the seccomp filter itself refuses: in kill mode the answer must be SIGSYS.
KILLED_PREFIXES = ("sys.", "args.", "net.socket.", "net.socketpair.")
# Refused without SIGSYS by design: clone3 is ENOSYS in every mode so that libc falls back to clone(2),
# args.allowlisted checks a call that must succeed, and AF_UNIX socketpair is the one family allowed.
NOT_KILLED = {"sys.clone3", "args.allowlisted", "net.socketpair.AF_UNIX"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("mode", choices=("errno", "kill"))
    ap.add_argument("--allow", action="append", default=[], metavar="PROBE=REASON")
    args = ap.parse_args()
    allowed = dict(a.split("=", 1) for a in args.allow)
    with open(args.results) as fh:
        results = json.load(fh)

    problems = []
    names = [r["probe"] for r in results]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        problems.append(f"probes reported more than once: {', '.join(duplicates)}")
    passed = {r["probe"] for r in results if r["status"] == "PASS"}
    if len(passed) < MIN_PROBES:
        problems.append(f"only {len(passed)} probes passed (expected at least {MIN_PROBES})")
    for r in results:
        line = f"{r['status']:<4} {r['probe']:<30} {r['detail']}"
        print(line)
        if r["status"] not in STATUSES:
            problems.append(f"{line}  (unknown status)")
        if r["status"] in ("FAIL", "WARN"):
            if r["probe"] in allowed:
                print(f"     ^ allowed on this host: {allowed[r['probe']]}")
            else:
                problems.append(line)
        if (args.mode == "kill" and r["status"] == "PASS" and r["probe"].startswith(KILLED_PREFIXES)
                and r["probe"] not in NOT_KILLED and "SIGSYS" not in r["detail"]):
            problems.append(f"{line}  (kill mode: expected SIGSYS)")
    unused = set(allowed) - {r["probe"] for r in results if r["status"] in ("FAIL", "WARN")}
    for probe in sorted(unused):
        print(f"note: --allow {probe} was not needed")
    if problems:
        print("\nprobe gate failed:", *problems, sep="\n  ")
        return 1
    print(f"\nprobe gate passed ({len(passed)} probes passed, mode {args.mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
