"""CI gate over `silo probe --json` output.

    python3 probe_gate.py RESULTS.json MODE [--allow PROBE=REASON ...]

Fails if any probe is FAIL or WARN without an --allow naming it, if fewer probes ran than expected,
or, in kill mode, if a denied syscall was refused with an errno instead of SIGSYS (which would mean
something other than the seccomp filter stopped it).
"""

import argparse
import json
import sys

MIN_PROBES = 60


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
    if len(results) < MIN_PROBES:
        problems.append(f"only {len(results)} probes reported (expected at least {MIN_PROBES})")
    for r in results:
        line = f"{r['status']:<4} {r['probe']:<30} {r['detail']}"
        print(line)
        if r["status"] in ("FAIL", "WARN"):
            if r["probe"] in allowed:
                print(f"     ^ allowed on this host: {allowed[r['probe']]}")
            else:
                problems.append(line)
        if (args.mode == "kill" and r["status"] == "PASS" and r["probe"].startswith(("sys.", "args."))
                and r["probe"] != "args.allowlisted" and "SIGSYS" not in r["detail"]):
            problems.append(f"{line}  (kill mode: expected SIGSYS)")
    unused = set(allowed) - {r["probe"] for r in results if r["status"] in ("FAIL", "WARN")}
    for probe in sorted(unused):
        print(f"note: --allow {probe} was not needed")
    if problems:
        print("\nprobe gate failed:", *problems, sep="\n  ")
        return 1
    print(f"\nprobe gate passed ({len(results)} probes, mode {args.mode})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
