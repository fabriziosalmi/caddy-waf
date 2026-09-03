#!/usr/bin/env python3
"""Fail if any benchmark regressed beyond a threshold.

Usage: bench-gate.py <old.txt> <new.txt>
Parses `go test -bench` output (multiple -count runs per benchmark), takes the
median ns/op per benchmark, and exits non-zero if a benchmark present in both
got slower by more than THRESHOLD. A generous threshold keeps CI-runner noise
from flapping while still catching real drift.
"""
import re
import statistics
import sys

THRESHOLD = 1.5  # fail on >50% slower

_LINE = re.compile(r"^(Benchmark\S+?)-\d+\s+\d+\s+([\d.]+)\s+ns/op")


def parse(path):
    runs = {}
    with open(path) as f:
        for line in f:
            m = _LINE.match(line)
            if m:
                runs.setdefault(m.group(1), []).append(float(m.group(2)))
    return {k: statistics.median(v) for k, v in runs.items() if v}


def main():
    old, new = parse(sys.argv[1]), parse(sys.argv[2])
    if not new:
        print("No benchmarks found in the current results; nothing to gate.")
        return 0
    regressed = []
    print(f"{'benchmark':40} {'base':>12} {'pr':>12}  ratio")
    for k in sorted(new):
        if k in old and old[k] > 0:
            ratio = new[k] / old[k]
            flag = "  <-- REGRESSION" if ratio > THRESHOLD else ""
            print(f"{k:40} {old[k]:12.0f} {new[k]:12.0f}  {ratio:.2f}x{flag}")
            if ratio > THRESHOLD:
                regressed.append((k, ratio))
        else:
            print(f"{k:40} {'(new)':>12} {new[k]:12.0f}")
    pct = int((THRESHOLD - 1) * 100)
    if regressed:
        print(f"\nFAIL: {len(regressed)} benchmark(s) regressed beyond {pct}%:")
        for k, r in regressed:
            print(f"  {k}  {r:.2f}x")
        return 1
    print(f"\nOK: no benchmark regressed beyond {pct}%.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
