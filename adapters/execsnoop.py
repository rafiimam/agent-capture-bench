#!/usr/bin/env python3
"""Adapt BCC execsnoop output to the canonical exec-jsonl-v1 schema.

Collect (while the experiment runs, in a second terminal):

    sudo execsnoop-bpfcc | tee execsnoop.txt        # Debian/Ubuntu package: bpfcc-tools
    # or, from a BCC checkout: sudo ./execsnoop

Convert:

    python3 adapters/execsnoop.py --input execsnoop.txt --output recorder-output.jsonl
    python3 tools/report.py --oracle ... --supervisor ... --recorder recorder-output.jsonl --output report.json

Format notes (BCC execsnoop): a header line "TIME(s) COMM PID PPID RET ARGS"
followed by one line per execve return. Only successful execs (RET >= 0) are
emitted. execsnoop does not print the resolved executable path; the adapter
preserves argv[0] exactly as invoked in the `filename` field. The canonical
comparison matches on basename + argv, so this loses nothing, but the field
must not be mistaken for a resolved path. Lines that do not parse are skipped
and counted in the summary printed to stderr — never silently dropped.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

LINE_RE = re.compile(r"^\s*(?P<time>\S+)\s+(?P<comm>\S+)\s+(?P<pid>\d+)\s+"
                     r"(?P<ppid>\d+)\s+(?P<ret>-?\d+)\s+(?P<args>.*)$")


def convert(lines: list[str]) -> tuple[list[dict], int]:
    records: list[dict] = []
    skipped = 0
    for line in lines:
        if not line.strip() or line.lstrip().startswith("TIME(s)"):
            continue
        match = LINE_RE.match(line)
        if not match:
            skipped += 1
            continue
        if int(match.group("ret")) < 0:
            continue  # failed execve: not a successful execution
        try:
            argv = shlex.split(match.group("args"))
        except ValueError:
            argv = match.group("args").split()
        if not argv:
            skipped += 1
            continue
        records.append({
            "type": "exec",
            "filename": argv[0],
            "argv": argv,
            "pid": int(match.group("pid")),
            "ppid": int(match.group("ppid")),
        })
    return records, skipped


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    records, skipped = convert(args.input.read_text(encoding="utf-8").splitlines())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(f"execsnoop adapter: {len(records)} exec records, {skipped} lines skipped",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
