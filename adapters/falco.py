#!/usr/bin/env python3
"""Adapt Falco JSON output to canonical exec-jsonl-v1.

STATUS: UNVALIDATED. Falco's contract is alerting on rule matches, not a
complete execution log (see docs/LANDSCAPE.md). Scoring Falco on capture
completeness is only meaningful for the events a configured rule actually
surfaces; the adapter cannot create events Falco never emitted. Do NOT
publish a comparison until this adapter has been run against a real capture
and confirmed. Parser skips are reported, never silent.

Collect (while the experiment runs, in a second terminal):

    sudo falco -o json_output=true -o json_include_output_property=true \
        | tee falco.jsonl

The default Falco ruleset does NOT log every execve. For a completeness
measurement, configure a rule that selects execve/execveat unconditionally,
e.g.:

    - rule: AgentCaptureBench execve accounting
      desc: Surface every execve for benchmark capture (not an alert)
      condition: evt.type in (execve, execveat) and evt.dir=<
      output: "acb %evt.type %proc.cmdline"
      priority: NOTICE

Without such a rule, every absent event is a scope limitation by design,
not a capture failure.

Convert:

    python3 adapters/falco.py --input falco.jsonl --output recorder-output.jsonl

Format notes: one JSON object per line. The adapter reads `output_fields`:
proc.pid, proc.ppid, proc.exepath (preferred filename) and proc.cmdline
(whitespace/shlex split into argv, argv[0] preserved as recorded). Events
whose evt.type is not an execve variant are skipped and counted. When
proc.ppid is absent (some Falco versions under `proc.ppid` vs
`proc.parent.pid`), the adapter falls back to proc.parent.pid / proc.ancestors
best-effort; failing that, ppid is 0 (unknown), never guessed.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

EXECVE_TYPES = {"execve", "execveat"}


def _field(fields: dict, *names: str):
    for name in names:
        value = fields.get(name)
        if value is not None:
            return value
    return None


def _int_field(fields: dict, *names: str) -> int:
    value = _field(fields, *names)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def convert(lines: list[str]) -> tuple[list[dict], int]:
    records: list[dict] = []
    skipped = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            skipped += 1
            continue
        fields = item.get("output_fields") if isinstance(item, dict) else None
        if not isinstance(fields, dict):
            skipped += 1
            continue
        evt_type = str(_field(fields, "evt.type", "evtType") or "").lower()
        if evt_type not in EXECVE_TYPES:
            skipped += 1
            continue
        cmdline = _field(fields, "proc.cmdline", "procCmdline")
        exepath = _field(fields, "proc.exepath", "procExepath", "proc.exe")
        if cmdline is not None:
            try:
                argv = shlex.split(str(cmdline))
            except ValueError:
                argv = str(cmdline).split()
        elif exepath is not None:
            argv = [str(exepath)]
        else:
            skipped += 1
            continue
        if not argv:
            skipped += 1
            continue
        filename = str(exepath) if exepath else argv[0]
        records.append({
            "type": "exec",
            "filename": filename,
            "argv": argv,
            "pid": _int_field(fields, "proc.pid", "procPid"),
            "ppid": _int_field(fields, "proc.ppid", "procPpid", "proc.parent.pid"),
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
    print(f"falco adapter: {len(records)} exec records, {skipped} lines skipped",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
