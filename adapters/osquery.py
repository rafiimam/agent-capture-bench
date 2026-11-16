#!/usr/bin/env python3
"""Adapt osquery process_events output to canonical exec-jsonl-v1.

STATUS: UNVALIDATED. osquery process_events is configuration-dependent:
the process-events publisher (audit or BPF) must be enabled and kept up
with load, or events are silently absent — absence under a
misconfigured/overwhelmed publisher is a scope/configuration limitation,
not a capture failure, and must be ruled out before any comparison is
published. Do NOT publish a comparison until this adapter has been run
against a real capture on a live host and confirmed. Parser skips are
reported, never silent.

Collect (while the experiment runs; requires a working events publisher —
on Linux the eBPF publisher needs flags like --enable_bpf_events=true,
and audit needs --disable_audit=false):

    sudo osqueryi --json "SELECT * FROM process_events" | tee osquery.jsonl

Convert:

    python3 adapters/osquery.py --input osquery.jsonl --output recorder-output.jsonl

Format notes: the input is either a JSON array of event objects (as printed
by `osqueryi --json`) or newline-delimited JSON objects (accepted
transparently). Relevant process_events columns: `action` (only `exec`
rows are kept; rows with another action, or none, are skipped and counted),
`path` (executed binary as recorded), `cmdline` (JSON-encoded array string
of argv, e.g. '["git","log"]'; if that fails to parse, the raw string is
shlex-split), `pid`, `ppid`. Snapshot tables (processes, etc.) are NOT
input for this adapter — snapshots are not an execution log.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path


def _records_from_value(value) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _parse_cmdline(raw) -> list[str]:
    if raw is None:
        return []
    text = str(raw)
    try:
        decoded = json.loads(text)
        if isinstance(decoded, list) and decoded:
            return [str(arg) for arg in decoded]
    except json.JSONDecodeError:
        pass
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _int_field(source: dict, name: str) -> int:
    try:
        return int(str(source.get(name, 0)), 10)
    except (TypeError, ValueError):
        return 0


def convert(lines: list[str]) -> tuple[list[dict], int]:
    text = "\n".join(lines).strip()
    items: list[dict] = []
    parse_failures = 0
    if text:
        try:
            items = _records_from_value(json.loads(text))
        except json.JSONDecodeError:
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    items.extend(_records_from_value(json.loads(stripped)))
                except json.JSONDecodeError:
                    parse_failures += 1

    records: list[dict] = []
    skipped = 0
    for item in items:
        action = str(item.get("action") or "").lower()
        if action and action != "exec":
            skipped += 1
            continue
        argv = _parse_cmdline(item.get("cmdline"))
        path = item.get("path") or item.get("name") or (argv[0] if argv else None)
        if not path:
            skipped += 1
            continue
        if not argv:
            argv = [str(path)]
        records.append({
            "type": "exec",
            "filename": str(path),
            "argv": argv,
            "pid": _int_field(item, "pid"),
            "ppid": _int_field(item, "ppid"),
        })
    return records, skipped + parse_failures


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
    print(f"osquery adapter: {len(records)} exec records, {skipped} rows skipped",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
