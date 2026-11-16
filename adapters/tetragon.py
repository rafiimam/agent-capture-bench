#!/usr/bin/env python3
"""Adapt Cilium Tetragon process_exec events to canonical exec-jsonl-v1.

STATUS: UNVALIDATED. The field layout below follows Tetragon's documented
JSON output for process exec events (tetra getevents -o json). Tetragon's
JSON schema has shifted across releases; this adapter targets the
process_exec shape with a nested `process` object and looks up pid/ppid in
both the process object and its `parent`. Do NOT publish a comparison
produced by this adapter until it has been run against a real capture on a
live host and the parser confirmed (see adapters/README.md and the
validation report issue template). Parser skips are reported, never silent.

Collect (while the experiment runs, in a second terminal):

    sudo tetra getevents -o json --types PROCESS_EXEC | tee tetragon.jsonl

Convert:

    python3 adapters/tetragon.py --input tetragon.jsonl --output recorder-output.jsonl

Format notes: one JSON object per line. Recognized shapes (either accepted,
auto-detected per line):

    {"process_exec": {"process": {...}, "parent": {...}}, "time": ...}
    {"process": {...}, "parent": {...}}                      (unnested)
    {"node_name": ..., "process_exec": ..., "time": ...}     (as emitted by
                                                            tetra)

The `process` object is expected to carry `binary` (the executed path as
recorded — NOT invented or resolved here), `arguments` (a single
space-joined string), `pid`, and (newer releases) `ppid`. If `ppid` is
absent from `process`, the adapter falls back to `parent.pid`; if neither
is present, `ppid` is emitted as 0 (unknown), never guessed. `arguments`
is split with shlex; quoting artifacts are preserved verbatim when shlex
cannot parse (falling back to plain whitespace split). Lines without a
parseable process object (e.g. process_exit, process_kprobe) are skipped
and counted.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path


def _extract_process(item: dict) -> tuple[dict, dict] | None:
    if not isinstance(item, dict):
        return None
    wrapped = item.get("process_exec")
    if isinstance(wrapped, dict):
        process = wrapped.get("process")
        parent = wrapped.get("parent") or {}
    else:
        process = item.get("process")
        parent = item.get("parent") or {}
    if not isinstance(process, dict) or not process:
        return None
    return process, parent if isinstance(parent, dict) else {}


def _int_field(source: dict, *names: str) -> int:
    for name in names:
        value = source.get(name)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
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
        extracted = _extract_process(item)
        if extracted is None:
            skipped += 1
            continue
        process, parent = extracted
        binary = process.get("binary")
        arguments = process.get("arguments")
        if arguments is None and process.get("arguments_length") is not None:
            # Some releases emit only arguments_length for long argument
            # lists; the text is genuinely unavailable — do not fabricate it.
            arguments = None
        if not binary or not isinstance(binary, str):
            skipped += 1
            continue
        if arguments is not None:
            try:
                argv = [binary, *shlex.split(str(arguments))]
            except ValueError:
                argv = [binary, *str(arguments).split()]
        else:
            argv = [binary]
        pid = _int_field(process, "pid")
        ppid = _int_field(process, "ppid", "parent_pid") or _int_field(parent, "pid")
        records.append({
            "type": "exec",
            "filename": binary,
            "argv": argv,
            "pid": pid,
            "ppid": ppid,
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
    print(f"tetragon adapter: {len(records)} exec records, {skipped} lines skipped",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
