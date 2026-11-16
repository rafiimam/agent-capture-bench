#!/usr/bin/env python3
"""Adapt sysdig output to canonical exec-jsonl-v1.

STATUS: UNVALIDATED and schema-tolerant by necessity. sysdig's JSON line
format (`sysdig -j`) varies across releases and is not pinned by a stable
public spec; rather than pretend precision we do not have, this adapter
recursively walks each event object and looks up fields by name. Do NOT
publish a comparison produced by this adapter until it has been run against
a real capture on a live host and confirmed against `sysdig -l` /
`sysdig -L` output for your version. Parser skips are reported, never
silent.

Collect (while the experiment runs, in a second terminal):

    sudo sysdig -j evt.type in '(execve, execveat)' | tee sysdig.jsonl
    # or from a capture file:
    sysdig -r trace.scap -j evt.type in '(execve, execveat)' | tee sysdig.jsonl

Convert:

    python3 adapters/sysdig.py --input sysdig.jsonl --output recorder-output.jsonl

Format notes: one JSON object per event. The adapter requires an
execve/execveat marker somewhere in the object (a `type`/`evt.type`-style
field whose value contains "execve"); events without one are skipped and
counted. Field lookup (first case-insensitive match wins): pid <- pid,
proc.pid, procpid, process_pid; ppid <- ppid, proc.ppid, procppid,
parent_pid; argv <- proc.args, args, arguments, cmdline, cmd; filename <-
proc.exepath, exepath, exe, filepath; if no filename field exists, argv[0]
is used verbatim (never resolved). argv string values are shlex-split with
a whitespace fallback. Missing ppid is emitted as 0 (unknown), never
guessed; missing argv yields a single-element argv from the filename.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

_PID_KEYS = ("pid", "proc.pid", "procpid", "process_pid")
_PPID_KEYS = ("ppid", "proc.ppid", "procppid", "parent_pid")
_ARGV_KEYS = ("proc.args", "args", "arguments", "cmdline", "cmd")
_PATH_KEYS = ("proc.exepath", "exepath", "exe", "filepath")
_TYPE_KEYS = ("type", "evt.type", "event_type", "evtype")


def _flatten(value, prefix: str = "") -> dict[str, object]:
    flat: dict[str, object] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            namespaced = f"{prefix}{key}".lower() if prefix else str(key).lower()
            _flatten_into(flat, namespaced, child)
    return flat


def _flatten_into(flat: dict[str, object], name: str, child) -> None:
    if isinstance(child, dict):
        for key, grandchild in child.items():
            _flatten_into(flat, f"{name}.{str(key).lower()}", grandchild)
        return
    if isinstance(child, list):
        if all(not isinstance(item, (dict, list)) for item in child):
            flat.setdefault(name, child)
        else:
            for index, item in enumerate(child):
                _flatten_into(flat, f"{name}.{index}", item)
        return
    # Leaf scalars only — container objects are never field candidates.
    flat.setdefault(name, child)


def _lookup(flat: dict[str, object], keys: tuple[str, ...]):
    for key in keys:
        if key in flat and flat[key] is not None:
            return flat[key]
    return None


def _lookup_loose(flat: dict[str, object], keys: tuple[str, ...]):
    # Also match the terminal component of dotted keys (e.g. "evdata.args.pid"
    # for key "pid") so schema nesting depth does not defeat the lookup.
    direct = _lookup(flat, keys)
    if direct is not None:
        return direct
    for key in keys:
        terminal = key.rsplit(".", 1)[-1]
        for flat_key, value in flat.items():
            if flat_key.rsplit(".", 1)[-1] == terminal and value is not None:
                return value
    return None


def _int(value) -> int:
    try:
        return int(str(value), 10)
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
        flat = _flatten(item)
        marker = _lookup_loose(flat, _TYPE_KEYS)
        if marker is None or "execve" not in str(marker).lower():
            skipped += 1
            continue
        raw_argv = _lookup_loose(flat, _ARGV_KEYS)
        raw_path = _lookup_loose(flat, _PATH_KEYS)
        argv: list[str] = []
        if isinstance(raw_argv, list):
            argv = [str(arg) for arg in raw_argv]
        elif raw_argv is not None:
            text = str(raw_argv)
            try:
                argv = shlex.split(text)
            except ValueError:
                argv = text.split()
        filename = str(raw_path) if raw_path else (argv[0] if argv else "")
        if not filename:
            skipped += 1
            continue
        if not argv:
            argv = [filename]
        records.append({
            "type": "exec",
            "filename": filename,
            "argv": argv,
            "pid": _int(_lookup_loose(flat, _PID_KEYS) or 0),
            "ppid": _int(_lookup_loose(flat, _PPID_KEYS) or 0),
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
    print(f"sysdig adapter: {len(records)} exec records, {skipped} lines skipped",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
