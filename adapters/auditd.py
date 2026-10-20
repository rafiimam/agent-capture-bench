#!/usr/bin/env python3
"""Adapt Linux auditd logs to the canonical exec-jsonl-v1 schema.

Collect (as root; the rule must be in place BEFORE the experiment runs):

    sudo auditctl -a always,exit -F arch=b64 -S execve -S execveat -k agentcap
    # run the experiment, then export and remove the rule:
    sudo ausearch -k agentcap --format text > audit.txt    # or read /var/log/audit/audit.log
    sudo auditctl -d always,exit -F arch=b64 -S execve -S execveat -k agentcap

On aarch64 use arch=b64 with the same syscall names; auditctl resolves them.

Convert:

    python3 adapters/auditd.py --input audit.txt --output recorder-output.jsonl

Format notes: audit events are multi-record. The EXECVE record carries argc
and a0..aN; the matching SYSCALL record (same msg serial) carries exe, pid,
ppid and success. Argument values appear either quoted or as bare hex strings
(audit hex-encodes arguments containing spaces or non-printable bytes); the
adapter decodes hex when the value is unquoted, even-length hex that decodes
to printable UTF-8, and otherwise preserves the raw value — a decoded value is
marked nowhere because the canonical schema has no such field; treat argv from
this adapter as best-effort for arguments with exotic bytes. Only events whose
SYSCALL record reports success=yes and an execve/execveat syscall are emitted.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

EXECVE_SYSCALLS = {"59", "322", "221", "281"}  # x86_64 execve/execveat, aarch64 execve/execveat
MSG_RE = re.compile(r"msg=audit\([\d.]+:(?P<serial>\d+)\)")
FIELD_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")


def decode_arg(raw: str) -> str:
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw and len(raw) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", raw):
        try:
            decoded = bytes.fromhex(raw).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return raw
        if all(ch.isprintable() or ch in "\t" for ch in decoded):
            return decoded
    return raw


def parse_fields(line: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in FIELD_RE.finditer(line)}


def convert(lines: list[str]) -> tuple[list[dict], int]:
    events: dict[str, dict[str, dict[str, str]]] = {}
    order: list[str] = []
    for line in lines:
        msg = MSG_RE.search(line)
        if not msg:
            continue
        serial = msg.group("serial")
        record_type = parse_fields(line).get("type")
        if record_type not in ("SYSCALL", "EXECVE"):
            continue
        if serial not in events:
            events[serial] = {}
            order.append(serial)
        events[serial][record_type] = parse_fields(line)

    records: list[dict] = []
    incomplete = 0
    for serial in order:
        event = events[serial]
        syscall_rec = event.get("SYSCALL")
        execve_rec = event.get("EXECVE")
        if not syscall_rec or not execve_rec:
            incomplete += 1
            continue
        if syscall_rec.get("success") != "yes" or syscall_rec.get("syscall") not in EXECVE_SYSCALLS:
            continue
        try:
            argc = int(execve_rec.get("argc", "0"))
        except ValueError:
            incomplete += 1
            continue
        argv = [decode_arg(execve_rec.get(f"a{i}", "")) for i in range(argc)]
        exe = syscall_rec.get("exe", "").strip('"')
        records.append({
            "type": "exec",
            "filename": exe or (argv[0] if argv else ""),
            "argv": argv,
            "pid": int(syscall_rec.get("pid", "0")),
            "ppid": int(syscall_rec.get("ppid", "0")),
        })
    return records, incomplete


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    records, incomplete = convert(args.input.read_text(encoding="utf-8").splitlines())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(f"auditd adapter: {len(records)} exec records, {incomplete} incomplete events skipped",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
