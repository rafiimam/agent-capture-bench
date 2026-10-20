#!/usr/bin/env python3
"""Summarize the kernel oracle's observations for the first experiment."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCENARIO_ID = "python-subprocess-capture-v1"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"{path}:{line_number}: JSONL record must be an object")
            records.append(item)
    return records


def basename(value: str) -> str:
    return value.rsplit("/", 1)[-1]


def is_python_probe(event: dict[str, Any]) -> bool:
    if event.get("type") != "exec":
        return False
    argv = event.get("argv") or []
    if len(argv) < 3 or "-c" not in argv:
        return False
    return any("subprocess.run(['git', 'log', '-n', '1']" in str(arg) for arg in argv)


def is_git_log(event: dict[str, Any]) -> bool:
    if event.get("type") != "exec" or basename(str(event.get("filename", ""))) != "git":
        return False
    argv = [str(arg) for arg in (event.get("argv") or [])]
    return any(argv[i:i + 3] == ["log", "-n", "1"] for i in range(max(0, len(argv) - 2)))


def find_event(events: list[dict[str, Any]], predicate) -> dict[str, Any] | None:
    return next((event for event in events if predicate(event)), None)


def compare_canonical_recorder(
    oracle_events: list[dict[str, Any]], recorder_events: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compare a recorder adapter's documented canonical exec-event schema.

    Expected normalized record fields: type='exec', filename, argv (array),
    pid, ppid. This is intentionally not a parser for vendor-native logs.
    An adapter must map those logs to this schema and preserve uncertainty.
    """
    oracle_execs = [event for event in oracle_events if event.get("type") == "exec"]
    recorder_execs = [event for event in recorder_events if event.get("type") == "exec"]

    def key(event: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
        return (basename(str(event.get("filename", ""))), tuple(str(x) for x in (event.get("argv") or [])))

    oracle_counter = Counter(key(event) for event in oracle_execs)
    recorder_counter = Counter(key(event) for event in recorder_execs)
    missed = list((oracle_counter - recorder_counter).elements())
    unexpected = list((recorder_counter - oracle_counter).elements())
    return {
        "schema": "canonical-exec-jsonl-v1",
        "oracle_exec_event_count": len(oracle_execs),
        "recorder_exec_event_count": len(recorder_execs),
        "matched_event_count": sum((oracle_counter & recorder_counter).values()),
        "missed_events": [
            {"filename_basename": item[0], "argv": list(item[1])} for item in missed
        ],
        "unexpected_events": [
            {"filename_basename": item[0], "argv": list(item[1])} for item in unexpected
        ],
        "note": "Matching is by executable basename and exact captured argv; PID/timing matching is not implemented.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--supervisor", required=True, type=Path)
    parser.add_argument("--recorder", type=Path,
                        help="optional recorder adapter output in canonical exec-jsonl-v1 format")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        oracle_records = read_jsonl(args.oracle)
        supervisor_records = read_jsonl(args.supervisor)
        recorder_records = read_jsonl(args.recorder) if args.recorder else []
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    metadata = next((r for r in oracle_records if r.get("record_type") == "metadata"), {})
    oracle_events = [r for r in oracle_records if r.get("record_type") == "event"]
    supervisor_metadata = next(
        (r for r in supervisor_records if r.get("record_type") == "supervisor_metadata"), {}
    )
    step_results = [r for r in supervisor_records if r.get("record_type") == "step_result"]
    fs_results = [r for r in supervisor_records if r.get("record_type") == "filesystem_result"]
    exec_events = [event for event in oracle_events if event.get("type") == "exec"]
    type_counts = Counter(str(event.get("type", "unknown")) for event in oracle_events)

    python_event = find_event(exec_events, is_python_probe)
    git_event = find_event(exec_events, is_git_log)
    git_parent_matches_python = bool(
        python_event and git_event and git_event.get("ppid") == python_event.get("pid")
    )

    def has_exec(predicate) -> bool:
        return find_event(exec_events, predicate) is not None

    checks = {
        "path_echo_seen": has_exec(lambda e: basename(str(e.get("filename", ""))) == "echo"
                                   and (e.get("argv") or [None])[0] == "echo"
                                   and "hello" in (e.get("argv") or [])),
        "absolute_echo_seen": has_exec(lambda e: basename(str(e.get("filename", ""))) == "echo"
                                        and (e.get("argv") or [None])[0] == "/bin/echo"
                                        and "absolute" in (e.get("argv") or [])),
        "shell_pipeline_shell_seen": has_exec(lambda e: basename(str(e.get("filename", ""))) == "sh"
                                               and "/bin/echo pipeline | /usr/bin/wc -l" in (e.get("argv") or [])),
        "shell_pipeline_echo_seen": has_exec(lambda e: basename(str(e.get("filename", ""))) == "echo"
                                              and "pipeline" in (e.get("argv") or [])),
        "shell_pipeline_wc_seen": has_exec(lambda e: basename(str(e.get("filename", ""))) == "wc"
                                            and "-l" in (e.get("argv") or [])),
        "nonzero_command_seen": has_exec(lambda e: basename(str(e.get("filename", ""))) == "false"),
        "python_probe_seen": python_event is not None,
        "git_child_exec_seen": git_event is not None,
        "git_parent_is_python_probe": git_parent_matches_python,
        "file_change_recorded": bool(fs_results and fs_results[0].get("changed")
                                      and fs_results[0].get("sha256_after")),
    }
    # --- capture-evasion-v1 checks (scenario-v2) ---
    def argv_str(event: dict[str, Any]) -> str:
        return " ".join(str(a) for a in (event.get("argv") or []))

    execveat_probe = find_event(exec_events, lambda e: basename(str(e.get("filename", ""))).startswith("python")
                                and "SYS_execveat" in argv_str(e))
    execveat_git = None
    if execveat_probe:
        execveat_git = find_event(exec_events, lambda e: is_git_log(e)
                                  and e.get("ppid") == execveat_probe.get("pid"))
    daemon_probe = find_event(exec_events, lambda e: basename(str(e.get("filename", ""))).startswith("python")
                              and "daemon-marker" in argv_str(e))
    daemon_echo = find_event(exec_events, lambda e: basename(str(e.get("filename", ""))) == "echo"
                             and "daemon-echo" in (e.get("argv") or []))
    true_count = sum(1 for e in exec_events if basename(str(e.get("filename", ""))) == "true")
    evasion_checks = {
        "shell_c_git_shell_seen": has_exec(lambda e: basename(str(e.get("filename", ""))) == "sh"
                                           and "git log -n 1" in argv_str(e)),
        "execveat_probe_seen": execveat_probe is not None,
        "execveat_git_child_seen": execveat_git is not None,
        "daemon_grandchild_seen": daemon_echo is not None,
        "daemon_grandchild_orphaned": bool(daemon_echo and daemon_probe
                                           and daemon_echo.get("ppid") != daemon_probe.get("pid")),
        "short_lived_burst_all_seen": true_count >= 20,
        "short_lived_burst_true_count": true_count,
        "argv_overflow_truncation_flagged": has_exec(
            lambda e: basename(str(e.get("filename", ""))) == "echo"
            and bool(e.get("args_truncated")) and int(e.get("argc") or 0) >= 9),
        "script_exec_seen": has_exec(lambda e: "helper.sh" in str(e.get("filename", ""))
                                     or "helper.sh" in argv_str(e)),
    }

    failed_steps = [step.get("case_id") for step in step_results if not step.get("passed")]
    recorder_comparison = (
        compare_canonical_recorder(oracle_events, recorder_records)
        if args.recorder else {"status": "not_run", "reason": "No recorder adapter output supplied."}
    )

    report = {
        "report_schema_version": 1,
        "scenario_id": SCENARIO_ID,
        "status": "oracle_observation_only",
        "metadata": metadata,
        "supervisor_metadata": supervisor_metadata,
        "oracle_event_count": len(oracle_events),
        "oracle_event_type_counts": dict(type_counts),
        "observed_checks": checks,
        "all_oracle_checks_observed": all(checks.values()),
        "evasion_checks": evasion_checks,
        "supervisor_step_count": len(step_results),
        "supervisor_steps_passed": len(step_results) - len(failed_steps),
        "failed_supervisor_steps": failed_steps,
        "recorder_comparison": recorder_comparison,
        "interpretation_warning": (
            "A missing oracle event can indicate a test, permission, configuration, or oracle problem; "
            "classify it as undetermined until those possibilities are ruled out. This report does not "
            "declare a recorder defect or a novel finding."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failed_steps else 1


if __name__ == "__main__":
    raise SystemExit(main())
