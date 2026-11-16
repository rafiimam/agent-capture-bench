#!/usr/bin/env python3
"""Summarize the kernel oracle's observations for the first experiment."""
from __future__ import annotations

import argparse
import json
import re
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


_WS_RUN = re.compile(r"\s+")
_SHELL_TOLERANT = re.compile(r"[\s\"']+")


def _joined_args(argv: list[Any]) -> str:
    return " ".join(str(arg) for arg in argv[1:]) if len(argv) > 1 else ""


def _collapse_space(value: str) -> str:
    return _WS_RUN.sub(" ", value).strip()


def _shell_tolerant(value: str) -> str:
    # Remove ALL whitespace and quote characters so argv fragmentation
    # (a space-joined text stream re-split by the recorder adapter) compares
    # equal to the oracle's original tokenization.
    return _SHELL_TOLERANT.sub("", value)


def normalized_match_tier(oracle_event: dict[str, Any], recorder_event: dict[str, Any]) -> str | None:
    """Return the strongest match tier, or None if the events cannot be paired.

    Tiers, strongest first:
      tier1_exact          — basename(argv[0]) equal AND the caller already
                             matched the full argv tuple exactly. (Handled by
                             the strict counter; never returned here.)
      tier2_token_collapsed— basename equal AND whitespace-collapsed joined
                             argument strings equal. Absorbs argv fragmentation
                             and spacing differences.
      tier3_truncation_prefix
                           — as tier2 but the recorder's joined arguments start
                             with the oracle's captured prefix. Only valid when
                             the oracle set args_truncated: the oracle's capture
                             is a prefix of the true invocation by definition.
      tier4_shell_tolerant — basename equal AND all whitespace/quote characters
                             removed from both joined argument strings, either
                             equal or with the recorder starting with the
                             oracle's (possibly truncated) prefix. Absorbs
                             quote-style rendering differences in -c strings.
    """
    oracle_argv = [str(a) for a in (oracle_event.get("argv") or [])]
    recorder_argv = [str(a) for a in (recorder_event.get("argv") or [])]
    if not oracle_argv or not recorder_argv:
        return None
    if basename(oracle_argv[0]) != basename(recorder_argv[0]):
        return None
    oracle_joined = _collapse_space(_joined_args(oracle_argv))
    recorder_joined = _collapse_space(_joined_args(recorder_argv))
    if oracle_joined == recorder_joined:
        return "tier2_token_collapsed"
    oracle_truncated = bool(oracle_event.get("args_truncated"))
    if oracle_truncated and recorder_joined.startswith(oracle_joined):
        return "tier3_truncation_prefix"
    oracle_st = _shell_tolerant(oracle_joined)
    recorder_st = _shell_tolerant(recorder_joined)
    if oracle_st == recorder_st:
        return "tier4_shell_tolerant"
    if oracle_truncated and recorder_st.startswith(oracle_st):
        return "tier4_shell_tolerant_truncation_prefix"
    return None


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

    # --- Normalization-aware matching (normalized-match-v1) -----------------
    # Stage 1 (strict): identical basename + argv tuple, multiset semantics.
    # Stage 2+: tiered normalized pairing (see normalized_match_tier). Pairing
    # is greedy in oracle event order; a recorder event is spent once paired.
    # Unmatched oracle events are classified with a reason, never auto-declared
    # capture failures.
    recorder_by_key: dict[tuple[str, tuple[str, ...]], list[int]] = {}
    for index, candidate in enumerate(recorder_execs):
        recorder_by_key.setdefault(key(candidate), []).append(index)
    spent = [False] * len(recorder_execs)
    tier_counts: Counter[str] = Counter()
    tier1_unmatched: list[dict[str, Any]] = []

    for event in oracle_execs:
        positions = recorder_by_key.get(key(event))
        if positions:
            spent[positions.pop()] = True
            tier_counts["tier1_exact"] += 1
        else:
            tier1_unmatched.append(event)

    unmatched_oracle: list[dict[str, Any]] = []
    for event in tier1_unmatched:
        match: tuple[int, str] | None = None
        for index, candidate in enumerate(recorder_execs):
            if spent[index]:
                continue
            tier = normalized_match_tier(event, candidate)
            if tier:
                match = (index, tier)
                break
        if match is not None:
            spent[match[0]] = True
            tier_counts[match[1]] += 1
            continue
        leftover_basenames = {
            basename(str(candidate.get("filename", "")))
            for index, candidate in enumerate(recorder_execs) if not spent[index]
        }
        oracle_argv = [str(a) for a in (event.get("argv") or [])]
        if oracle_argv and basename(oracle_argv[0]) in leftover_basenames:
            reason = ("representation_difference_truncation_suspected"
                      if event.get("args_truncated")
                      else "representation_difference_unresolved")
        else:
            reason = "no_recorder_evidence"
        unmatched_oracle.append({
            "filename_basename": basename(oracle_argv[0]) if oracle_argv else "",
            "argv": oracle_argv,
            "args_truncated": bool(event.get("args_truncated")),
            "reason": reason,
        })

    normalized_matched = len(oracle_execs) - len(unmatched_oracle)
    unexpected = [
        {"filename_basename": basename(str(candidate.get("filename", ""))),
         "argv": [str(a) for a in (candidate.get("argv") or [])]}
        for index, candidate in enumerate(recorder_execs) if not spent[index]
    ]
    return {
        "schema": "canonical-exec-jsonl-v1",
        "matcher": "normalized-match-v1",
        "oracle_exec_event_count": len(oracle_execs),
        "recorder_exec_event_count": len(recorder_execs),
        "matched_event_count": normalized_matched,
        "strict_matched_event_count": tier_counts.get("tier1_exact", 0),
        "match_tier_counts": dict(sorted(tier_counts.items())),
        "missed_events": [
            {"filename_basename": item["filename_basename"], "argv": item["argv"]}
            for item in unmatched_oracle
        ],
        "unmatched_oracle_events": unmatched_oracle,
        "unexpected_events": unexpected,
        "note": ("Matching: tier1_exact (basename + full argv tuple), then tiered "
                 "normalization — token-collapsed joined argv, truncation prefix "
                 "(only when the oracle set args_truncated), and quote/whitespace-tolerant "
                 "comparison. PID/timing correlation is not implemented. Unmatched events "
                 "are classified with a reason and are NOT declared capture failures; "
                 "'no_recorder_evidence' requires manual adjudication before publication."),
    }


REDACTION_MARKER = "FAKE-ACB-sk-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1"
_REDACTION_MARKERS = ("[REDACTED]", "***", "[REDACT]", "<redacted>")


def redaction_analysis(
    oracle_execs: list[dict[str, Any]],
    recorder_records: list[dict[str, Any]],
    has_recorder: bool,
) -> dict[str, Any]:
    """Best-effort redaction accounting for scenario redaction-probes-v1.

    Presence of the synthetic marker in the recorder is reported honestly;
    absence is NOT declared a capture failure (the recorder may redact, or
    may never have captured the exec). Classification stays with the human
    adjudicator — see workflow/scenario-redaction.yaml.
    """
    marker = REDACTION_MARKER

    def argv_text(event: dict[str, Any]) -> str:
        return " ".join(str(a) for a in (event.get("argv") or []))

    oracle_marker = sum(1 for e in oracle_execs if marker in argv_text(e))
    analysis: dict[str, Any] = {
        "marker": marker,
        "note": "Synthetic marker; presence/absence in recorder output is "
                "reported, not adjudicated. Absence is undetermined between "
                "redaction and non-capture until a redaction pattern appears.",
        "oracle_events_containing_marker": oracle_marker,
    }
    if not has_recorder:
        analysis["recorder_events_containing_marker"] = None
        analysis["recorder_redaction_pattern_hits"] = None
        return analysis
    recorder_execs = [e for e in recorder_records if e.get("type") == "exec"]
    marker_hits = sum(1 for e in recorder_execs if marker in argv_text(e))
    pattern_hits = sum(
        1 for e in recorder_execs
        if any(pattern in argv_text(e) for pattern in _REDACTION_MARKERS)
    )
    analysis["recorder_events_containing_marker"] = marker_hits
    analysis["recorder_redaction_pattern_hits"] = pattern_hits
    if marker_hits:
        analysis["classification_hint"] = "marker_present_in_recorder"  # not redacted
    elif pattern_hits:
        analysis["classification_hint"] = "redaction_pattern_observed"
    else:
        analysis["classification_hint"] = "absent_undetermined_redaction_or_miss"
    return analysis


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
        # The oracle's argc counts CAPTURED args and caps at ACB_MAX_ARGS (8),
        # so "argc >= 9" would be unsatisfiable. The honest signal is:
        # args_truncated set AND the captured argv sitting at the cap.
        "argv_overflow_truncation_flagged": has_exec(
            lambda e: basename(str(e.get("filename", ""))) == "echo"
            and bool(e.get("args_truncated")) and len(e.get("argv") or []) >= 8),
        "script_exec_seen": has_exec(lambda e: "helper.sh" in str(e.get("filename", ""))
                                     or "helper.sh" in argv_str(e)),
    }

    # --- redaction-probes-v1 checks (scenario-redaction.yaml) ---
    scenario_str = str(supervisor_metadata.get("scenario_id", ""))
    redaction_suite = "redaction-probes-v1" in scenario_str
    redaction_checks: dict[str, Any] = {}
    if redaction_suite:
        redaction_checks = {
            "secret_in_argv_seen": has_exec(
                lambda e: "--token=" in argv_str(e) and REDACTION_MARKER in argv_str(e)),
            "secret_argv_overflow_truncation_flagged": has_exec(
                lambda e: bool(e.get("args_truncated"))
                and any(str(a).startswith("A" * 60 + "--token=" + REDACTION_MARKER[:16])
                        for a in (e.get("argv") or []))),
            "secret_in_env_step_passed": any(
                step.get("case_id") == "secret_in_env" and step.get("passed")
                for step in step_results),
        }

    failed_steps = [step.get("case_id") for step in step_results if not step.get("passed")]
    recorder_comparison = (
        compare_canonical_recorder(oracle_events, recorder_records)
        if args.recorder else {"status": "not_run", "reason": "No recorder adapter output supplied."}
    )
    redaction = None
    if redaction_suite:
        redaction = redaction_analysis(exec_events, recorder_records, bool(args.recorder))

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
        "redaction_checks": redaction_checks or None,
        "redaction_analysis": redaction,
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
