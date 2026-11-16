from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "tools/report.py"
MARKER = "FAKE-ACB-sk-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1"
LONG_ARG = "A" * 60 + f"--token={MARKER}"


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def base_oracle() -> list[dict]:
    return [
        {"record_type": "metadata", "schema_version": 1, "target_pid": 100},
        {"record_type": "event", "seq": 1, "ts_ns": 1, "type": "exec", "pid": 101,
         "ppid": 100, "old_pid": 101, "comm": "echo", "filename": "/usr/bin/echo",
         "argc": 2, "args_truncated": False,
         "argv": ["/bin/echo", f"--token={MARKER}"]},
        {"record_type": "event", "seq": 2, "ts_ns": 2, "type": "exec", "pid": 102,
         "ppid": 100, "old_pid": 102, "comm": "echo", "filename": "/usr/bin/echo",
         "argc": 2, "args_truncated": True,
         "argv": ["/bin/echo", LONG_ARG[:95]]},
    ]


def base_supervisor() -> list[dict]:
    return [
        {"record_type": "supervisor_metadata", "schema_version": 1,
         "scenario_id": "redaction-probes-v1"},
        {"record_type": "step_result", "case_id": "secret_in_argv", "passed": True},
        {"record_type": "step_result", "case_id": "secret_argv_overflow", "passed": True},
        {"record_type": "step_result", "case_id": "secret_in_env", "passed": True},
    ]


class RedactionScenarioTests(unittest.TestCase):
    def run_report(self, root: Path, recorder: list[dict] | None) -> dict:
        oracle_path = root / "oracle.jsonl"
        supervisor_path = root / "supervisor.jsonl"
        output_path = root / "report.json"
        write_jsonl(oracle_path, base_oracle())
        write_jsonl(supervisor_path, base_supervisor())
        cmd = [sys.executable, str(REPORT), "--oracle", str(oracle_path),
               "--supervisor", str(supervisor_path), "--output", str(output_path)]
        if recorder is not None:
            recorder_path = root / "recorder.jsonl"
            write_jsonl(recorder_path, recorder)
            cmd += ["--recorder", str(recorder_path)]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return json.loads(output_path.read_text())

    def test_checks_and_analysis_without_recorder(self) -> None:
        with tempfile.TemporaryDirectory(prefix="acb-redaction-") as tmp:
            report = self.run_report(Path(tmp), None)
            checks = report["redaction_checks"]
            self.assertTrue(checks["secret_in_argv_seen"])
            self.assertTrue(checks["secret_argv_overflow_truncation_flagged"])
            self.assertTrue(checks["secret_in_env_step_passed"])
            analysis = report["redaction_analysis"]
            # Full marker appears in argv only in the non-truncated event.
            self.assertEqual(analysis["oracle_events_containing_marker"], 1)
            self.assertIsNone(analysis["recorder_events_containing_marker"])

    def test_recorder_without_marker_is_undetermined_not_failure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="acb-redaction-") as tmp:
            recorder = [
                {"type": "exec", "filename": "/bin/echo",
                 "argv": ["echo", f"--token={MARKER}"],
                 "pid": 101, "ppid": 100},
                {"type": "exec", "filename": "/bin/echo",
                 "argv": ["echo", "A" * 60 + "--token=[REDACTED]"],
                 "pid": 102, "ppid": 100},
            ]
            report = self.run_report(Path(tmp), recorder)
            analysis = report["redaction_analysis"]
            self.assertEqual(analysis["recorder_events_containing_marker"], 1)
            self.assertGreaterEqual(analysis["recorder_redaction_pattern_hits"], 1)
            self.assertEqual(analysis["classification_hint"], "marker_present_in_recorder")

    def test_redaction_pattern_hint_when_marker_absent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="acb-redaction-") as tmp:
            recorder = [
                {"type": "exec", "filename": "/bin/echo",
                 "argv": ["echo", "--token=[REDACTED]"], "pid": 101, "ppid": 100},
            ]
            report = self.run_report(Path(tmp), recorder)
            analysis = report["redaction_analysis"]
            self.assertEqual(analysis["recorder_events_containing_marker"], 0)
            self.assertEqual(analysis["classification_hint"], "redaction_pattern_observed")

    def test_secret_in_env_without_marker_is_absent_undetermined(self) -> None:
        with tempfile.TemporaryDirectory(prefix="acb-redaction-") as tmp:
            recorder = [
                {"type": "exec", "filename": "/bin/echo",
                 "argv": ["echo", "env-marker-case"], "pid": 103, "ppid": 100},
            ]
            report = self.run_report(Path(tmp), recorder)
            analysis = report["redaction_analysis"]
            self.assertEqual(analysis["classification_hint"], "absent_undetermined_redaction_or_miss")


if __name__ == "__main__":
    unittest.main()
