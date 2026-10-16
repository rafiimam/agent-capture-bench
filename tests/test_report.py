from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "tools/report.py"


class ReportTests(unittest.TestCase):
    def test_report_detects_python_child_git_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="acb-report-") as tmp:
            root = Path(tmp)
            oracle_path = root / "oracle.jsonl"
            supervisor_path = root / "supervisor.jsonl"
            output_path = root / "report.json"

            python_code = "import subprocess; subprocess.run(['git', 'log', '-n', '1'], check=False)"
            oracle = [
                {"record_type": "metadata", "schema_version": 1, "target_pid": 100},
                {"record_type": "event", "seq": 1, "ts_ns": 1, "type": "exec", "pid": 100,
                 "ppid": 0, "old_pid": 100, "comm": "python3", "filename": "/usr/bin/python3",
                 "argc": 2, "args_truncated": False,
                 "argv": ["python3", "/workflow/run_workflow.py"]},
                {"record_type": "event", "seq": 2, "ts_ns": 2, "type": "exec", "pid": 101,
                 "ppid": 100, "old_pid": 101, "comm": "echo", "filename": "/usr/bin/echo",
                 "argc": 2, "args_truncated": False, "argv": ["echo", "hello"]},
                {"record_type": "event", "seq": 3, "ts_ns": 3, "type": "exec", "pid": 102,
                 "ppid": 100, "old_pid": 102, "comm": "echo", "filename": "/usr/bin/echo",
                 "argc": 2, "args_truncated": False, "argv": ["/bin/echo", "absolute"]},
                {"record_type": "event", "seq": 4, "ts_ns": 4, "type": "exec", "pid": 103,
                 "ppid": 100, "old_pid": 103, "comm": "sh", "filename": "/bin/sh",
                 "argc": 3, "args_truncated": False,
                 "argv": ["/bin/sh", "-c", "/bin/echo pipeline | /usr/bin/wc -l"]},
                {"record_type": "event", "seq": 5, "ts_ns": 5, "type": "exec", "pid": 104,
                 "ppid": 100, "old_pid": 104, "comm": "wc", "filename": "/usr/bin/wc",
                 "argc": 2, "args_truncated": False, "argv": ["/usr/bin/wc", "-l"]},
                {"record_type": "event", "seq": 6, "ts_ns": 6, "type": "exec", "pid": 108,
                 "ppid": 100, "old_pid": 108, "comm": "echo", "filename": "/bin/echo",
                 "argc": 2, "args_truncated": False, "argv": ["/bin/echo", "pipeline"]},
                {"record_type": "event", "seq": 7, "ts_ns": 7, "type": "exec", "pid": 105,
                 "ppid": 100, "old_pid": 105, "comm": "false", "filename": "/usr/bin/false",
                 "argc": 1, "args_truncated": False, "argv": ["/usr/bin/false"]},
                {"record_type": "event", "seq": 8, "ts_ns": 8, "type": "exec", "pid": 106,
                 "ppid": 100, "old_pid": 106, "comm": "python3", "filename": "/usr/bin/python3",
                 "argc": 3, "args_truncated": False,
                 "argv": ["python3", "-c", python_code]},
                {"record_type": "event", "seq": 9, "ts_ns": 9, "type": "exec", "pid": 107,
                 "ppid": 106, "old_pid": 107, "comm": "git", "filename": "/usr/bin/git",
                 "argc": 4, "args_truncated": False, "argv": ["git", "log", "-n", "1"]},
            ]
            supervisor = [
                {"record_type": "supervisor_metadata", "schema_version": 1,
                 "scenario_id": "python-subprocess-capture-v1"},
                *[{"record_type": "step_result", "case_id": case, "passed": True}
                  for case in ["path_echo", "absolute_echo", "shell_pipeline", "nonzero_exit", "python_spawns_git"]],
                {"record_type": "filesystem_result", "case_id": "file_modification", "changed": True,
                 "sha256_after": "abc"},
            ]
            oracle_path.write_text("".join(json.dumps(x) + "\n" for x in oracle))
            supervisor_path.write_text("".join(json.dumps(x) + "\n" for x in supervisor))

            subprocess.run(
                [sys.executable, str(REPORT), "--oracle", str(oracle_path),
                 "--supervisor", str(supervisor_path), "--output", str(output_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads(output_path.read_text())
            self.assertTrue(report["all_oracle_checks_observed"])
            self.assertTrue(report["observed_checks"]["git_parent_is_python_probe"])
            self.assertEqual(report["oracle_event_type_counts"]["exec"], 9)

    def test_recorder_comparison_detects_missed_and_unexpected_events(self) -> None:
        with tempfile.TemporaryDirectory(prefix="acb-report-") as tmp:
            root = Path(tmp)
            oracle_path = root / "oracle.jsonl"
            supervisor_path = root / "supervisor.jsonl"
            recorder_path = root / "recorder.jsonl"
            output_path = root / "report.json"

            python_code = "import subprocess; subprocess.run(['git', 'log', '-n', '1'], check=False)"
            oracle = [
                {"record_type": "metadata", "schema_version": 1, "target_pid": 100},
                {"record_type": "event", "seq": 1, "ts_ns": 1, "type": "exec", "pid": 100,
                 "ppid": 0, "old_pid": 100, "comm": "python3", "filename": "/usr/bin/python3",
                 "argc": 2, "args_truncated": False,
                 "argv": ["python3", "/workflow/run_workflow.py"]},
                {"record_type": "event", "seq": 2, "ts_ns": 2, "type": "exec", "pid": 101,
                 "ppid": 100, "old_pid": 101, "comm": "echo", "filename": "/usr/bin/echo",
                 "argc": 2, "args_truncated": False, "argv": ["echo", "hello"]},
                {"record_type": "event", "seq": 3, "ts_ns": 3, "type": "exec", "pid": 106,
                 "ppid": 100, "old_pid": 106, "comm": "python3", "filename": "/usr/bin/python3",
                 "argc": 3, "args_truncated": False,
                 "argv": ["python3", "-c", python_code]},
                {"record_type": "event", "seq": 4, "ts_ns": 4, "type": "exec", "pid": 107,
                 "ppid": 106, "old_pid": 107, "comm": "git", "filename": "/usr/bin/git",
                 "argc": 4, "args_truncated": False, "argv": ["git", "log", "-n", "1"]},
            ]
            # Recorder sees the python probe but misses the child git exec,
            # and reports an unexpected /usr/bin/curl event the oracle never saw.
            recorder = [
                {"type": "exec", "filename": "/usr/bin/python3", "pid": 100,
                 "ppid": 0, "argv": ["python3", "/workflow/run_workflow.py"]},
                {"type": "exec", "filename": "/usr/bin/echo", "pid": 101,
                 "ppid": 100, "argv": ["echo", "hello"]},
                {"type": "exec", "filename": "/usr/bin/python3", "pid": 106,
                 "ppid": 100, "argv": ["python3", "-c", python_code]},
                # git is MISSING here — a capture gap
                {"type": "exec", "filename": "/usr/bin/curl", "pid": 200,
                 "ppid": 0, "argv": ["curl", "https://example.com"]},
            ]
            supervisor = [
                {"record_type": "supervisor_metadata", "schema_version": 1,
                 "scenario_id": "python-subprocess-capture-v1"},
            ]
            oracle_path.write_text("".join(json.dumps(x) + "\n" for x in oracle))
            supervisor_path.write_text("".join(json.dumps(x) + "\n" for x in supervisor))
            recorder_path.write_text("".join(json.dumps(x) + "\n" for x in recorder))

            subprocess.run(
                [sys.executable, str(REPORT), "--oracle", str(oracle_path),
                 "--supervisor", str(supervisor_path), "--recorder", str(recorder_path),
                 "--output", str(output_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads(output_path.read_text())
            comparison = report["recorder_comparison"]
            self.assertEqual(comparison["schema"], "canonical-exec-jsonl-v1")
            self.assertEqual(comparison["oracle_exec_event_count"], 4)
            self.assertEqual(comparison["recorder_exec_event_count"], 4)
            self.assertEqual(comparison["matched_event_count"], 3)
            self.assertEqual(len(comparison["missed_events"]), 1)
            self.assertEqual(comparison["missed_events"][0]["filename_basename"], "git")
            self.assertEqual(len(comparison["unexpected_events"]), 1)
            self.assertEqual(comparison["unexpected_events"][0]["filename_basename"], "curl")


if __name__ == "__main__":
    unittest.main()

