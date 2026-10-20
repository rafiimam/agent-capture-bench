from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EVASION_CASES = {
    "shell_c_git", "execveat_git", "double_fork_daemon",
    "short_lived_burst", "argv_overflow", "script_exec",
}


class EvasionWorkflowTests(unittest.TestCase):
    def test_evasion_suite_completes_all_cases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="acb-evasion-") as tmp:
            work = Path(tmp)
            fixture = work / "fixture"
            events = work / "supervisor.jsonl"
            subprocess.run(
                [sys.executable, str(ROOT / "workflow/prepare_fixture.py"), "--dir", str(fixture)],
                check=True, capture_output=True, text=True,
            )
            subprocess.run(
                [sys.executable, str(ROOT / "workflow/run_workflow.py"),
                 "--fixture-dir", str(fixture), "--events", str(events),
                 "--suite", "evasion"],
                check=True, capture_output=True, text=True,
            )
            records = [json.loads(line) for line in events.read_text().splitlines()]
            metadata = next(r for r in records if r.get("record_type") == "supervisor_metadata")
            self.assertEqual(metadata["scenario_id"], "capture-evasion-v1")
            results = {r["case_id"]: r for r in records if r.get("record_type") == "step_result"}
            self.assertEqual(set(results), EVASION_CASES)
            self.assertTrue(all(r["passed"] for r in results.values()),
                            {k: v["returncode"] for k, v in results.items() if not v["passed"]})
            # The daemon grandchild must have left its marker via the fixture dir.
            self.assertTrue((fixture / "daemon-marker.txt").exists())


if __name__ == "__main__":
    unittest.main()
