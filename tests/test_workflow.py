from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def test_workflow_completes_and_records_real_outcomes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="acb-test-") as tmp:
            work = Path(tmp)
            fixture = work / "fixture"
            events = work / "supervisor.jsonl"
            subprocess.run(
                [sys.executable, str(ROOT / "workflow/prepare_fixture.py"), "--dir", str(fixture)],
                check=True,
                capture_output=True,
                text=True,
            )
            completed = subprocess.run(
                [sys.executable, str(ROOT / "workflow/run_workflow.py"),
                 "--fixture-dir", str(fixture), "--events", str(events)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("Workflow completed", completed.stdout)
            records = [json.loads(line) for line in events.read_text().splitlines()]
            results = {record["case_id"]: record for record in records
                       if record.get("record_type") == "step_result"}
            self.assertEqual(set(results), {
                "path_echo", "absolute_echo", "shell_pipeline", "nonzero_exit", "python_spawns_git"
            })
            self.assertTrue(all(r["passed"] for r in results.values()))
            self.assertEqual(results["nonzero_exit"]["returncode"], 1)
            file_result = next(r for r in records if r.get("record_type") == "filesystem_result")
            self.assertTrue(file_result["changed"])
            self.assertNotEqual(file_result["sha256_before"], file_result["sha256_after"])

    def test_fixture_refuses_to_reuse_existing_repository(self) -> None:
        with tempfile.TemporaryDirectory(prefix="acb-test-") as tmp:
            fixture = Path(tmp) / "fixture"
            subprocess.run(
                [sys.executable, str(ROOT / "workflow/prepare_fixture.py"), "--dir", str(fixture)],
                check=True,
                capture_output=True,
                text=True,
            )
            duplicate = subprocess.run(
                [sys.executable, str(ROOT / "workflow/prepare_fixture.py"), "--dir", str(fixture)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertIn("refusing to reuse", duplicate.stderr)


if __name__ == "__main__":
    unittest.main()
