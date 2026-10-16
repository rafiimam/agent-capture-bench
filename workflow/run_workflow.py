#!/usr/bin/env python3
"""Run the deterministic scenario while an external eBPF oracle is attached."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def emit(handle, event: dict[str, Any]) -> None:
    handle.write(json.dumps(event, sort_keys=True) + "\n")
    handle.flush()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_case(handle, *, case_id: str, argv: list[str], cwd: Path | None = None,
             expected_returncode: int = 0, env: dict[str, str] | None = None) -> dict[str, Any]:
    start_ns = time.monotonic_ns()
    emit(handle, {
        "record_type": "step_start",
        "case_id": case_id,
        "ts_ns": start_ns,
        "argv": argv,
        "cwd": str(cwd) if cwd else os.getcwd(),
    })
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    end_ns = time.monotonic_ns()
    result = {
        "record_type": "step_result",
        "case_id": case_id,
        "start_ns": start_ns,
        "end_ns": end_ns,
        "duration_ns": end_ns - start_ns,
        "argv": argv,
        "cwd": str(cwd) if cwd else os.getcwd(),
        "returncode": completed.returncode,
        "expected_returncode": expected_returncode,
        "passed": completed.returncode == expected_returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    emit(handle, result)
    if not result["passed"]:
        raise RuntimeError(
            f"case {case_id!r} returned {completed.returncode}; "
            f"expected {expected_returncode}. stderr={completed.stderr!r}"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-dir", required=True, type=Path)
    parser.add_argument("--events", required=True, type=Path)
    args = parser.parse_args()

    fixture = args.fixture_dir.resolve()
    event_path = args.events.resolve()
    if not (fixture / ".git").is_dir():
        raise SystemExit(f"fixture repository not found: {fixture}; run prepare_fixture.py first")
    if not shutil.which("echo") or not Path("/bin/echo").exists():
        raise SystemExit("required echo executable is unavailable")
    if not Path("/bin/sh").exists() or not Path("/usr/bin/wc").exists():
        raise SystemExit("required /bin/sh or /usr/bin/wc is unavailable")
    false_path = shutil.which("false")
    if not false_path:
        raise SystemExit("required false executable is unavailable")
    git_path = shutil.which("git")
    if not git_path:
        raise SystemExit("required git executable is unavailable")

    event_path.parent.mkdir(parents=True, exist_ok=True)
    watched = fixture / "watched.txt"
    python_code = "import subprocess; subprocess.run(['git', 'log', '-n', '1'], check=False)"
    # Use a local fixture repo and a deliberately explicit expected argv shape.
    with event_path.open("w", encoding="utf-8") as handle:
        emit(handle, {
            "record_type": "supervisor_metadata",
            "schema_version": 1,
            "scenario_id": "python-subprocess-capture-v1",
            "python": sys.executable,
            "git_path_expected": git_path,
            "fixture_dir": str(fixture),
        })

        run_case(handle, case_id="path_echo", argv=["echo", "hello"])
        run_case(handle, case_id="absolute_echo", argv=["/bin/echo", "absolute"])
        run_case(
            handle,
            case_id="shell_pipeline",
            argv=["/bin/sh", "-c", "/bin/echo pipeline | /usr/bin/wc -l"],
        )
        run_case(handle, case_id="nonzero_exit", argv=[false_path], expected_returncode=1)
        run_case(
            handle,
            case_id="python_spawns_git",
            argv=[sys.executable, "-c", python_code],
            cwd=fixture,
        )

        before_exists = watched.exists()
        before_hash = sha256_file(watched) if before_exists else None
        start_ns = time.monotonic_ns()
        watched.write_text("first version\nsecond line\n", encoding="utf-8")
        end_ns = time.monotonic_ns()
        after_hash = sha256_file(watched)
        emit(handle, {
            "record_type": "filesystem_result",
            "case_id": "file_modification",
            "start_ns": start_ns,
            "end_ns": end_ns,
            "path": str(watched),
            "existed_before": before_exists,
            "sha256_before": before_hash,
            "sha256_after": after_hash,
            "changed": before_hash != after_hash,
        })

    print(f"Workflow completed. Supervisor observations: {event_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"workflow error: {exc}", file=sys.stderr)
        raise SystemExit(1)
