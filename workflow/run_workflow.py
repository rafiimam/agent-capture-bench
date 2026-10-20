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


# --- Evasion suite (scenario capture-evasion-v1) ----------------------------
# Each snippet runs as `python -c <code>` so the oracle sees a Python parent,
# mirroring how an agent runtime launches work. Snippets must be deterministic
# and self-verifying: a nonzero exit fails the supervisor step.

EXECVEAT_CODE = r"""
import ctypes, os, sys
SYS_execveat = {"x86_64": 322, "aarch64": 281, "arm64": 281}[os.uname().machine]
libc = ctypes.CDLL(None, use_errno=True)
pid = os.fork()
if pid == 0:
    # NOTE: raw execveat performs no PATH search (unlike execvp); a bare
    # "git" would mean ./git. The workflow injects git's resolved path.
    argv = [b"git", b"log", b"-n", b"1"]
    cargv = (ctypes.c_char_p * (len(argv) + 1))(*argv, None)
    cenvp = (ctypes.c_char_p * 1)(None)
    ret = libc.syscall(SYS_execveat, -100, b"GIT_PATH_PLACEHOLDER", cargv, cenvp, 0)
    os._exit(127 if ret == -1 else 0)
_, status = os.waitpid(pid, 0)
sys.exit(0 if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 else 1)
""".strip()

DOUBLE_FORK_CODE = r"""
import os, sys, time
marker = os.path.join(os.getcwd(), "daemon-marker.txt")
if os.path.exists(marker):
    os.unlink(marker)
first = os.fork()
if first == 0:
    second = os.fork()
    if second == 0:
        with open(marker, "w") as fh:
            fh.write("grandchild ran\n")
        os.execv("/bin/echo", ["/bin/echo", "daemon-echo"])
    os._exit(0)
os.waitpid(first, 0)
for _ in range(100):
    if os.path.exists(marker):
        sys.exit(0)
    time.sleep(0.05)
sys.exit(1)
""".strip()

BURST_CODE = r"""
import subprocess, sys
for _ in range(20):
    subprocess.run(["/bin/true"], check=True)
sys.exit(0)
""".strip()


def run_evasion_cases(handle, fixture: Path) -> None:
    """Scenario capture-evasion-v1: execution patterns capture tools miss."""
    run_case(
        handle,
        case_id="shell_c_git",
        argv=["/bin/sh", "-c", "git log -n 1"],
        cwd=fixture,
    )
    git_path = shutil.which("git") or "/usr/bin/git"
    run_case(
        handle,
        case_id="execveat_git",
        argv=[sys.executable, "-c", EXECVEAT_CODE.replace("GIT_PATH_PLACEHOLDER", git_path)],
        cwd=fixture,
    )
    run_case(
        handle,
        case_id="double_fork_daemon",
        argv=[sys.executable, "-c", DOUBLE_FORK_CODE],
        cwd=fixture,
    )
    run_case(
        handle,
        case_id="short_lived_burst",
        argv=[sys.executable, "-c", BURST_CODE],
        cwd=fixture,
    )
    long_arg = "A" * 200
    run_case(
        handle,
        case_id="argv_overflow",
        argv=["/bin/echo"] + [f"arg{i}" for i in range(12)] + [long_arg],
    )
    script = fixture / "helper.sh"
    script.write_text("#!/bin/sh\necho scripted\n", encoding="utf-8")
    script.chmod(0o755)
    run_case(handle, case_id="script_exec", argv=[str(script)])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-dir", required=True, type=Path)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--suite", choices=["core", "evasion", "all"], default="core",
                        help="core = scenario python-subprocess-capture-v1 (default); "
                             "evasion adds scenario capture-evasion-v1 cases")
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
    if not shutil.which("true") or not Path("/bin/true").exists():
        raise SystemExit("required /bin/true executable is unavailable")
    git_path = shutil.which("git")
    if not git_path:
        raise SystemExit("required git executable is unavailable")

    event_path.parent.mkdir(parents=True, exist_ok=True)
    watched = fixture / "watched.txt"
    python_code = "import subprocess; subprocess.run(['git', 'log', '-n', '1'], check=False)"
    # Use a local fixture repo and a deliberately explicit expected argv shape.
    with event_path.open("w", encoding="utf-8") as handle:
        scenario_ids = []
        if args.suite in ("core", "all"):
            scenario_ids.append("python-subprocess-capture-v1")
        if args.suite in ("evasion", "all"):
            scenario_ids.append("capture-evasion-v1")
        emit(handle, {
            "record_type": "supervisor_metadata",
            "schema_version": 1,
            "scenario_id": "+".join(scenario_ids),
            "suite": args.suite,
            "python": sys.executable,
            "git_path_expected": git_path,
            "fixture_dir": str(fixture),
        })

        if args.suite in ("core", "all"):
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

        if args.suite in ("evasion", "all"):
            run_evasion_cases(handle, fixture)

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
