from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_adapter(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "adapters" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExecsnoopAdapterTests(unittest.TestCase):
    def test_parses_successful_execs_and_skips_failures(self) -> None:
        adapter = load_adapter("execsnoop")
        lines = [
            "TIME(s)            COMM             PID     PPID    RET ARGS",
            "0.000              python3          106     100     0   python3 -c pass",
            "0.010              git              107     106     0   git log -n 1",
            "0.020              missing          108     106     -2   /bin/missing arg",
            "garbage line that does not parse",
        ]
        records, skipped = adapter.convert(lines)
        self.assertEqual(len(records), 2)
        self.assertEqual(skipped, 1)
        self.assertEqual(records[1]["filename"], "git")
        self.assertEqual(records[1]["argv"], ["git", "log", "-n", "1"])
        self.assertEqual(records[1]["ppid"], 106)


class AuditdAdapterTests(unittest.TestCase):
    def test_joins_execve_and_syscall_records_and_decodes_hex(self) -> None:
        adapter = load_adapter("auditd")
        lines = [
            'type=SYSCALL msg=audit(1700000000.100:501): arch=c000003e syscall=59 '
            'success=yes exit=0 ppid=106 pid=107 exe="/usr/bin/git" key="agentcap"',
            'type=EXECVE msg=audit(1700000000.100:501): argc=4 a0="git" a1="log" a2="-n" a3="1"',
            # Hex-encoded argument ("hello world") and a failed exec that must be dropped.
            'type=SYSCALL msg=audit(1700000000.200:502): arch=c000003e syscall=59 '
            'success=yes exit=0 ppid=100 pid=108 exe="/usr/bin/echo" key="agentcap"',
            'type=EXECVE msg=audit(1700000000.200:502): argc=2 a0="echo" a1=68656C6C6F20776F726C64',
            'type=SYSCALL msg=audit(1700000000.300:503): arch=c000003e syscall=59 '
            'success=no exit=-2 ppid=100 pid=109 exe="/bin/missing" key="agentcap"',
            'type=EXECVE msg=audit(1700000000.300:503): argc=1 a0="/bin/missing"',
        ]
        records, incomplete = adapter.convert(lines)
        self.assertEqual(incomplete, 0)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["filename"], "/usr/bin/git")
        self.assertEqual(records[0]["argv"], ["git", "log", "-n", "1"])
        self.assertEqual(records[1]["argv"], ["echo", "hello world"])


if __name__ == "__main__":
    unittest.main()
