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


    def test_parses_ubuntu_bpfcc_layout_without_time_column(self) -> None:
        # Real lines captured from execsnoop-bpfcc on Ubuntu 24.04 (2026-10-20):
        # header is "PCOMM PID PPID RET ARGS" and events can precede the header.
        adapter = load_adapter("execsnoop")
        lines = [
            "bash             20583   1123      0 /bin/bash -c echo hello",
            "PCOMM            PID     PPID    RET ARGS",
            "cat              20590   20587     0 /usr/bin/cat /proc/loadavg",
            "git              30107   30106     0 git log -n 1",
            "missing          30108   30106     -2 /bin/missing",
        ]
        records, skipped = adapter.convert(lines)
        self.assertEqual(skipped, 0)
        self.assertEqual(len(records), 3)
        self.assertEqual(records[1]["argv"], ["/usr/bin/cat", "/proc/loadavg"])
        self.assertEqual(records[1]["pid"], 20590)
        self.assertEqual(records[1]["ppid"], 20587)
        self.assertEqual(records[2]["filename"], "git")


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


class TetragonAdapterTests(unittest.TestCase):
    def test_parses_process_exec_event_nested_shape(self) -> None:
        adapter = load_adapter("tetragon")
        lines = [
            '{"process_exec":{"process":{"binary":"/usr/bin/git","arguments":"log -n 1",'
            '"pid":107,"ppid":106},"parent":{"pid":105}},"node_name":"vm1","time":"2026-11-16T00:00:00Z"}',
            '{"process_exec":{"process":{"binary":"/bin/echo","arguments":"hello","pid":108}}}',
            'not json',
            '{"process_exit":{"process":{"binary":"/bin/echo","pid":108}}}',
        ]
        records, skipped = adapter.convert(lines)
        self.assertEqual(len(records), 2)
        self.assertEqual(skipped, 2)
        self.assertEqual(records[0]["argv"], ["/usr/bin/git", "log", "-n", "1"])
        self.assertEqual(records[0]["ppid"], 106)
        # No ppid in process and parent only carried pid 105 in event 1;
        # event 2 has neither → ppid unknown (0), never guessed.
        self.assertEqual(records[1]["ppid"], 0)


class FalcoAdapterTests(unittest.TestCase):
    def test_parses_execve_rules_and_ignores_other_events(self) -> None:
        adapter = load_adapter("falco")
        lines = [
            '{"rule":"AgentCaptureBench execve accounting","output":"acb",'
            '"priority":"Notice","time":"2026-11-16T00:00:00Z",'
            '"output_fields":{"evt.type":"execve","proc.pid":"107","proc.ppid":"106",'
            '"proc.exepath":"/usr/bin/git","proc.cmdline":"git log -n 1"}}',
            '{"rule":"Terminal shell in container","output":"alert",'
            '"priority":"Notice",'
            '"output_fields":{"evt.type":"open","proc.pid":"108","proc.pcmdline":"bash"}}',
        ]
        records, skipped = adapter.convert(lines)
        self.assertEqual(len(records), 1)
        self.assertEqual(skipped, 1)
        self.assertEqual(records[0]["filename"], "/usr/bin/git")
        self.assertEqual(records[0]["argv"], ["git", "log", "-n", "1"])
        self.assertEqual(records[0]["pid"], 107)
        self.assertEqual(records[0]["ppid"], 106)


class OsqueryAdapterTests(unittest.TestCase):
    def test_parses_json_array_and_ndjson(self) -> None:
        adapter = load_adapter("osquery")
        array_input = [
            '[{"action":"exec","path":"/usr/bin/git","cmdline":"[\\"git\\",\\"log\\",\\"-n\\",\\"1\\"]",'
            '"pid":"107","ppid":"106","time":"1760000000"},'
            '{"action":"exit","path":"/usr/bin/git","pid":"107","ppid":"106"}]',
        ]
        records, skipped = adapter.convert(array_input)
        self.assertEqual(len(records), 1)
        self.assertEqual(skipped, 1)
        self.assertEqual(records[0]["argv"], ["git", "log", "-n", "1"])
        self.assertEqual(records[0]["pid"], 107)
        self.assertEqual(records[0]["ppid"], 106)

        ndjson_input = [
            '{"action":"exec","path":"/bin/echo","cmdline":"[\\"echo\\",\\"hello\\"]",'
            '"pid":"109","ppid":"108"}',
        ]
        records, skipped = adapter.convert(ndjson_input)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["argv"], ["echo", "hello"])


class SysdigAdapterTests(unittest.TestCase):
    def test_tolerant_lookup_matches_execve_and_skips_others(self) -> None:
        adapter = load_adapter("sysdig")
        lines = [
            '{"ts":1760000000.1,"name":"syscall","evdata":{"type":"execve","args":'
            '{"name":"git","args":"git log -n 1","pid":"107","ppid":"106",'
            '"exepath":"/usr/bin/git"}}}',
            '{"ts":1760000001.1,"name":"syscall","evdata":{"type":"open","args":{"fd":"3"}}}',
            '{"ts":1760000002.1,"name":"syscall","evdata":{"type":"execve","args":'
            '{"name":"echo","args":"echo hello","pid":"108"}}}',
        ]
        records, skipped = adapter.convert(lines)
        self.assertEqual(len(records), 2)
        self.assertEqual(skipped, 1)
        self.assertEqual(records[0]["filename"], "/usr/bin/git")
        self.assertEqual(records[0]["argv"], ["git", "log", "-n", "1"])
        # No ppid in event 3 → 0 (unknown), never guessed.
        self.assertEqual(records[1]["ppid"], 0)


if __name__ == "__main__":
    unittest.main()
