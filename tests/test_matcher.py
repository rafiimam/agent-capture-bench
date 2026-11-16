from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_report():
    spec = importlib.util.spec_from_file_location("report", ROOT / "tools" / "report.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REPORT = load_report()


def oracle_event(
    filename: str,
    argv: list[str],
    *,
    pid: int = 1000,
    ppid: int = 999,
    truncated: bool = False,
) -> dict:
    return {
        "type": "exec",
        "filename": filename,
        "argv": argv,
        "pid": pid,
        "ppid": ppid,
        "args_truncated": truncated,
    }


def recorder_event(filename: str, argv: list[str], *, pid: int = 1000, ppid: int = 999) -> dict:
    return {"type": "exec", "filename": filename, "argv": argv, "pid": pid, "ppid": ppid}


PYTHON_CODE = (
    "import subprocess; subprocess.run(['git', 'log', '-n', '1'], check=False)"
)


class NormalizedMatcherTests(unittest.TestCase):
    def compare(self, oracle, recorder):
        return REPORT.compare_canonical_recorder(oracle, recorder)

    def test_resolved_vs_invoked_argv0_matches_at_token_collapsed_tier(self) -> None:
        # argv[0] recorded resolved (/usr/bin/echo) vs as-invoked (echo): the
        # basename rule pairs these without touching arguments.
        result = self.compare(
            [oracle_event("/usr/bin/echo", ["/bin/echo", "hello"])],
            [recorder_event("/bin/echo", ["echo", "hello"])],
        )
        self.assertEqual(result["matched_event_count"], 1)
        self.assertEqual(result["match_tier_counts"].get("tier2_token_collapsed"), 1)
        self.assertEqual(result["unmatched_oracle_events"], [])

    def test_space_joined_fragmentation_matches_at_token_collapsed_tier(self) -> None:
        # execsnoop renders argv space-joined; the adapter's re-split fragments
        # the -c string, but whitespace-collapsed joining reconstitutes it.
        oracle = [oracle_event("/bin/sh", ["/bin/sh", "-c", "/bin/echo pipeline | /usr/bin/wc -l"])]
        recorder = [recorder_event("sh", ["/bin/sh", "-c", "/bin/echo", "pipeline", "|", "/usr/bin/wc", "-l"])]
        result = self.compare(oracle, recorder)
        self.assertEqual(result["match_tier_counts"].get("tier2_token_collapsed"), 1)
        self.assertEqual(result["unmatched_oracle_events"], [])

    def test_shell_tolerant_matches_quote_rendering_differences(self) -> None:
        # Python -c code: oracle keeps the raw source (with quotes and brackets);
        # execsnoop's space-joined text drops/alters them. Quote- and
        # whitespace-tolerant comparison pairs them.
        oracle = [oracle_event("/usr/bin/python3", ["python3", "-c", PYTHON_CODE])]
        recorder = [
            recorder_event("python3",
                           ["python3", "-c", "import", "subprocess;", "subprocess.run([git,",
                            "log,", "-n,", "1],", "check=False)"])
        ]
        result = self.compare(oracle, recorder)
        self.assertEqual(result["unmatched_oracle_events"], [])
        self.assertEqual(result["matched_event_count"], 1)

    def test_truncation_prefix_matches_when_oracle_flags_args_truncated(self) -> None:
        oracle = [oracle_event("/bin/echo", ["/bin/echo"] + [f"arg{i}" for i in range(7)],
                               truncated=True)]
        recorder = [recorder_event("echo",
                                   ["echo"] + [f"arg{i}" for i in range(7)]
                                   + ["arg7", "arg8", "arg9", "arg10", "arg11", "A" * 200])]
        result = self.compare(oracle, recorder)
        self.assertEqual(result["unmatched_oracle_events"], [])
        tiers = result["match_tier_counts"]
        self.assertEqual(sum(tiers.values()), 1)
        self.assertTrue(any(name.startswith("tier3") or name.startswith("tier4")
                            for name in tiers))

    def test_truncation_prefix_requires_args_truncated_flag(self) -> None:
        oracle = [oracle_event("/bin/echo", ["/bin/echo", "a"], truncated=False)]
        recorder = [recorder_event("echo", ["echo", "a", "b", "c"])]
        result = self.compare(oracle, recorder)
        self.assertEqual(result["matched_event_count"], 0)
        self.assertEqual(result["unmatched_oracle_events"][0]["reason"],
                         "representation_difference_unresolved")

    def test_git_child_pairs_as_invoked_resolved(self) -> None:
        oracle = [oracle_event("/usr/bin/git", ["git", "log", "-n", "1"])]
        recorder = [recorder_event("git", ["git", "log", "-n", "1"])]
        result = self.compare(oracle, recorder)
        self.assertEqual(result["matched_event_count"], 1)

    def test_missing_git_child_is_no_recorder_evidence(self) -> None:
        oracle = [
            oracle_event("/usr/bin/python3", ["python3", "-c", PYTHON_CODE]),
            oracle_event("/usr/bin/git", ["git", "log", "-n", "1"], pid=1001, ppid=1000),
        ]
        recorder = [recorder_event("python3", ["python3", "-c", PYTHON_CODE])]
        result = self.compare(oracle, recorder)
        self.assertEqual(result["matched_event_count"], 1)
        unmatched = result["unmatched_oracle_events"]
        self.assertEqual(len(unmatched), 1)
        self.assertEqual(unmatched[0]["reason"], "no_recorder_evidence")
        self.assertEqual(unmatched[0]["filename_basename"], "git")

    def test_recorder_only_events_are_unexpected_not_failures(self) -> None:
        result = self.compare(
            [oracle_event("/usr/bin/git", ["git", "log", "-n", "1"])],
            [recorder_event("git", ["git", "log", "-n", "1"]),
             recorder_event("curl", ["curl", "https://example.com"], pid=3000, ppid=1)],
        )
        self.assertEqual(len(result["unexpected_events"]), 1)
        self.assertEqual(result["unexpected_events"][0]["filename_basename"], "curl")

    def test_tier1_multiset_semantics_preserved(self) -> None:
        oracle = [oracle_event("/usr/bin/true", ["/bin/true"], pid=i) for i in range(3)]
        recorder = [recorder_event("true", ["/bin/true"], pid=i) for i in range(2)]
        result = self.compare(oracle, recorder)
        self.assertEqual(result["strict_matched_event_count"], 2)
        self.assertEqual(len(result["unmatched_oracle_events"]), 1)

    def test_python_spawns_git_pair_end_to_end(self) -> None:
        # The 2026-10-20 execsnoop run: 38 oracle execs, 27 strict matches,
        # 11 representation differences, 0 genuine misses. The normalizing
        # matcher must close the gap on the fixture-shaped subset.
        oracle = [
            oracle_event("/usr/bin/echo", ["/bin/echo", "hello"]),
            oracle_event("/usr/bin/echo", ["/bin/echo", "absolute"]),
            oracle_event("/bin/sh", ["/bin/sh", "-c", "/bin/echo pipeline | /usr/bin/wc -l"]),
            oracle_event("/usr/bin/wc", ["/usr/bin/wc", "-l"]),
            oracle_event("/bin/echo", ["/bin/echo", "pipeline"]),
            oracle_event("/usr/bin/false", ["/usr/bin/false"]),
            oracle_event("/usr/bin/python3", ["python3", "-c", PYTHON_CODE]),
            oracle_event("/usr/bin/git", ["git", "log", "-n", "1"], pid=1001, ppid=1000),
        ]
        recorder = [
            recorder_event("echo", ["echo", "hello"]),
            recorder_event("/bin/echo", ["/bin/echo", "absolute"]),
            recorder_event("sh", ["sh", "-c", "/bin/echo", "pipeline", "|", "/usr/bin/wc", "-l"]),
            recorder_event("/usr/bin/wc", ["wc", "-l"]),
            recorder_event("echo", ["echo", "pipeline"]),
            recorder_event("false", ["false"]),
            recorder_event("python3", ["python3", "-c", "import", "subprocess;",
                                       "subprocess.run([git,", "log,", "-n,", "1],",
                                       "check=False)"]),
            recorder_event("git", ["git", "log", "-n", "1"]),
        ]
        result = self.compare(oracle, recorder)
        self.assertEqual(result["unmatched_oracle_events"], [])
        self.assertEqual(result["matched_event_count"], len(oracle))


if __name__ == "__main__":
    unittest.main()
