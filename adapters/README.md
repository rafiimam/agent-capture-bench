# Recorder adapters

An adapter converts one recorder's native output into the benchmark's
canonical schema so [`tools/report.py`](../tools/report.py) can compare it
against the eBPF oracle. Adapters are deliberately small parsers — they must
preserve the recorder's uncertainty, not launder it.

## Canonical schema: `canonical-exec-jsonl-v1`

One JSON object per line, one line per successful process execution:

```json
{"type": "exec", "filename": "/usr/bin/git", "argv": ["git", "log", "-n", "1"], "pid": 107, "ppid": 106}
```

| Field | Meaning |
|---|---|
| `type` | Always `"exec"` in v1. |
| `filename` | The executed file as the recorder reports it. If the recorder only reports the invoked command (e.g. execsnoop), use `argv[0]` as invoked — do not invent a resolved path. |
| `argv` | Argument vector as captured, in order, including `argv[0]`. If the recorder truncates arguments, preserve the truncated values as-is; do not pad or guess. |
| `pid` / `ppid` | Process and parent process IDs as reported. Use `0` only when the recorder genuinely does not report the value. |

Comparison (in `tools/report.py`, matcher `normalized-match-v1`) matches on
executable **basename**, then tiers: exact argv tuple → whitespace-collapsed
joined argv → prefix match at the oracle's truncation bound (only when
`args_truncated`) → quote/whitespace-tolerant comparison. The stricter
basename + exact-argv result is still reported (`strict_matched_event_count`)
for comparability with earlier published runs, and every unmatched oracle
event carries a machine-readable reason (`representation_difference_*` or
`no_recorder_evidence`). PID/timing correlation is not implemented yet, so an
adapter cannot gain or lose credit through timestamps — only through what it
captured.

## Included adapters

| Adapter | Recorder | Collection | Validation status |
|---|---|---|---|
| [`execsnoop.py`](execsnoop.py) | BCC `execsnoop` / `execsnoop-bpfcc` | `sudo execsnoop-bpfcc \| tee execsnoop.txt` during the run | **Validated 2026-10-20** (Ubuntu 24.04 arm64) |
| [`auditd.py`](auditd.py) | Linux audit framework | Load the execve/execveat audit rule *before* the run, export with `ausearch -k agentcap` after (see the adapter docstring) | Implemented, not yet run end-to-end |
| [`tetragon.py`](tetragon.py) | Cilium Tetragon | `sudo tetra getevents -o json --types PROCESS_EXEC \| tee tetragon.jsonl` during the run | **Unvalidated** — layout follows Tetragon docs; confirm against a real capture before publishing |
| [`falco.py`](falco.py) | Falco (JSON output) | Needs an unconditional execve/execveat rule; Falco does not log these by default (see docstring) | **Unvalidated** — and scope-limited to what its rules surface |
| [`osquery.py`](osquery.py) | osquery `process_events` | `sudo osqueryi --json "SELECT * FROM process_events"` with the BPF/audit events publisher enabled | **Unvalidated** |
| [`sysdig.py`](sysdig.py) | Sysdig (JSON) | `sudo sysdig -j evt.type in '(execve, execveat)' \| tee sysdig.jsonl` | **Unvalidated** — schema-tolerant by necessity; verify against `sysdig -l` for your version |
| [`rr`](https://github.com/rr-project/rr) — no adapter | Deterministic record/replay | n/a | Out of scope so far: rr replays a recorded tree rather than emitting an exec log; an adapter would need a different evidence model |
| DEPOSE / Tracekit — no adapter yet | Agent-layer recorders | n/a | Blocked on format verification — do not write a parser until a sanitized sample of the native output is available (see [adapter proposal template](../.github/ISSUE_TEMPLATE/recorder_adapter.md)); guessing a format would fabricate evidence |

All adapters take `--input` (native log) and `--output` (canonical JSONL), print a
summary including how many lines/events were skipped, and exit nonzero only on
I/O or usage errors. Skips are reported, never silent. **Unvalidated adapters
exist to be corrected on real hosts**; publishing a comparison from one without
a confirmatory run violates the classification discipline.

## Running a comparison end-to-end

```bash
# Terminal 1: start the recorder (example: execsnoop)
sudo execsnoop-bpfcc | tee /tmp/execsnoop.txt

# Terminal 2: run the experiment under the oracle
./run_experiment.sh        # or ACB_SUITE=all ./run_experiment.sh

# Then convert and compare (paths from the printed .work/run-* directory)
python3 adapters/execsnoop.py --input /tmp/execsnoop.txt --output .work/run-*/recorder-output.jsonl
python3 tools/report.py --oracle .work/run-*/oracle-events.jsonl \
  --supervisor .work/run-*/supervisor-events.jsonl \
  --recorder .work/run-*/recorder-output.jsonl --output .work/run-*/report.json
```

Note the recorder also captures unrelated system activity; the comparison
reports *unexpected* events separately from *missed* ones for exactly this
reason. When publishing results, pin the recorder version, configuration, and
host details alongside the report.

## Writing a new adapter

1. Read the recorder's documented capture guarantee first — the adapter (and
   any result published from it) is scored against that guarantee, nothing
   else. If the guarantee is unclear, say so in the adapter docstring.
2. Copy the structure of an existing adapter: pure `convert(lines)` function,
   `--input`/`--output` CLI, skip counting on stderr.
3. Add parser tests with synthetic native-format fixtures under `tests/`.
4. Open the PR with a sample of the native input format (sanitized) so
   reviewers can check the parser against reality.
