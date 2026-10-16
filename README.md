# AgentCaptureBench — Linux oracle prototype

> **Status: experimental prototype; not yet validated on a host where eBPF can be loaded.**
>
> This repository is the first, deliberately narrow milestone: an independent Linux process-execution observer plus one deterministic workflow. It does not yet include adapters for DEPOSE, Tracekit, or other recorders, and it does not establish a new capture failure.

## Research question

Under a controlled Linux execution environment, does a selected capture configuration record a child process launched by a Python interpreter, and does that behavior match the configuration's documented guarantees?

The high-value test case is:

```python
import subprocess
subprocess.run(['git', 'log', '-n', '1'], check=False)
```

The oracle observes successful process image changes through `sched:sched_process_exec`, captures bounded argv data at `sys_enter_execve` and `sys_enter_execveat`, and uses `sched:sched_process_fork` to reconstruct parent/child relationships. Its output is independent of any recorder-under-test output.

**The oracle is not omniscient.** It does not prove that all system activity was observed. It logs successful exec events, not every failed `execve()` attempt; captures at most 8 argv elements of 95 bytes each; and uses a kernel tracepoint as its process-execution ground truth. A missing event must be classified as *undetermined* until oracle permissions, scenario execution, configuration, and buffering have been checked.

## Artifacts

- `workflow/scenario.yaml` — expectations and measurement boundaries.
- `.work/run-*/oracle-events.jsonl` — independent eBPF event stream, including metadata.
- `.work/run-*/supervisor-events.jsonl` — workflow step outcomes and before/after hashes for the controlled file.
- `.work/run-*/oracle-report.json` — sanity report for the oracle and workflow. This is not a recorder-comparison result.
- `recorder-output.jsonl` — reserved for a future recorder adapter; no adapter is implemented yet.

The supervisor and eBPF oracle answer different questions. The supervisor records whether named workflow steps completed and what their return codes and file hashes were. The kernel oracle records successful exec/fork events. Neither is derived from the recorder-under-test output.

## Prototype event schema

Every non-metadata line in `oracle-events.jsonl` uses these fields:

- `record_type`: `event`
- `seq`: userspace delivery sequence (not a guaranteed cross-CPU kernel total order)
- `ts_ns`: monotonic nanoseconds from `bpf_ktime_get_ns()`
- `type`: `fork` or `exec`
- `pid`, `ppid`, `old_pid`, `comm`, `filename`
- `argv`, `argc`, `args_truncated`

`ppid: 0` means unknown in this prototype; do not interpret it as proof of a root process. Fork records establish ancestry, while exec records are emitted when the kernel reports a successful image change. Arguments may be truncated, and the report must preserve that uncertainty.

## Requirements

The prototype targets Linux with:

- A kernel with eBPF, ring-buffer map support, and the following tracepoints: `syscalls:sys_enter_execve`, `syscalls:sys_enter_execveat`, `sched:sched_process_fork`, `sched:sched_process_exec`, and `sched:sched_process_exit`.
- Clang with the BPF backend (the `clang` binary must support `-target bpf`).
- `libbpf-dev`, `libelf-dev`, `zlib1g-dev`, a C compiler, `make`, and the usual kernel/userspace development headers.
- Permission to load eBPF programs and attach to tracepoints. Depending on the kernel and security policy, this generally requires root or suitable `CAP_BPF`/`CAP_PERFMON` and perf-event permissions.
- Python 3 and Git for the workflow.

On Debian/Ubuntu, dependencies are typically installed with:

```bash
sudo apt update
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev make gcc git python3
```

Exact package versions and capabilities vary by distribution, kernel, container policy, and lockdown settings. Building successfully does not imply that the current host permits BPF loading.

## Run

From this directory:

```bash
make
./run_experiment.sh
```

The script prepares a tiny local Git fixture before attaching the oracle, then invokes the target workflow while capture is active. When run through `sudo`, the loader attempts to drop the target child back to the invoking user's `SUDO_UID`/`SUDO_GID` before releasing it. If you run as root without `SUDO_UID` and `SUDO_GID`, the tool refuses to run the target unless you explicitly pass `--allow-root-target`; use that override only inside an isolated test environment.

To run manually:

```bash
mkdir -p .work
python3 workflow/prepare_fixture.py --dir .work/fixture
sudo build/agentcap-oracle \
  --output .work/oracle-events.jsonl -- \
  "$(command -v python3)" "$PWD/workflow/run_workflow.py" \
  --fixture-dir "$PWD/.work/fixture" \
  --events "$PWD/.work/supervisor-events.jsonl"
python3 tools/report.py \
  --oracle .work/oracle-events.jsonl \
  --supervisor .work/supervisor-events.jsonl \
  --output .work/oracle-report.json
```

The experiment script creates a unique `.work/run-*` directory for each run. The fixture preparation script refuses to reuse an existing Git repository, preventing accidental mixing of observations across experiments.

## Workflow cases

1. `echo hello` resolved through `PATH`.
2. `/bin/echo absolute` invoked by absolute path.
3. A pipeline containing `/bin/echo` and `/usr/bin/wc`.
4. `/usr/bin/false`, which executes successfully and then returns exit status 1.
5. A Python `-c` process that calls `subprocess.run(['git', 'log', '-n', '1'])` in the local fixture repository.
6. A controlled file write with SHA-256 hashes recorded before and after.

This first experiment intentionally excludes session interruption, secret-redaction, tamper detection, syscall-level failed-exec capture, and macOS. Those should be separate test families after the Linux oracle is validated.

## Interpretation rules

Use four distinct classifications when recorder adapters are added:

- **Conformant** — the output matches the documented capture guarantee.
- **Capture failure** — an event covered by the stated guarantee is missing or incorrect.
- **Scope limitation** — the event is outside the stated guarantee and this boundary is explicit.
- **Undetermined** — insufficient evidence to distinguish a recorder miss from a workflow, permission, oracle, configuration, or buffering problem.

A recorder is not defective merely because it does not capture OS-level child processes when it promises only to record agent lifecycle hooks. Likewise, a signed or hash-chained record can establish integrity of recorded bytes without establishing completeness of capture.

Do not rank recorders using one composite score. Report capture coverage, field accuracy, event ordering/correlation, redaction, integrity, and overhead separately. A recorder comparison should pin exact versions, permissions, platform, configuration, and documented claims.

## Current validation status

The source tree was created in a constrained Linux container. In this environment, tracefs is not mounted, the installed Swift-derived Clang does not advertise a BPF target, and libbpf development headers are absent. Therefore the eBPF program could **not** be compiled, loaded, or validated against real kernel events here. The Python workflow and report parser are testable independently; successful tests of those scripts are not evidence that the kernel oracle works.

After running on a suitable host, publish the exact kernel version, distribution, compiler/libbpf versions, capabilities, raw JSONL files, and report. If the oracle fails to attach or its observed events don't match the workflow, classify the experiment as *undetermined* until the oracle itself is debugged.

## Useful technical references

- Linux tracepoint eBPF program type: <https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACEPOINT/>
- libbpf-bootstrap process execution example: <https://github.com/libbpf/libbpf-bootstrap>
- Kernel tracepoint program sections: <https://kernel.org/doc/html/latest/bpf/libbpf/program_types.html>

## License

MIT. See `LICENSE`.
