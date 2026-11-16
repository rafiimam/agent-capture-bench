# Validation log

> **2026-11-16 — two entries below are validated and published in `results/`:**
> the 2026-10-20 execsnoop comparison re-scored with `normalized-match-v1`
> (34/38 matched), and a fresh `ACB_SUITE=all` run on 2026-11-16 (37/41
> matched; kernel 6.8.0-147-generic; all core/evasion/redaction checks
> true; redaction family validated on a real host). Both reproduced the same
> execveat finding: `execsnoop-bpfcc` (Ubuntu bpfcc-tools 0.29.1) attaches a
> kprobe to `sys_execve` only and cannot see execveat-spawned execs.
> Still NOT validated on any host: the Tetragon, Falco, osquery, and Sysdig
> adapters — none may produce a published comparison until confirmed against a
> real capture. Anything not yet run is stated as such; a failed or unmatched
> run is classified *undetermined* until the oracle side is ruled out.

## Fresh end-to-end run — 2026-11-16 (results published in results/execsnoop-bpfcc-2026-11-16/)

Ubuntu 24.04.5 LTS (aarch64), kernel 6.8.0-147-generic (Multipass VM), clang
18.1.3 (Ubuntu 1ubuntu1), libbpf 1:1.3.0-2build2, bpfcc-tools
0.29.1+ds-1ubuntu7, ACB `main` @ 6c6b058, suite `all`
(`ACB_SUITE=all ./run_experiment.sh`):

- Oracle: **82 events (41 exec, 41 fork)**; supervisor **14/14 steps passed**.
- Checks: core **10/10 true**; evasion **9/9 true** (incl. 20/20
  short-lived burst, execveat child seen by the oracle); redaction **3/3
  true** — first host validation of the family.
- Redaction analysis: oracle observed the synthetic marker (1 full-argv
  event; the overflow probe's marker survives only as a prefix at the
  95-byte bound, `args_truncated` set). The recorder captured the two
  marker-bearing echo executions **verbatim** (2 events;
  `marker_present_in_recorder`) — execsnoop-bpfcc does not redact.
- Recorder comparison (matcher `normalized-match-v1`): 41 oracle execs,
  **37 paired** (29 strict + 5 token-collapsed + 2 truncation-prefix +
  1 shell-tolerant); 4 unmatched — 3 truncated python `-c` probes with
  same-PID recorder evidence (representation), 1 execveat-spawned git child
  absent (scope limitation, mechanism-confirmed — execsnoop-bpfcc hooks
  `sys_execve` only). 61 recorder-only events (system background).

## Re-score of the 2026-10-20 capture with normalized-match-v1 — 2026-11-16

Same capture, new matcher (see [results/execsnoop-bpfcc-2026-10-20/](results/execsnoop-bpfcc-2026-10-20/)):
oracle **38** execs; **34 paired** (27 strict + 5 token-collapsed +
1 truncation-prefix + 1 shell-tolerant); 4 unmatched with the same two
adjudicated classes as the fresh run. 224 recorder-only events under strict
matching became 217 after normalized matching. Raw artifacts and full
adjudication are published with the entry; the original exact-match report is
retained as `report-exact-match-original.json`.

## First real-host validation — 2026-10-20

The eBPF oracle was built, loaded, and run against the core scenario on a
real (virtualized) kernel for the first time.

### Environment

| Item | Value |
|---|---|
| Host | Multipass VM on MacBook Air M1 (Apple Silicon) |
| Guest | Ubuntu 24.04.5 LTS (noble), aarch64 |
| Kernel | 6.8.0-147-generic (`Linux acb 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC aarch64`) |
| Clang | Ubuntu clang 18.1.3 (1ubuntu1) |
| libbpf | libbpf-dev 1:1.3.0-2build2 (arm64) |

### Portability bugs found and fixed by this validation

1. **`__builtin_memset` on large structs fails the BPF build** (commit
   f99968d). Clang's BPF backend has no memset/memcpy libcall; the builtin on
   the 1072-byte `acb_event` (and the 776-byte `acb_argv_data`) errored with
   *"A call to built-in function 'memset' is not supported."* Replaced with
   explicit unrolled `__u64` word loops (`zero_event` / `copy_argv`).
2. **Clang's loop-idiom pass resurrected the memset** (commit f40b2e7). The
   plain zeroing loop was recognized and rewritten as a memset call, failing
   at the store itself. All loop accesses are now `volatile`, which is exempt
   from idiom recognition.

### Core suite run (scenario python-subprocess-capture-v1)

- Run directory: `.work/run-20261020T161818-12851`
- `make`: **PASS** — `oracle.bpf.o` and the userspace loader both build.
- `./run_experiment.sh`: **PASS** — oracle attached and collected events.
- Oracle events: **17** (9 exec, 8 fork).
- Supervisor: **5/5 steps passed**.
- Observed checks: **10/10 true** — `path_echo_seen`, `absolute_echo_seen`,
  `shell_pipeline_shell_seen`, `shell_pipeline_echo_seen`,
  `shell_pipeline_wc_seen`, `nonzero_command_seen`, `python_probe_seen`,
  `git_child_exec_seen`, `git_parent_is_python_probe`,
  `file_change_recorded`. `all_oracle_checks_observed: true`.

This validates the oracle for the core scenario on the environment above:
it attaches, observes successful execs and fork ancestry, and correctly
attributes the Python-launched `git` child.

### Evasion suite run (scenario capture-evasion-v1) — 2026-10-20

Same environment, `ACB_SUITE=all ./run_experiment.sh`, reproduced identically
across three runs (`.work/run-20261020T162304-18500`,
`.work/run-20261020T162512-21137`, `.work/run-20261020T163015-27119`):

- Oracle events: **76** (38 exec, 38 fork); supervisor **11/11 steps passed**.
- Core checks: **10/10 true**. Evasion checks: **9/9 true** —
  `shell_c_git_shell_seen`, `execveat_probe_seen`, `execveat_git_child_seen`,
  `daemon_grandchild_seen`, `daemon_grandchild_orphaned`,
  `short_lived_burst_all_seen` (count exactly 20),
  `argv_overflow_truncation_flagged`, `script_exec_seen`.
- Two defects were found and fixed during this validation, neither in the
  oracle: (1) `report.py`'s overflow check required `argc >= 9`, but the
  oracle's `argc` counts *captured* args and caps at 8 — the raw event stream
  confirms `args_truncated: true` was set correctly all along (commit
  fdfffd9); (2) the execsnoop adapter knew only the upstream BCC header
  layout and skipped 548/548 lines of Ubuntu's `PCOMM`-layout output (same
  commit). Both fixes carry regression tests built from the real data.

### First recorder comparison: execsnoop (BCC / bpfcc-tools) — 2026-10-20

Setup: `execsnoop-bpfcc` (Ubuntu 24.04 `bpfcc-tools`) recording system-wide
during an `ACB_SUITE=all` run (`.work/run-20261020T163015-27119`), converted
with `adapters/execsnoop.py` (251 recorder events) and compared with
`tools/report.py`.

- Oracle exec events: **38**. Exact-argv matches: **27**.
- **11 oracle events unmatched — all classified as representation
  differences, not capture failures**, after inspecting the pairs:
  argv[0] recorded resolved (`/usr/bin/echo`, `/usr/bin/git`) vs as-invoked
  (`echo`, `git`); multi-word arguments (`sh -c` strings, Python `-c` code)
  fragmented by execsnoop's space-joined text format and bounded at 95 bytes
  by the oracle, so exact-argv matching cannot pair them; the argv-overflow
  event, where the oracle caps at 8 args and execsnoop prints all 14.

  **Superseded by the 2026-11-16 re-score above (results/execsnoop-bpfcc-2026-10-20/):
  34/38 paired; 4 remained unmatched — 3 truncated python `-c` probes
  (representation; same-PID evidence) and the execveat-spawned git child,
  which is **absent** from the recorder's stream (scope limitation —
  execsnoop-bpfcc hooks `sys_execve` only). The "every execution is present"
  phrasing does not hold for the execveat path.**
- **224 recorder events had no oracle counterpart** — expected and not a
  defect on either side: execsnoop is system-wide (VM background services,
  fixture setup, the harness's own shell commands), while the oracle tracks
  only the workflow's process tree.
- Methodology note: exact-argv matching understates agreement when the two
  sides bound or render argv differently. This landed as the
  `normalized-match-v1` matcher (see the 2026-11-16 re-score and fresh run
  above) and the comparison is now published with tier counts plus per-event
  adjudication in `results/`, not as a bare match count.

## Authoring-container checks — 2026-10-16

## Checks performed in the authoring container

- `python3 -m unittest discover -s tests -v`: **PASS**, 3 tests.
  - Workflow executes the six defined cases (five command cases plus controlled file modification) and records real return codes/hashes.
  - Fixture setup refuses to reuse an existing Git repository.
  - Report parser identifies a synthetic Python `-c` event and its child `git log -n 1` event.
- `python3 -m py_compile workflow/prepare_fixture.py workflow/run_workflow.py tools/report.py`: **PASS**.
- `bash -n run_experiment.sh`: **PASS**.
- Userspace and BPF C sources passed host-compiler syntax-only checks with temporary API/helper stubs: **PASS**. These checks catch ordinary C syntax errors only; they do not validate real libbpf ABI declarations, BPF instruction generation, verifier acceptance, or attachment.

## Checks blocked by the environment

- `make`: **BLOCKED** because `/usr/include/bpf/bpf_helpers.h` is absent (the libbpf development package is not installed).
- `clang -print-targets`: no BPF target was listed for the installed Swift-derived Clang.
- Kernel tracefs event directories were not present/mounted in this container, and the container does not expose the capabilities/mounts needed to validate tracepoint attachment.
- Therefore the eBPF object has **not been compiled, loaded, or tested against live kernel events** here.

These results validate the Python workflow and report parser only. They do not validate eBPF source correctness, kernel compatibility, event completeness, or any recorder comparison. The first action on a suitable Linux host should be to install dependencies, build, run the workflow, and inspect raw oracle events before testing any recorder.
