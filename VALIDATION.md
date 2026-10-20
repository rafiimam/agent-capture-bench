# Validation log

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
attributes the Python-launched `git` child. It does not yet validate the
evasion suite (`capture-evasion-v1`) or any recorder comparison — those runs
are recorded here as they happen.

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
