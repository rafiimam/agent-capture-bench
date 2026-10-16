# Initial Issues

These issues track the work needed to reach each milestone. Create them on GitHub after the repository is public.

---

## Issue 1: Validate the Linux eBPF oracle on a supported kernel

**Labels:** `validation`, `good first issue`

**Description:**

The eBPF oracle has been written but never compiled or loaded on a host with eBPF support. The first priority is to build and run it on a suitable Linux host and report whether the observed kernel events match the expected workflow.

**Acceptance criteria:**

- [ ] `make` completes successfully
- [ ] `./run_experiment.sh` runs to completion
- [ ] `oracle-events.jsonl` contains exec events for all six workflow cases
- [ ] `oracle-report.json` shows `all_oracle_checks_observed: true`
- [ ] The git child process's `ppid` matches the Python probe's `pid`
- [ ] Raw JSONL files, kernel version, distribution, compiler/libbpf versions, and capabilities are published

**Environment guidance:**

A minimal Ubuntu 22.04+ VM or bare-metal host with `sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev make gcc git python3` should be sufficient. Containers may require `--privileged` or explicit capability grants for eBPF.

Use the **Validation report** issue template to report results.

---

## Issue 2: Reproduce the Python-launched subprocess scenario independently

**Labels:** `validation`

**Description:**

After Issue 1 is resolved, a second person should reproduce the result on a different Linux distribution or kernel version. This confirms the oracle is not specific to one configuration.

**Acceptance criteria:**

- [ ] Reproduced on a different distribution OR kernel version than Issue 1
- [ ] Results match: `all_oracle_checks_observed: true`
- [ ] Any differences from Issue 1's results are documented

---

## Issue 3: Test argv truncation and args_truncated flag

**Labels:** `testing`

**Description:**

The oracle captures at most 8 argv elements of 95 bytes each. The current workflow cases are well within these limits. Add a test case that deliberately exceeds them:

1. A command with more than 8 arguments.
2. A command with an argument longer than 95 bytes.

Confirm that:
- `args_truncated` is `true` in both cases
- The oracle does not crash, drop events, or silently truncate without setting the flag
- The report generator preserves the truncation uncertainty

**Suggested implementation:**

Add two new cases to `run_workflow.py` and corresponding expectations in `scenario.yaml`. For example:

```python
# Many arguments
run_case(handle, case_id="many_args", argv=["echo"] + [f"arg{i}" for i in range(12)])

# Long argument
run_case(handle, case_id="long_arg", argv=["echo", "x" * 120])
```

---

## Issue 4: Review ppid:0 handling in report and oracle

**Labels:** `testing`

**Description:**

`ppid: 0` means "unknown parent" in the oracle's schema, not "the parent is PID 0." The report generator should not misinterpret this. Verify that:

1. When a fork event establishes parentage, the subsequent exec event has the correct `ppid`.
2. When no fork event is observed (e.g., for the root target process), `ppid` is 0 and the report does not claim it has no parent.
3. Add a test case with a deep process tree (parent → child → grandchild) to confirm ancestry propagation.

---

## Issue 5: Add a second recorder adapter

**Labels:** `adapter`, `milestone-3`

**Description:**

Implement an adapter that maps a recorder's native output to the canonical `exec-jsonl-v1` schema. The adapter must:

- Map `filename`, `argv`, `pid`, `ppid` to the canonical schema
- Preserve `null` for fields the recorder does not provide
- Document which of the recorder's guarantees are being tested
- Not fabricate fields

**Prerequisites:**
- Issue 1 is resolved (oracle validated)
- The recorder's documented guarantees have been reviewed and quoted in the issue
- Use the **Recorder adapter proposal** issue template

---

## Issue 6: Resolve hardcoded BPF object path

**Labels:** `build`, `enhancement`

**Description:**

`oracle.c` opens the BPF object file with a relative path:

```c
struct bpf_object *obj = bpf_object__open_file("build/oracle.bpf.o", NULL);
```

This only works when the binary is invoked from the repository root. Options:

1. **BPF skeleton embedding** via `bpftool gen skeleton` (the libbpf-bootstrap pattern). This compiles the BPF object into the userspace binary.
2. **Resolve relative to the binary** using `/proc/self/exe`.
3. **Accept the path as a CLI argument** (simplest, least ergonomic).

Option 1 is the standard approach but adds a build dependency on `bpftool`.
