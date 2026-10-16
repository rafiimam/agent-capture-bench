# Validation log

Date: 2026-10-16

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
