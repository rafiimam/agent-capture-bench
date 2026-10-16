---
name: Bug report
about: Report incorrect behavior in the oracle, workflow, or report generator
title: ""
labels: bug
assignees: ""
---

**Component**
Which part of the project is affected?
- [ ] eBPF oracle (`src/oracle.bpf.c`, `src/oracle.c`)
- [ ] Workflow (`workflow/run_workflow.py`, `workflow/prepare_fixture.py`)
- [ ] Report generator (`tools/report.py`)
- [ ] Build system (`Makefile`)
- [ ] Documentation

**Environment**
- Kernel version (`uname -r`):
- Distribution and version:
- Clang version (`clang --version`):
- libbpf version:
- Python version (`python3 --version`):
- How was the oracle invoked? (sudo, capabilities, container, etc.):

**Observed behavior**
What happened?

**Expected behavior**
What should have happened? If the expected behavior is based on a documented guarantee, quote the relevant section.

**Raw artifacts (if available)**
Attach or paste the relevant sections of:
- `oracle-events.jsonl`
- `supervisor-events.jsonl`
- `oracle-report.json`
- Build or runtime error output

**Classification**
How would you classify this under the project's framework?
- [ ] Oracle problem (the independent observer itself is incorrect)
- [ ] Workflow problem (the test scenario did not execute as designed)
- [ ] Report problem (the comparison/report logic is wrong)
- [ ] Undetermined (insufficient evidence to classify)
