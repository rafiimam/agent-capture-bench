---
name: Validation report
about: Report results from running the oracle on a Linux host with eBPF support
title: "Validation: [distribution] [kernel version]"
labels: validation
assignees: ""
---

**Environment**
- Distribution and version:
- Kernel version (`uname -r`):
- Architecture (`uname -m`):
- Clang version (`clang --version`):
- libbpf version (`dpkg -l libbpf-dev` or equivalent):
- GCC version (`gcc --version`):
- Python version (`python3 --version`):
- Git version (`git --version`):
- How privileges were obtained (sudo, CAP_BPF+CAP_PERFMON, etc.):
- Container or VM? If so, which runtime and relevant settings:

**Build result**
Did `make` succeed? If not, paste the error.

**Oracle attachment**
Did the eBPF programs load and attach? Paste any errors from `agentcap-oracle`.

**Workflow execution**
Did `run_experiment.sh` complete? What was the exit status?

**Oracle observations**
Attach the raw `oracle-events.jsonl` file or paste its contents.

Key checks:
- [ ] `path_echo` exec event observed
- [ ] `absolute_echo` exec event observed
- [ ] `shell_pipeline` shell + echo + wc events observed
- [ ] `nonzero_exit` (false) exec event observed
- [ ] `python_spawns_git` — Python exec event observed
- [ ] `python_spawns_git` — child git exec event observed
- [ ] git event's ppid matches Python event's pid

**Report output**
Attach or paste `oracle-report.json`. Does `all_oracle_checks_observed` equal `true`?

**Notes**
Anything unexpected, surprising, or worth investigating further.
