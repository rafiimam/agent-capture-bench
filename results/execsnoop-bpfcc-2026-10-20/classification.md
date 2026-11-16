# Adjudication — execsnoop-bpfcc, 2026-10-20 capture (re-scored 2026-11-16)

Every oracle exec event and every recorder exec event lands in exactly one
bucket below. Buckets: `tier*_matched`, `unmatched_adjudicated (reason)`,
`recorder_only (unexpected_events)`.

## Matched (34/38)

| Tier | Count | What it covers (representative) |
|---|---|---|
| `tier1_exact` | 27 | argv[0] identical both sides (basename + full tuple equal) — identical invocations such as `false` and the PATH-resolved cases as recorded |
| `tier2_token_collapsed` | 5 | basename equal, whitespace-collapsed joined argv equal — absorbs argv[0] resolved-vs-as-invoked (`/usr/bin/echo` vs `echo hello`) and space-joined `sh -c` pipeline strings |
| `tier3_truncation_prefix` | 1 | oracle captured prefix at the 95-byte bound (`args_truncated` set) vs the recorder's full argument list (the 12-arg + 200-byte argv_overflow case) |
| `tier4_shell_tolerant` | 1 | quote/whitespace-insensitive comparison — the `python -c "import subprocess; subprocess.run([...])"` probe, whose rendered quotes execsnoop strips |

## Unmatched, adjudicated (4)

### 3× truncated python `-c` probes — `representation_difference_truncation_suspected`

Oracle events: pids 27150 (execveat probe), 27152 (double-fork daemon
snippet), 27155 (short-lived burst). Recorder processes with the **same PIDs**
are present, argv in both, with embedded newlines rendered as line splits
(e.g. tokens `timenmarker`, `sysnSYS_execveat`), so neither the collapsed nor
the prefix comparison can pair them character-for-character.

- **Classification: representation difference** (oracle truncation at its
  95-byte bound + recorder's newline-mangled rendering of multi-line
  `-c` strings). Not a capture failure; the process executions are observed
  and verifiable on both sides.

### 1× `git log -n 1` via `execveat` (oracle pid 27151, ppid 27150) — `representation_difference_unresolved`

The recorder's stream contains the two sibling `git log -n 1` executions
(27147, 27149) but **no event for pid 27151 at all**. Root by mechanism, not
inference: `execsnoop-bpfcc` on Ubuntu 24.04 aarch64 (bpfcc-tools
0.29.1+ds-1ubuntu7) attaches a kprobe and kretprobe to
`get_syscall_fnname("execve")` — the `sys_execve` wrapper — and attaches to
**no `execveat` probe** (verified by inspecting `/usr/sbin/execsnoop-bpfcc`
on the run host: lines `execve_fnname = b.get_syscall_fnname("execve")`,
`attach_kprobe`/`attach_kretprobe`, nothing else).

- **Classification: scope limitation of this build/configuration** — the
  execveat path is outside execsnoop-bpfcc's observation point. Not a
  buffering loss; not a failure within its mechanism. This is a coverage
  boundary a user should know when relying on execsnoop for execveat-heavy
  workloads (this includes `posix_spawn`-with-execveat tooling and any raw
  `SYS_execveat` call). The same boundary reproduced identically on
  2026-11-16 (pid 86476; see `../execsnoop-bpfcc-2026-11-16/`).
- The check `execveat_git_child_seen` still passes on the oracle side
  (`execveat_git` = pid 27151 observed by the oracle).

## Recorder-only events (217)

System background on the host VM (fixture setup, harness shells, tooling)
outside the oracle's tracked process tree. Expected by design; counted in
`unexpected_events`; no defect implied on either side. Notable reduction from
the original 224: the 7 normalized matches absorbed recorder events the
strict matcher could not pair.

## Redaction probes

Scenario `redaction-probes-v1` did not exist on 2026-10-20. Nothing in this
capture is tagged as a redaction probe; no marker-like strings appear.
