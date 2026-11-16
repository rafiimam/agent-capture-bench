# Adjudication — execsnoop-bpfcc, 2026-11-16 fresh run

Buckets: `tier*_matched`, `unmatched_adjudicated (reason)`, `recorder_only (unexpected_events)`.

## Matched (37/41)

| Tier | Count | Notes |
|---|---|---|
| `tier1_exact` | 29 | argv[0] identical both sides |
| `tier2_token_collapsed` | 5 | basename + whitespace-collapsed joined argv — argv[0] resolved-vs-as-invoked and `sh -c` fragmentation |
| `tier3_truncation_prefix` | 2 | oracle captured prefix at 95-byte bound: the 12-arg/200-byte overflow case **and** the redaction overflow probe (secret sits beyond the bound) |
| `tier4_shell_tolerant` | 1 | quote/whitespace-insensitive — the `python -c` probe |

## Unmatched, adjudicated (4)

### 3× truncated python `-c` probes — `representation_difference_truncation_suspected`

PIDs 86475 (execveat probe), 86477 (double-fork daemon snippet), 86480
(short-lived burst) — all present in the recorder stream with
newline-mangled rendering (e.g. tokens `sysnSYS_execveat`, `timenmarker`),
so collapsed/prefix comparison cannot pair them character-for-character but
same-PID and case evidence is unambiguous.

- **Classification: representation difference** (oracle 95-byte truncation +
  recorder's newline-mangled `-c` rendering). Not a capture failure.

### 1× `git log -n 1` via `execveat` (oracle pid 86476, ppid 86475) — `representation_difference_unresolved`

Recorder contains the sibling git execs (86472, 86474) and the `sh -c`
parent (86473), but **no event for pid 86476**. Mechanism-confirmed, same as
2026-10-20: `execsnoop-bpfcc` (Ubuntu bpfcc-tools 0.29.1+ds-1ubuntu7,
aarch64) attaches kprobe/kretprobe to `sys_execve` only — no `execveat`
attachment in the script.

- **Classification: scope limitation of this build/configuration** — the
  execveat path is invisible to this build/configuration of execsnoop-bpfcc
  on Ubuntu 24.04. Not a failure within its mechanism; a coverage boundary.
- Identical finding on 2026-10-20 (pid 27151; see
  `../execsnoop-bpfcc-2026-10-20/classification.md`).

## Recorder-only events (61)

Host VM background outside the oracle's tracked process tree — expected;
not defects. (Lower count than the 2026-10-20 run's 217: this VM was otherwise
idle.)

## Redaction probes (validated on the host)

| Check | Result |
|---|---|
| `secret_in_argv_seen` | oracle observed the synthetic-marker argv ✓ |
| `secret_argv_overflow_truncation_flagged` | oracle set `args_truncated` and kept only the marker prefix ✓ |
| `secret_in_env_step_passed` | supervisor step passed ✓ |

Recorder behavior: the two marker-bearing echo executions appear **verbatim**
in the recorder stream (`marker_present_in_recorder`,
`recorder_events_containing_marker: 2`) — execsnoop-bpfcc does not redact.
This is reported as observed behavior, not adjudicated a defect (redaction is
not part of execsnoop's guarantee). The `secret_in_env` case shows nothing
in argv, as designed (the oracle does not capture environment; env-capturing
recorders are the intended target of that probe).
