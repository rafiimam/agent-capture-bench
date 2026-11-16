# execsnoop-bpfcc — 2026-11-16 fresh end-to-end run

| Item | Value |
|---|---|
| Outcome | `all_oracle_checks_observed: true` (core 10/10, evasion 9/9, **redaction 3/3** — new family, first host validation) |
| Suite(s) | `all` (`python-subprocess-capture-v1` + `capture-evasion-v1` + `redaction-probes-v1`) |
| Host | Multipass VM on Apple Silicon (macOS host) — Ubuntu 24.04.5 LTS, aarch64 |
| Kernel | 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC aarch64 (Ubuntu 24.04.5) |
| clang / libbpf | Ubuntu clang 18.1.3 (1ubuntu1) / libbpf-dev 1:1.3.0-2build2 |
| bpfcc-tools | 0.29.1+ds-1ubuntu7 (source of `execsnoop-bpfcc`) |
| Recorder invocation | `sudo execsnoop-bpfcc` system-wide during the run, tee'd to a capture file |
| ACB commit | `6c6b058` (`git pull --ff-only` on the VM before the run; includes the normalized matcher and redaction family) |
| Steps | supervisor 14/14 |
| Redaction analysis | oracle observed marker (1 full + 1 truncation-prefix event); **recorder recorded the marker verbatim (2 events) — execsnoop-bpfcc does not redact**; classification hint `marker_present_in_recorder` |

```
oracle 41 exec / 41 fork · recorder 98 exec records (18 lines skipped of 116)
strict 29 · normalized 37 · unmatched 4 (see classification.md) · unexpected 61
tier1_exact=29 tier2_token_collapsed=5 tier3_truncation_prefix=2 tier4_shell_tolerant=1
```

## Environment & reproduction

```bash
make                      # builds build/agentcap-oracle (this run rebuilt it)
ACB_SUITE=all ./run_experiment.sh
python3 adapters/execsnoop.py --input /tmp/execsnoop-2026-11-16.txt --output <run>/recorder-output.jsonl
python3 tools/report.py --oracle <run>/oracle-events.jsonl --supervisor <run>/supervisor-events.jsonl \
  --recorder <run>/recorder-output.jsonl --output <run>/report.json
```

Re-derivation from this directory's files reproduces
`match_tier_counts`, `matched_event_count`, `strict_matched_event_count` and
the 4 unmatched events exactly (verified 2026-11-16).

## Sanitization

`/home/ubuntu/agent-capture-bench` replaced verbatim with `<acb-repo>` in all
JSONL/JSON artifacts; no other content altered (JSON re-parse verified, zero
hostnames/IPs/usernames; the two token-like strings are the synthetic
`FAKE-ACB-sk-…` redaction marker, which is greppable by design). VM-internal
PIDs and run-directory timestamps retained.

## Relationship to the 2026-10-20 entry

Same four unmatched events in the same two classes (3× truncated python
`-c` with same-PID recorder evidence; 1× execveat-spawned `git`, absent —
mechanism-confirmed). The redaction family was run and validated 3/3 on a
real host. Cross-run consistency is the reason this is published as a pair;
see `../execsnoop-bpfcc-2026-10-20/` for the re-scored 2026-10-20 capture.
