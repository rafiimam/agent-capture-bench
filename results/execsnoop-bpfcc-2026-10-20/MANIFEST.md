# execsnoop-bpfcc — 2026-10-20 capture, re-scored 2026-11-16

Two dates matter here and are kept separate on purpose:

- **Run date (ground truth collection): 2026-10-20**, commit `fdfffd9` (first
  evasion-suite + recorder pipeline validation).
- **Analysis date (matcher re-score): 2026-11-16**, `tools/report.py` from
  `main` @ `a55f7e5` with matcher `normalized-match-v1`. The raw artifacts in
  this directory are verbatim from 2026-10-20 except the path-sanitization
  step below.

## What this entry is

The 2026-10-20 run's published classification used exact-argv matching and
reported 27 exact matches, 11 "representation differences", zero genuine
capture misses. This entry re-runs the comparison with the normalized
matcher, adds per-event adjudication for the 4 events that remain unmatched,
and documents the execveat finding (see `classification.md`). It supersedes
the 2026-10-20 footnote in the README table and VALIDATION.md.

| Item | Value |
|---|---|
| Outcome | `all_oracle_checks_observed: true` (core 10/10, evasion 9/9) |
| Suite(s) | `all` (scenarios `python-subprocess-capture-v1` + `capture-evasion-v1`) |
| Host | Multipass VM on Apple Silicon (macOS host) — Ubuntu 24.04.5 LTS, aarch64 |
| Kernel | 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC aarch64 (Ubuntu 24.04.5) |
| clang / libbpf | Ubuntu clang 18.1.3 (1ubuntu1) / libbpf-dev 1:1.3.0-2build2 |
| bpfcc-tools | 0.29.1+ds-1ubuntu7 (source of `execsnoop-bpfcc`) |
| Recorder invocation | `sudo execsnoop-bpfcc` system-wide during the run, tee'd to a capture file |
| ACB run commit | `fdfffd9` (oracle sources unchanged through `main` @ `6c6b058` for this build) |
| Adapter | `adapters/execsnoop.py` invoked 2026-10-20, Ubuntu bpfcc layout (PCOMM header accepted) |
| Events | oracle 38 exec / 38 fork; recorder 251; strict 27; normalized **34**; unexpected 217 |
| Steps | supervisor 11/11 |
| Known limitations | See `classification.md` — execveat visibility of this build; representation noise in truncated python `-c` captures |

## Environment & reproduction

Exact re-derivation (requires this directory's files only):

```bash
python3 tools/report.py \
  --oracle oracle-events.jsonl \
  --supervisor supervisor-events.jsonl \
  --recorder recorder-output.jsonl \
  --output /tmp/report-rescore.json
# match_tier_counts must equal {"tier1_exact": 27,
#   "tier2_token_collapsed": 5, "tier3_truncation_prefix": 1, "tier4_shell_tolerant": 1}
```

The fixture repo (`.work/run-20261020T163015-27119/fixture`) is not included;
the supervisor's `git log -n 1` steps ran inside the fixture at run time.

## Sanitization

`/home/ubuntu/agent-capture-bench` was replaced verbatim with `<acb-repo>` in
all JSONL/JSON artifacts (the Multipass default account path; no other
content altered — verified byte-level JSON parse afterwards and full
re-derivation as shown above). VM-internal PIDs and run-directory timestamps
are retained for correlation with VALIDATION.md. No hostnames, IPs, or real
credentials appear; the only token-like strings are the synthetic redaction
markers, which this run does not contain (that scenario landed 2026-11-16).
`report-exact-match-original.json` is the 2026-10-20 report as published,
including its original exact-match classification, kept for provenance.
