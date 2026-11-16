# Changelog

All notable changes to AgentCaptureBench. See VALIDATION.md for the
host-validation log (only entries there represent runs on real kernels).

## [0.1.0] — 2026-11-16 — unreleased

### Added
- **`normalized-match-v1` matcher** in `tools/report.py`: tiered matching
  (tier1 exact basename+argv, tier2 whitespace-collapsed joined argv,
  tier3 truncation prefix — only with `args_truncated`, tier4
  quote/whitespace-tolerant). Match tiers are reported, `strict_matched_event_count`
  and `match_tier_counts` are included, and every unmatched oracle event
  carries a machine-readable reason (`representation_difference_unresolved`,
  `representation_difference_truncation_suspected`, `no_recorder_evidence`).
  Unmatched events are never auto-declared capture failures.
- **`--bpf-object PATH`** on `agentcap-oracle`; the object is also resolved
  relative to `/proc/self/exe` (alongside the binary, or `../build/`), then
  falls back to the legacy cwd-relative `build/oracle.bpf.o`.
- **Adapters:** Tetragon, Falco, osquery, Sysdig — all implemented with
  parser tests and marked **UNVALIDATED**; none may be used for a published
  comparison until confirmed against a real capture on a live host. DEPOSE and
  Tracekit adapters intentionally absent (native output format unverified —
  do not guess formats).
- **`redaction-probes-v1` scenario family** (`workflow/scenario-redaction.yaml`,
  suite `redaction`): synthetic-secret probes for argv, argv beyond the
  95-byte capture bound (truncation interplay), and env. `tools/report.py`
  gains `redaction_checks` and a best-effort `redaction_analysis` (presence
  reported, absence adjudicated as *undetermined*, never a failure).
- **`docs/SCENARIO_FAMILIES.md`** — design specs for session interruption,
  tamper/integrity, and namespace attribution (not implemented).
- **`results/`** — registry and submission protocol for published,
  re-derivable comparisons (nothing published yet).
- **CI:** `bpf-build` job (Ubuntu clang BPF compile of `oracle.bpf.o` +
  userspace loader) alongside the Python job.
- `CITATION.cff`, this changelog.

### Changed
- `recorder_comparison` in report JSON: `matched_event_count` now reflects
  the normalized matcher; `match_tier_counts`/`unmatched_oracle_events` are
  new; `missed_events` keeps its shape (filename_basename + argv) but is
  defined over the normalized unmatched set; `unexpected_events` now lists
  actual recorder orphans rather than a strict multiset difference.
- Shell (`run_experiment.sh`) unchanged; `ACB_SUITE=redaction|all` selects
  the redaction family.

### Not yet done
- Linux host validation of the new matcher (it is expected to retire the
  11-event "representation difference" caveat from the execsnoop comparison —
  this must be demonstrated, not assumed).
- End-to-end runs of the auditd and new adapters; cross-distro/kernel matrix.
- Session-interruption, tamper/integrity, and namespace scenario families
  (design in docs/SCENARIO_FAMILIES.md).
- Published entries in `results/`.
