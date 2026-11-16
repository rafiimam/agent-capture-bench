# Published results registry

This directory is where validated benchmark runs are published, so the
community can inspect exactly what was measured — the MLPerf-style model: a
result only counts if the artifacts are reproducible and inspectable.

Two entries live here: **[execsnoop-bpfcc-2026-10-20/](execsnoop-bpfcc-2026-10-20/)** (original capture, re-scored with `normalized-match-v1`) and **[execsnoop-bpfcc-2026-11-16/](execsnoop-bpfcc-2026-11-16/)** (fresh end-to-end run validating the matcher and the redaction suite). Both carry raw artifacts, a MANIFEST.md with environment pinning, and per-event adjudication. A third-party re-derivation of either entry on a different kernel/distro is the fastest way to harden them from "author's first-run results" to community-verified.

## What a published result must include

Open a pull request adding `results/<recorder>-<version>-<date>/`:

```
results/<recorder>-<version>-<date>/
├── MANIFEST.md            # see template below
├── oracle-events.jsonl    # raw oracle output (verbatim)
├── supervisor-events.jsonl
├── oracle-report.json     # tools/report.py output
├── recorder-output.jsonl  # sanitized canonical adapter output
└── classification.md      # per-event adjudication notes for non-conformant events
```

Rules:

- **Raw or it didn't happen.** Summaries without the raw JSONL are not
  accepted; the classification discipline depends on being able to re-derive
  every number.
- **Sanitize secrets.** Never commit proprietary data, real credentials, or
  private environment details. The benchmark's redaction suite uses synthetic
  markers; any real secret in a published artifact is a rejection.
- **Pin everything.** MANIFEST.md must list: date (UTC), hostname class
  (VM/bare metal, arch), distro + version, kernel, clang, libbpf, recorder
  exact version + package source, recorder command line and config file,
  ACB commit SHA, suite(s) run, adapter used (with its commit SHA), known
  limitations.
- **Classification, not scores.** `classification.md` adjudicates each
  unmatched event: conformant / scope limitation / undetermined / capture
  failure, with evidence. Unmatched events are never auto-declared failures —
  a reviewer must be able to replay the reasoning.

## MANIFEST.md template

```markdown
# <recorder> <version> on <date>

| Item | Value |
|---|---|
| Outcome | all_oracle_checks_observed: <true|false> |
| Suite(s) | <core|evasion|redaction|all> (scenario IDs) |
| Host | <VM|bare metal>, <arch> |
| Distro | <name + version> |
| Kernel | <uname -a output> |
| clang / libbpf | <versions> |
| ACB commit | <sha> |
| Adapter | <adapters/<name>.py @ <sha> |
| Recorder version | <exact version and package source> |
| Recorder invocation | <full command line, config file paths> |
| Events | oracle <n> exec / <n> fork; recorder <n>; matched <n> (strict <n>) |
| Notes | <anything the next runner needs> |
```

## How review works

1. Open the PR with the artifacts above.
2. The CI workflow runs `make check`; a maintainer re-derives the headline
   numbers from the raw JSONL with `tools/report.py` and spot-checks the
   `classification.md` adjudications.
3. Merged entries are listed in the PR's results table (README) with a link.

Entries in this directory are first-party validated runs (author's host,
Multipass Ubuntu 24.04 aarch64, kernel 6.8.0-147-generic). They are honestly
unvalidated by third parties until someone re-derives them on a different
kernel/distro or independently re-runs the pipeline — that reproduction is
the fastest way to turn these into community-verified results. The Multipass
VM details and exact versions are pinned in each MANIFEST.md.
