#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PYTHON="$(command -v python3)"
WORK="${ROOT}/.work/run-$(date -u +%Y%m%dT%H%M%S)-$$"
mkdir -p "$WORK"

make -C "$ROOT"
"$PYTHON" "$ROOT/workflow/prepare_fixture.py" --dir "$WORK/fixture"

# Running the observer with sudo is expected on many Linux hosts. The C loader
# drops the target child back to SUDO_UID/SUDO_GID before executing the workflow.
set +e
sudo "$ROOT/build/agentcap-oracle" \
  --output "$WORK/oracle-events.jsonl" -- \
  "$PYTHON" "$ROOT/workflow/run_workflow.py" \
  --suite "${ACB_SUITE:-core}" \
  --fixture-dir "$WORK/fixture" \
  --events "$WORK/supervisor-events.jsonl"
TARGET_STATUS=$?
set -e

if [[ -f "$WORK/oracle-events.jsonl" && -f "$WORK/supervisor-events.jsonl" ]]; then
  "$PYTHON" "$ROOT/tools/report.py" \
  --oracle "$WORK/oracle-events.jsonl" \
  --supervisor "$WORK/supervisor-events.jsonl" \
  --output "$WORK/oracle-report.json"
else
  echo "warning: missing oracle or supervisor output; classify this run as undetermined" >&2
fi

printf '\nArtifacts written under %s\n' "$WORK"
exit "$TARGET_STATUS"
