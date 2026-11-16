# Proposed scenario families (design — not yet implemented)

These three families extend AgentCaptureBench beyond "did the recorder see the
exec?" into the questions that decide whether a capture pipeline can be
*trusted* after something goes wrong. They are design specifications, not
claims: **nothing here has been implemented or validated on a host.** Each is
scoped so a contributor can pick one up and build it like the existing suites
(workflow case + scenario YAML + supervisor checks + report checks + tests).

The classification discipline still applies: surprising observations are
*undetermined* until the oracle, workflow, permission, and buffering layers are
ruled out. A design goal here is never "gotcha the recorder."

## Family 1 — Session interruption (recorder liveness under agent death)

**Question:** When the agent (or the process under observation) is killed
mid-run — SIGKILL, SIGTERM, or a hard crash — does the recorder's output
survive, and can gaps be distinguished from a quiet system?

**Why it matters:** Agent executions get interrupted (user Ctrl-C, OOM,
timeout). A recorder that only flushes its buffer on clean shutdown silently
loses exactly the events that matter for post-incident analysis.

**Protocol sketch:**
1. Workflow spawns a burst of short-lived children, then is SIGKILLed by the
   harness at a fixed point (after N children) — the supervisor writes the
   kill marker before dying.
2. Oracle (kernel tracepoints) is unaffected by the agent's death and sees
   all N+ children — it is the baseline for "what actually executed."
3. The recorder's flushed output (file/socket captured up to the kill) is
   compared against the oracle's. The expected finding for many recorders is
   a tail loss; the benchmark measures *how much* and *whether it is
   accounted for* (dropped-event counters, gap markers).

**Oracle/supervisor needs:** none beyond what exists — the supervisor must
record its own death (case `self_kill` writes `step_start` but no
`step_result`; the oracle records exits). Report gains a
`interruption_checks` block: `self_kill_step_started`,
`oracle_saw_children_after_kill`, `recorder_tail_accounted_or_unaccounted`.

**Classification guidance:** tail loss + recorder self-reported drop counters
→ *conformant with documented limits*; tail loss + no accounting → *capture
failure* (events inside stated guarantee gone without a trace); inability to
distinguish → *undetermined*.

**Status:** not implemented. Blocker: none — doable with existing harness.

## Family 2 — Tamper detection and output integrity

**Question:** Can the recorder's output be modified after the fact without
detection — and are gaps in that output indistinguishable from silence?

**Why it matters:** Hash-chained / signed logs establish integrity of the
recorded bytes, not completeness of capture (see the classification
discipline). This family tests both claims separately:
- **Integrity:** mutate/delete/truncate recorder output files between
  experiment end and analysis; does any downstream verification (hash chain,
  signature, sequence numbers) flag it?
- **Completeness accounting:** a recorder with per-record sequence numbers
  makes gaps detectable; one without them cannot.

**Protocol sketch:**
1. Run an existing suite with the recorder enabled.
2. Post-run, the harness makes controlled edits to the captured recorder
   stream (delete 10% of lines, flip bytes in one record, truncate the file).
3. A neutral `verify_recorder_integrity` tool (new, `tools/`) applies the
   recorder's own documented integrity mechanism (if any) and reports
   pass/fail/absent.

**Oracle/supervisor needs:** none. The analysis consumes recorder output +
documented integrity spec (pinned per recorder in its adapter docstring).

**Classification guidance:** undetected byte-flip → integrity claim false for
this configuration; detected edit + verified gap accounting → conformant to
its own guarantee; unverifiable → *undetermined*, never "tamper-proof."

**Status:** not implemented. Depends on per-recorder integrity mechanisms;
needs a spec subsection per adapter.

## Family 3 — Container/namespace attribution

**Question:** Does a recorder attribute execs inside a container/namespace to
the in-container identity, and does the comparison stay meaningful when the
oracle (host kernel tracepoints) sees the same execs?

**Why it matters:** AI agents run in sandboxes. A recorder keyed to host
PIDs misattributes in-container execs; an overlay/rootfs image changes
`filename` resolution. The oracle sees raw host PIDs; the benchmark checks
whether the recorder preserves usable ancestry across the namespace boundary.

**Protocol sketch:**
1. Workflow runs a sub-scenario inside a minimal container (`docker run --rm
   agentcapturebench-fixture` or `unshare -mpf --mount-proc`), executing the
   python_spawns_git case.
2. Oracle captures host-side execs + fork relations crossing the boundary.
3. Recorder-under-test captures whatever its design allows; the adapter
   preserves namespace fields (`mnt_ns`, container id) when present.
4. Comparison uses basename + argv (already namespace-agnostic) and records
   pid-namespace agreement/disagreement separately.

**Oracle/supervisor needs:** supervisor writes `container=<runtime>` into
metadata for the in-container cases; oracle unchanged. Report gains
`namespace_checks` keyed off metadata.

**Classification guidance:** missing ns fields ≠ missing execs — classify by
the recorder's documented namespace support; PID disagreement across the
boundary is *expected* and must not be scored as capture failure.

**Status:** not implemented. Blocker: needs container runtime in the harness;
best validated in CI-like Linux runners, not on developer laptops.
