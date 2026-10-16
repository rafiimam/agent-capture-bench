---
name: Recorder adapter proposal
about: Propose or discuss adding an adapter for a specific recorder
title: "Adapter: [recorder name]"
labels: adapter
assignees: ""
---

**Recorder**
- Name and version:
- Repository or documentation URL:
- License:

**Documented capture guarantees**
What does this recorder's documentation explicitly claim to capture? Quote the relevant sections. This is the basis for the Conformant/Capture failure/Scope limitation classification.

**What it does NOT claim**
What is explicitly outside its documented scope? This determines what qualifies as a Scope limitation vs. a Capture failure.

**Expected output format**
What is the recorder's native output format? (e.g., JSONL, structured log, database, etc.)

**Adapter design**
How would you map the recorder's native output to the canonical `exec-jsonl-v1` schema?
- `type` → ?
- `filename` → ?
- `argv` → ?
- `pid` → ?
- `ppid` → ?

**Fields that cannot be mapped**
Which canonical fields have no equivalent in the recorder's output? These should be preserved as `null` or absent, not silently dropped.

**Prerequisites**
- [ ] The oracle has been validated on at least one Linux host (Milestone 2)
- [ ] The recorder's documented guarantees have been reviewed
- [ ] The adapter preserves uncertainty (does not fabricate missing fields)
