# Contributing to AgentCaptureBench

Thank you for your interest. This project aims to build an independently reproducible method for evaluating whether AI-agent execution recorders capture the processes that actually executed. Contributions that improve the methodology, extend the evidence, or correct mistakes are welcome.

## How to contribute

### Validate the oracle on your Linux host

The single most valuable contribution right now is running the experiment on a Linux host with eBPF support and reporting the results. Use the **Validation report** issue template and include:

- Your exact kernel version, distribution, and compiler/libbpf versions.
- Whether the eBPF programs loaded and attached successfully.
- The raw `oracle-events.jsonl` and `oracle-report.json` files.
- Any unexpected behavior or missing events.

### Report a bug

Use the **Bug report** issue template. Include the raw artifact files when possible. Classify the problem using the project's four-way framework:

- **Oracle problem**: the independent observer itself is incorrect.
- **Workflow problem**: the test scenario did not execute as designed.
- **Report problem**: the comparison or report logic is wrong.
- **Undetermined**: insufficient evidence to distinguish the cause.

### Propose a recorder adapter

Use the **Recorder adapter proposal** issue template. Before writing code, identify:

1. What the recorder's documentation explicitly claims to capture.
2. What is explicitly outside its documented scope.
3. How the recorder's native output maps to the canonical `exec-jsonl-v1` schema.
4. Which fields cannot be mapped and must be preserved as absent or null.

An adapter must not fabricate fields the recorder does not provide. A recorder that does not claim OS-level process capture is not defective for missing it — that is a **scope limitation**, not a **capture failure**.

### Improve the code

Pull requests are welcome for:

- Build system improvements (e.g., BPF skeleton embedding, cross-distribution compatibility).
- Additional workflow test cases (with clear expected-event declarations).
- Report generator improvements (e.g., timestamp-proximity matching, deeper ancestry validation).
- Documentation corrections and clarifications.

## Development setup

### Python components (works on any OS)

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile workflow/prepare_fixture.py workflow/run_workflow.py tools/report.py
```

Or use `make check`, which runs both.

### eBPF oracle (requires Linux)

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev make gcc git python3

# Build
make

# Run the experiment
./run_experiment.sh
```

See the README for detailed requirements and manual execution instructions.

## Code style

- **C**: follow the existing kernel-adjacent style (tabs for indentation, `snake_case`, `/* C89 comments */`).
- **Python**: standard library only, no external dependencies. Type annotations where practical. Run `python3 -m py_compile` on all Python files.
- **Shell**: `set -euo pipefail`, `shellcheck`-clean where possible.

## Classification discipline

This project's credibility depends on honest classification. When reviewing or writing code:

- **Do not assume a recorder failure exists before you observe one.** A missing oracle event could be an oracle problem, a permission problem, a configuration problem, or a buffering problem.
- **Do not rank recorders with a single composite score.** Report capture coverage, field accuracy, event ordering, redaction, integrity, and overhead separately.
- **Pin exact versions.** Every comparison must specify the recorder version, kernel version, distribution, configuration, and documented claims.
- **Preserve uncertainty.** If an argument is truncated, say so. If a parent PID is unknown, emit `ppid: 0`, not a guess. If a result is ambiguous, classify it as **Undetermined**.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
