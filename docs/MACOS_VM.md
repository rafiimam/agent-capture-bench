# Running on macOS (Apple Silicon) with Multipass

macOS cannot load Linux eBPF programs, and Docker Desktop's shared Linux VM
does not give you a kernel you control. The reliable path on an Apple Silicon
Mac is a real Ubuntu VM with its own kernel. [Multipass](https://multipass.run)
(Canonical) does this in one command and runs ARM64 Ubuntu natively on M-series
chips — no emulation, and this project's Makefile already handles `aarch64`.

A 2-CPU / 4 GB / 20 GB VM is plenty. Everything below takes ~10 minutes.

## 1. Install and launch

```bash
brew install multipass        # or download the installer from multipass.run
multipass launch 24.04 --name acb --cpus 2 --memory 4G --disk 20G
multipass shell acb
```

## 2. Inside the VM: dependencies and code

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev make gcc git python3
# Only needed for the recorder adapters:
sudo apt install -y bpfcc-tools auditd

git clone https://github.com/rafiimam/agent-capture-bench.git
cd agent-capture-bench
make check        # Python tests; no eBPF needed for this step
```

## 3. First oracle run (the validation milestone)

```bash
make
./run_experiment.sh
```

Artifacts land in `.work/run-<timestamp>-<pid>/`. Then check the oracle
against the workflow:

```bash
cat .work/run-*/oracle-report.json | python3 -m json.tool | grep -A13 observed_checks
```

**Validation succeeds when every `observed_checks` entry is `true`** — that
means the oracle really attached, really loaded, and saw all six core cases,
including the Python-launched `git`. If some are `false`, the run is
*undetermined* by this project's rules: debug the oracle (permissions,
tracefs, verifier log) before drawing any conclusion.

Record the environment for VALIDATION.md:

```bash
uname -a; lsb_release -a; clang --version | head -1; dpkg -l libbpf-dev | tail -1
ls /sys/kernel/tracing/events/sched/ | head
```

## 4. Evasion suite

```bash
ACB_SUITE=all ./run_experiment.sh
```

This runs the core six cases plus the `capture-evasion-v1` family
(shell `-c` indirection, `execveat`, double-fork daemon, short-lived burst,
argv overflow, direct script exec). Check the `evasion_checks` section of the
new `oracle-report.json` the same way.

## 5. Score a recorder (adapters)

In one VM terminal, start the recorder; in another, run the experiment; then
convert and compare — full commands are in
[adapters/README.md](../adapters/README.md). Shortest path (execsnoop):

```bash
# Terminal 1
sudo execsnoop-bpfcc | tee /tmp/execsnoop.txt   # Ctrl-C after the run

# Terminal 2
ACB_SUITE=all ./run_experiment.sh
RUN=$(ls -d .work/run-* | tail -1)
python3 adapters/execsnoop.py --input /tmp/execsnoop.txt --output "$RUN/recorder-output.jsonl"
python3 tools/report.py --oracle "$RUN/oracle-events.jsonl" \
  --supervisor "$RUN/supervisor-events.jsonl" \
  --recorder "$RUN/recorder-output.jsonl" --output "$RUN/report.json"
```

The `recorder_comparison` section reports matched / missed / unexpected
events. Missed events are candidates for capture failures — classified per
the README's discipline, never by this table alone.

## 6. Get results out and clean up

```bash
# On the Mac:
multipass transfer acb:/home/ubuntu/agent-capture-bench/.work ./acb-results
multipass stop acb && multipass delete acb && multipass purge   # when done
```

## Troubleshooting

- **`make` fails on `bpf_helpers.h`** → `libbpf-dev` is not installed (step 2).
- **Oracle exits immediately / permission errors** → you must run through
  `./run_experiment.sh` (it uses `sudo` for the loader); check
  `ls /sys/kernel/tracing/events/syscalls/` lists `sys_enter_execve`.
- **Verifier rejection when loading** → capture the loader's stderr and open
  an issue with `uname -a`, `clang --version`, and the exact log; verifier
  failures are kernel-version-specific and are exactly what validation
  reports exist to record.
- **Multipass VM feels slow** → it shouldn't on Apple Silicon; make sure you
  launched the ARM64 image (default) and not an emulated one.
