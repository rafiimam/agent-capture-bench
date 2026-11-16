#!/usr/bin/env bash
# AgentCaptureBench: provision an Ubuntu VM with eBPF support via Multipass.
#
# This script runs on macOS. It creates an Ubuntu 24.04 VM, installs the
# build dependencies, clones the repository, builds the oracle, and runs
# the experiment.
#
# Prerequisites: Multipass must be installed.
#   brew install multipass
#   OR download from https://multipass.run/install
#
# Usage:
#   chmod +x docs/setup_linux_vm.sh
#   ./docs/setup_linux_vm.sh

set -euo pipefail

VM_NAME="acb-oracle"
VM_CPUS=2
VM_MEM="2G"
VM_DISK="10G"
UBUNTU_VERSION="24.04"
REPO_URL="https://github.com/rafiimam/agent-capture-bench.git"

echo "=== AgentCaptureBench Linux VM Setup ==="
echo ""

# --- Check prerequisites ---
if ! command -v multipass &>/dev/null; then
    echo "ERROR: multipass is not installed."
    echo ""
    echo "Install it with one of:"
    echo "  brew install multipass"
    echo "  OR download from https://multipass.run/install"
    echo ""
    echo "After installing, run this script again."
    exit 1
fi

# --- Check if VM already exists ---
if multipass info "$VM_NAME" &>/dev/null; then
    echo "VM '$VM_NAME' already exists."
    echo "To delete and recreate: multipass delete $VM_NAME && multipass purge"
    echo "To connect: multipass shell $VM_NAME"
    exit 0
fi

# --- Create the VM ---
echo "Creating Ubuntu $UBUNTU_VERSION VM: $VM_NAME"
echo "  CPUs: $VM_CPUS, Memory: $VM_MEM, Disk: $VM_DISK"
echo ""
multipass launch "$UBUNTU_VERSION" \
    --name "$VM_NAME" \
    --cpus "$VM_CPUS" \
    --memory "$VM_MEM" \
    --disk "$VM_DISK"

echo ""
echo "VM created. Installing dependencies..."
echo ""

# --- Install build dependencies inside the VM ---
multipass exec "$VM_NAME" -- bash -c '
set -euo pipefail

echo "--- Updating package list ---"
sudo apt-get update -qq

echo "--- Installing eBPF build dependencies ---"
sudo apt-get install -y -qq \
    clang llvm libbpf-dev libelf-dev zlib1g-dev \
    make gcc git python3 \
    linux-tools-common linux-tools-$(uname -r) 2>/dev/null || true

echo ""
echo "--- Verifying environment ---"
echo "Kernel:    $(uname -r)"
echo "Arch:      $(uname -m)"
echo "Clang:     $(clang --version | head -1)"
echo "libbpf:    $(dpkg -l libbpf-dev 2>/dev/null | grep libbpf-dev | awk "{print \$3}" || echo "unknown")"

# Check BPF target support
if clang -print-targets 2>/dev/null | grep -q bpf; then
    echo "BPF target: supported"
else
    echo "WARNING: clang does not list bpf in -print-targets"
    echo "  Trying direct compilation test..."
    echo "int main() { return 0; }" > /tmp/bpf_test.c
    if clang -target bpf -c /tmp/bpf_test.c -o /dev/null 2>/dev/null; then
        echo "BPF target: works (not listed but functional)"
    else
        echo "ERROR: BPF target not supported by this clang"
        exit 1
    fi
    rm -f /tmp/bpf_test.c
fi

# Check kernel eBPF support
if [ -d /sys/kernel/debug/tracing/events/sched ]; then
    echo "Tracepoints: available (tracefs mounted)"
elif sudo mount -t tracefs tracefs /sys/kernel/debug/tracing 2>/dev/null; then
    echo "Tracepoints: available (tracefs mounted by script)"
else
    echo "WARNING: tracefs not available — eBPF tracepoint attachment may fail"
fi

# Check specific tracepoints
for tp in sched/sched_process_exec sched/sched_process_fork sched/sched_process_exit \
          syscalls/sys_enter_execve syscalls/sys_enter_execveat; do
    if [ -d "/sys/kernel/debug/tracing/events/$tp" ] 2>/dev/null; then
        echo "  tracepoint $tp: present"
    else
        echo "  tracepoint $tp: NOT FOUND (may need tracefs or kernel config)"
    fi
done

echo ""
echo "--- Cloning repository ---"
if [ -d ~/agent-capture-bench ]; then
    echo "Repository already exists, pulling latest..."
    cd ~/agent-capture-bench && git pull
else
    git clone '"$REPO_URL"' ~/agent-capture-bench
fi

echo ""
echo "--- Building the oracle ---"
cd ~/agent-capture-bench
make clean 2>/dev/null || true
make

echo ""
echo "====================================="
echo "BUILD SUCCESSFUL"
echo "====================================="
echo ""
echo "The oracle is ready to run. To execute the experiment:"
echo ""
echo "  multipass shell '"$VM_NAME"'"
echo "  cd ~/agent-capture-bench"
echo "  ./run_experiment.sh"
echo ""
echo "Or from macOS:"
echo "  multipass exec '"$VM_NAME"' -- bash -c \"cd ~/agent-capture-bench && ./run_experiment.sh\""
'

echo ""
echo "=== Setup complete ==="
echo ""
echo "Quick reference:"
echo "  Connect:     multipass shell $VM_NAME"
echo "  Run:         multipass exec $VM_NAME -- bash -c 'cd ~/agent-capture-bench && ./run_experiment.sh'"
echo "  Copy files:  multipass transfer $VM_NAME:/home/ubuntu/agent-capture-bench/.work/run-*/oracle-events.jsonl ."
echo "  Stop:        multipass stop $VM_NAME"
echo "  Delete:      multipass delete $VM_NAME && multipass purge"
