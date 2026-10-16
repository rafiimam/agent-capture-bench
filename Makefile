CLANG ?= clang
CC ?= cc
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
BPF_ARCH := x86
else ifeq ($(ARCH),aarch64)
BPF_ARCH := arm64
else ifeq ($(ARCH),armv7l)
BPF_ARCH := arm
else ifeq ($(ARCH),riscv64)
BPF_ARCH := riscv
else
BPF_ARCH := $(ARCH)
endif
MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)
INCLUDE_ARCH := /usr/include/$(MULTIARCH)

CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Iinclude -I$(INCLUDE_ARCH) -I/usr/include
LDLIBS := -lbpf -lelf -lz
BUILD := build

.PHONY: all clean check
all: $(BUILD)/oracle.bpf.o $(BUILD)/agentcap-oracle

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/oracle.bpf.o: src/oracle.bpf.c include/oracle_events.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/agentcap-oracle: src/oracle.c include/oracle_events.h | $(BUILD)
	$(CC) $(CFLAGS) -Iinclude $< -o $@ $(LDLIBS)

check:
	python3 -m unittest discover -s tests -v
	python3 -m py_compile workflow/prepare_fixture.py workflow/run_workflow.py tools/report.py

clean:
	rm -rf $(BUILD) .work
