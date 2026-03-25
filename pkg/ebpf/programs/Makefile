# ANCHOR: eBPF Program Build System - Dec 27, 2025 / Mar 23, 2026
# Builds libbpf-style tracepoint programs for embed + cilium/ebpf loading.

CLANG ?= clang
OUTPUT := bin
ARCH := $(shell uname -m)
ARCH_INCLUDE := /usr/include/$(ARCH)-linux-gnu
TARGET_ARCH ?= x86
VMLINUX ?= /sys/kernel/btf/vmlinux
VMLINUX_H := vmlinux.h
BPF_INCLUDE ?= /usr/include/bpf
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) -I$(ARCH_INCLUDE) -I$(BPF_INCLUDE) -I.

TARGETS := $(OUTPUT)/process.o $(OUTPUT)/network.o $(OUTPUT)/file.o \
	$(OUTPUT)/capability.o $(OUTPUT)/dns.o

.PHONY: all clean vmlinux

all: $(OUTPUT) $(VMLINUX_H) $(TARGETS)

$(OUTPUT):
	mkdir -p $(OUTPUT)

# ANCHOR: vmlinux.h generation - Feature: CO-RE build pipeline - Mar 25, 2026
# Generates vmlinux.h from kernel BTF before compiling eBPF objects.
$(VMLINUX_H):
	bpftool btf dump file $(VMLINUX) format c > $(VMLINUX_H)

vmlinux: $(VMLINUX_H)

$(OUTPUT)/%.o: %.c $(VMLINUX_H) | $(OUTPUT)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT)

.DEFAULT_GOAL := all
