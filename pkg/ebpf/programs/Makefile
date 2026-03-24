# ANCHOR: eBPF Program Build System - Feature: libbpf CO-RE build - Mar 24, 2026
# Compiles eBPF C programs with libbpf headers and generated vmlinux.h for CO-RE.
# Output: .o bytecode files for LoadPrograms() in pkg/ebpf/loader.go

CLANG ?= clang
BPFTOOL ?= /usr/sbin/bpftool
ARCH ?= x86
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I. -I/usr/include -I/usr/include/bpf
OUTPUT := bin
VMLINUX ?= /sys/kernel/btf/vmlinux
VMLINUX_H := vmlinux.h

# All eBPF programs
TARGETS := $(OUTPUT)/process.o $(OUTPUT)/network.o $(OUTPUT)/file.o \
           $(OUTPUT)/capability.o $(OUTPUT)/dns.o

.PHONY: all clean

all: $(VMLINUX_H) $(OUTPUT) $(TARGETS)

# Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

# Generate CO-RE type header from kernel BTF
$(VMLINUX_H):
	$(BPFTOOL) btf dump file $(VMLINUX) format c > $(VMLINUX_H)

# Compile eBPF C program to bytecode
$(OUTPUT)/%.o: %.c common.h $(VMLINUX_H) | $(OUTPUT)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT) $(VMLINUX_H)

.DEFAULT_GOAL := all
