// ANCHOR: eBPF Bytecode Embedding - Phase 2: Monitor Implementation - Dec 27, 2025
// Uses //go:embed to include compiled eBPF programs in the binary
// Eliminates need for external file dependencies at runtime

package ebpf

import (
	"embed"
	"fmt"
)

// ANCHOR: Embed bin directory with .gitkeep fallback - Fix: build blocker without precompiled .o - Mar 29, 2026
// Use a directory-wide pattern so `go build` works even when object files are not prebuilt yet.
// Runtime loading still requires named `<program>.o` artifacts; GetProgram returns a clear error otherwise.
//
//go:embed programs/bin/*
var programFiles embed.FS

// GetProgram returns the compiled eBPF bytecode for the named program
// Examples: GetProgram("process"), GetProgram("network"), etc.
// Returns error if program bytecode file not found or unreadable
func GetProgram(name string) ([]byte, error) {
	data, err := programFiles.ReadFile(fmt.Sprintf("programs/bin/%s.o", name))
	if err != nil {
		return nil, fmt.Errorf("failed to load %s.o bytecode (run make -C pkg/ebpf/programs all): %w", name, err)
	}
	return data, nil
}

// ListPrograms returns the names of all available programs
// Useful for verification and debugging
var ListPrograms = []string{
	ProcessProgramName,
	NetworkProgramName,
	FileProgramName,
	CapabilityProgramName,
	DNSProgramName,
}
