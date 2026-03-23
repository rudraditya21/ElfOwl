//go:build integration
// +build integration

// ANCHOR: eBPF kernel integration tests - Feature: real kernel event verification - Mar 23, 2026
// Validates that compiled eBPF programs can load, attach, and emit events on a real kernel.

package ebpf

import (
	"bytes"
	"encoding/binary"
	"os"
	"runtime"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

const ebpfIntegrationEnv = "ELFOWL_EBPF_INTEGRATION"

// ANCHOR: Integration test gating - Safety: root + explicit opt-in - Mar 23, 2026
// Prevents accidental execution on unsupported systems or without privileges.
func requireEBPFIntegration(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("linux-only integration test")
	}

	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}

	if os.Getenv(ebpfIntegrationEnv) != "1" {
		t.Skipf("set %s=1 to enable", ebpfIntegrationEnv)
	}
}

func requireCompiledProgram(t *testing.T, name string) {
	t.Helper()

	data, err := GetProgram(name)
	if err != nil {
		t.Skipf("missing bytecode for %s: %v", name, err)
	}

	if len(data) < 256 {
		t.Skipf("bytecode for %s looks stubbed (size=%d); run make -C pkg/ebpf/programs", name, len(data))
	}

	if !bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
		t.Skipf("bytecode for %s is not ELF", name)
	}
}

func TestFileProgramEmitsEvents(t *testing.T) {
	requireEBPFIntegration(t)
	requireCompiledProgram(t, FileProgramName)

	logger := zaptest.NewLogger(t)

	opts := DefaultLoadOptions()
	opts.Process.Enabled = false
	opts.Network.Enabled = false
	opts.Capability.Enabled = false
	opts.DNS.Enabled = false
	opts.File.Enabled = true
	opts.File.Timeout = 200 * time.Millisecond
	opts.PerfBuffer.Enabled = true
	opts.RingBuffer.Enabled = false
	opts.PerfBuffer.LostHandler = false

	collection, err := LoadProgramsWithOptions(logger, opts)
	if err != nil {
		t.Fatalf("load programs: %v", err)
	}
	defer collection.Close()

	if collection.File == nil || collection.File.Reader == nil {
		t.Fatal("file program reader not initialized")
	}

	file, err := os.Open("/etc/hosts")
	if err != nil {
		t.Fatalf("open /etc/hosts: %v", err)
	}
	file.Close()

	pid := uint32(os.Getpid())
	deadline := time.Now().Add(2 * time.Second)

	for time.Now().Before(deadline) {
		data, err := collection.File.Reader.Read()
		if err != nil {
			t.Fatalf("read event: %v", err)
		}
		if len(data) == 0 {
			continue
		}

		var evt FileEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			continue
		}

		if evt.PID == pid {
			return
		}
	}

	t.Fatalf("did not observe file event for pid %d", pid)
}
