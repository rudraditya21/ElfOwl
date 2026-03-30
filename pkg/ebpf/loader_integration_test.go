//go:build integration
// +build integration

// ANCHOR: eBPF kernel integration tests - Feature: real kernel event verification - Mar 23, 2026
// Validates that compiled eBPF programs can load, attach, and emit events on a real kernel.

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
	"golang.org/x/sys/unix"
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

func mustLoadOnly(t *testing.T, name string) *Collection {
	t.Helper()

	opts := DefaultLoadOptions()
	opts.Process.Enabled = false
	opts.Network.Enabled = false
	opts.File.Enabled = false
	opts.Capability.Enabled = false
	opts.DNS.Enabled = false

	switch name {
	case ProcessProgramName:
		opts.Process.Enabled = true
		opts.Process.Timeout = 200 * time.Millisecond
	case NetworkProgramName:
		opts.Network.Enabled = true
		opts.Network.Timeout = 200 * time.Millisecond
	case FileProgramName:
		opts.File.Enabled = true
		opts.File.Timeout = 200 * time.Millisecond
	case CapabilityProgramName:
		opts.Capability.Enabled = true
		opts.Capability.Timeout = 200 * time.Millisecond
	case DNSProgramName:
		opts.DNS.Enabled = true
		opts.DNS.Timeout = 200 * time.Millisecond
	default:
		t.Fatalf("unknown program name: %s", name)
	}

	opts.PerfBuffer.Enabled = true
	opts.RingBuffer.Enabled = false
	opts.PerfBuffer.LostHandler = false

	collection, err := LoadProgramsWithOptions(zaptest.NewLogger(t), opts)
	if err != nil {
		t.Fatalf("load %s program: %v", name, err)
	}

	t.Cleanup(func() {
		_ = collection.Close()
	})
	return collection
}

func trimNull(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

func TestProcessProgramEmitsEvents(t *testing.T) {
	requireEBPFIntegration(t)
	requireCompiledProgram(t, ProcessProgramName)

	collection := mustLoadOnly(t, ProcessProgramName)
	if collection.Process == nil || collection.Process.Reader == nil {
		t.Fatal("process program reader not initialized")
	}

	// ANCHOR: Process probe PID matching - Fix: tracepoint comm ambiguity - Mar 28, 2026
	// sys_enter_execve reports pre-exec task comm on some kernels, so match by emitted PID.
	probePIDs := make(map[uint32]struct{}, 6)
	for i := 0; i < 6; i++ {
		cmd := exec.Command("/bin/echo", fmt.Sprintf("elfowl-ebpf-process-%d", i))
		if err := cmd.Start(); err != nil {
			t.Fatalf("start probe process %d: %v", i, err)
		}
		probePIDs[uint32(cmd.Process.Pid)] = struct{}{}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("wait probe process %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		data, err := collection.Process.Reader.Read()
		if err != nil {
			t.Fatalf("read process event: %v", err)
		}
		if len(data) == 0 {
			continue
		}

		var evt ProcessEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			continue
		}

		if _, ok := probePIDs[evt.PID]; ok {
			// ANCHOR: CO-RE field assertions - Test: cap/netns validation - Mar 25, 2026
			// Ensure CO-RE capability reads populate non-zero values.
			if evt.Capabilities == 0 {
				t.Fatal("capabilities not populated (CO-RE required)")
			}
			return
		}
	}

	t.Fatal("did not observe process execution event for probe PIDs")
}

func TestNetworkProgramEmitsEvents(t *testing.T) {
	requireEBPFIntegration(t)
	requireCompiledProgram(t, NetworkProgramName)

	collection := mustLoadOnly(t, NetworkProgramName)
	if collection.Network == nil || collection.Network.Reader == nil {
		t.Fatal("network program reader not initialized")
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()

	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial tcp4: %v", err)
	}
	_ = conn.Close()
	<-acceptDone

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		data, err := collection.Network.Reader.Read()
		if err != nil {
			t.Fatalf("read network event: %v", err)
		}
		if len(data) == 0 {
			continue
		}

		var evt NetworkEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			continue
		}
		if evt.Protocol == IPPROTO_TCP && int(evt.DPort) == port && evt.DAddr == ipStringToUint32("127.0.0.1") {
			// ANCHOR: CO-RE field assertions - Test: cap/netns validation - Mar 25, 2026
			// Ensure CO-RE netns reads populate non-zero values.
			if evt.NetNS == 0 {
				t.Fatalf("netns not populated (CO-RE required)")
			}
			return
		}
	}

	t.Fatalf("did not observe tcp connect event for 127.0.0.1:%d", port)
}

func TestFileProgramEmitsEvents(t *testing.T) {
	requireEBPFIntegration(t)
	requireCompiledProgram(t, FileProgramName)

	collection := mustLoadOnly(t, FileProgramName)
	if collection.File == nil || collection.File.Reader == nil {
		t.Fatal("file program reader not initialized")
	}

	file, err := os.CreateTemp("", "elfowl-file-probe-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	path := file.Name()
	_ = file.Close()
	defer os.Remove(path)

	opened, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open temp file for write: %v", err)
	}
	_, _ = opened.WriteString("probe")
	_ = opened.Close()

	pid := uint32(os.Getpid())
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		data, err := collection.File.Reader.Read()
		if err != nil {
			t.Fatalf("read file event: %v", err)
		}
		if len(data) == 0 {
			continue
		}

		var evt FileEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			continue
		}
		if evt.PID == pid && trimNull(evt.Filename[:]) == path && evt.Operation == FileOpWrite {
			return
		}
	}

	t.Fatalf("did not observe file write event for %s", path)
}

func TestCapabilityProgramEmitsEvents(t *testing.T) {
	requireEBPFIntegration(t)
	requireCompiledProgram(t, CapabilityProgramName)

	collection := mustLoadOnly(t, CapabilityProgramName)
	if collection.Capability == nil || collection.Capability.Reader == nil {
		t.Fatal("capability program reader not initialized")
	}

	_ = unix.Mount("none", "/definitely/not/a/real/path/elfowl-capability", "tmpfs", 0, "")

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		data, err := collection.Capability.Reader.Read()
		if err != nil {
			t.Fatalf("read capability event: %v", err)
		}
		if len(data) == 0 {
			continue
		}

		var evt CapabilityEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			continue
		}
		if evt.Capability == CapSysAdmin {
			return
		}
	}

	t.Fatal("did not observe CAP_SYS_ADMIN capability event")
}

func TestDNSProgramEmitsEvents(t *testing.T) {
	requireEBPFIntegration(t)
	requireCompiledProgram(t, DNSProgramName)

	collection := mustLoadOnly(t, DNSProgramName)
	if collection.DNS == nil || collection.DNS.Reader == nil {
		t.Fatal("dns program reader not initialized")
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("create udp socket: %v", err)
	}
	defer unix.Close(fd)

	// Minimal DNS query for example.com A IN.
	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // QTYPE=A
		0x00, 0x01, // QCLASS=IN
	}

	dst := &unix.SockaddrInet4{
		Port: 53,
		Addr: [4]byte{127, 0, 0, 1},
	}
	if err := unix.Sendto(fd, query, 0, dst); err != nil {
		t.Fatalf("send dns probe packet: %v", err)
	}

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		data, err := collection.DNS.Reader.Read()
		if err != nil {
			t.Fatalf("read dns event: %v", err)
		}
		if len(data) == 0 {
			continue
		}

		var evt DNSEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			continue
		}

		qname := trimNull(evt.QueryName[:])
		if evt.QueryType == DNSTypeA && strings.Contains(qname, "example.com") {
			return
		}
	}

	t.Fatal("did not observe DNS query event for example.com A")
}
