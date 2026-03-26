// ANCHOR: Cilium/eBPF Program Loader - Dec 27, 2025
// Loads compiled eBPF bytecode and manages program lifecycle
// Provides abstraction over cilium/ebpf Collection API for monitor integration

package ebpf

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/btf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// ============================================================================
// Reader Interface - Abstracts event stream source
// ============================================================================

// Reader defines the interface for reading eBPF events from kernel
// Implementations: PerfReader (perf buffers), RingBufferReader (ring buffers)
type Reader interface {
	// Read returns the next event or error
	Read() ([]byte, error)

	// Close releases reader resources
	Close() error
}

// ============================================================================
// ProgramSet - Wraps individual eBPF program + maps + reader
// ============================================================================

// ProgramSet represents a compiled eBPF program and its associated resources
// Example: ProcessMonitor consists of one program with process_events perf buffer
type ProgramSet struct {
	// Program is the loaded eBPF program (e.g., sched_process_exec tracepoint)
	Program *ebpf.Program

	// ANCHOR: Multi-program support - Feature: advanced tracepoints - Mar 25, 2026
	// Track all programs loaded from the collection so multi-tracepoint modules close cleanly.
	Programs map[string]*ebpf.Program

	// Maps contains all maps used by this program (perf buffers, ring buffers, etc.)
	Maps map[string]*ebpf.Map

	// Reader provides access to event stream from kernel
	// nil if program doesn't produce events (e.g., helper-only programs)
	Reader Reader

	// ANCHOR: ProgramSet link handles - Feature: tracepoint detach - Mar 23, 2026
	// Track attached links so programs are cleanly detached on shutdown.
	Links []link.Link

	// Logger for diagnostics
	Logger *zap.Logger
}

// ProgramConfig controls per-program loading and reader settings.
type ProgramConfig struct {
	Enabled    bool
	BufferSize int
	Timeout    time.Duration
}

// PerfBufferOptions controls perf buffer reader configuration.
type PerfBufferOptions struct {
	Enabled     bool
	PageCount   int
	LostHandler bool
}

// RingBufferOptions controls ring buffer reader configuration.
type RingBufferOptions struct {
	Enabled bool
	Size    int
}

// LoadOptions defines which programs to load and how to configure readers.
type LoadOptions struct {
	Process       ProgramConfig
	Network       ProgramConfig
	File          ProgramConfig
	Capability    ProgramConfig
	DNS           ProgramConfig
	PerfBuffer    PerfBufferOptions
	RingBuffer    RingBufferOptions
	KernelBTFPath string
}

// ============================================================================
// Collection - Wraps all loaded eBPF programs
// ============================================================================

// Collection represents all loaded eBPF programs for elf-owl
// One entry per monitoring domain (process, network, file, capability, dns)
type Collection struct {
	// Process monitors process execution (exec syscalls)
	Process *ProgramSet

	// Network monitors socket connections (TCP/UDP)
	Network *ProgramSet

	// File monitors file operations (open, write, chmod)
	File *ProgramSet

	// Capability monitors Linux capability usage
	Capability *ProgramSet

	// DNS monitors DNS queries and responses
	DNS *ProgramSet

	// Logger for diagnostics
	Logger *zap.Logger

	// bytecode holds embedded compiled eBPF programs
	bytecode map[string][]byte
}

type programDefinition struct {
	Name            string
	Description     string
	MapName         string
	TracepointGroup string
	TracepointName  string
	Config          ProgramConfig
}

// DefaultLoadOptions enables all programs with perf buffers by default.
func DefaultLoadOptions() LoadOptions {
	return LoadOptions{
		Process:    ProgramConfig{Enabled: true},
		Network:    ProgramConfig{Enabled: true},
		File:       ProgramConfig{Enabled: true},
		Capability: ProgramConfig{Enabled: true},
		DNS:        ProgramConfig{Enabled: true},
		PerfBuffer: PerfBufferOptions{Enabled: true, PageCount: 64, LostHandler: true},
		RingBuffer: RingBufferOptions{Enabled: false, Size: 65536},
	}
}

func programDefinitions(opts LoadOptions) []programDefinition {
	return []programDefinition{
		{
			Name:        ProcessProgramName,
			Description: "process execution",
			MapName:     ProcessEventsMap,
			// ANCHOR: Process tracepoint selection - Feature: execve/execveat - Mar 25, 2026
			TracepointGroup: "syscalls",
			TracepointName:  "sys_enter_execve",
			Config:          opts.Process,
		},
		{
			Name:            NetworkProgramName,
			Description:     "network connections",
			MapName:         NetworkEventsMap,
			TracepointGroup: "tcp",
			TracepointName:  "tcp_connect",
			Config:          opts.Network,
		},
		{
			Name:            FileProgramName,
			Description:     "file access",
			MapName:         FileEventsMap,
			TracepointGroup: "syscalls",
			TracepointName:  "sys_enter_openat",
			Config:          opts.File,
		},
		{
			Name:            CapabilityProgramName,
			Description:     "linux capabilities",
			MapName:         CapabilityEventsMap,
			TracepointGroup: "capability",
			TracepointName:  "cap_capable",
			Config:          opts.Capability,
		},
		{
			Name:            DNSProgramName,
			Description:     "DNS queries",
			MapName:         DNSEventsMap,
			TracepointGroup: "syscalls",
			TracepointName:  "sys_enter_sendto",
			Config:          opts.DNS,
		},
	}
}

// ANCHOR: Load single eBPF program set - Feature: tracepoint attach - Mar 23, 2026
// Parses bytecode, loads the collection, attaches tracepoint, and returns ProgramSet.
func loadProgramSet(logger *zap.Logger, def programDefinition, opts LoadOptions) (*ProgramSet, error) {
	data, err := GetProgram(def.Name)
	if err != nil {
		return nil, fmt.Errorf("get bytecode: %w", err)
	}

	if len(data) < 64 {
		return nil, fmt.Errorf("bytecode too small for valid ELF")
	}

	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("invalid ELF magic in bytecode")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse bytecode: %w", err)
	}

	// ANCHOR: Kernel BTF override - Feature: CO-RE portability - Mar 25, 2026
	// Allows loading CO-RE programs against an explicit kernel BTF path.
	var kernelTypes *btf.Spec
	if opts.KernelBTFPath != "" {
		btfSpec, err := btf.LoadSpec(opts.KernelBTFPath)
		if err != nil {
			return nil, fmt.Errorf("load kernel BTF spec: %w", err)
		}
		kernelTypes = btfSpec
	}

	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: kernelTypes,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("load collection: %w", err)
	}

	sectionByName := make(map[string]string, len(spec.Programs))
	for name, progSpec := range spec.Programs {
		if progSpec == nil {
			continue
		}
		sectionByName[name] = progSpec.SectionName
	}

	// ANCHOR: Multi-tracepoint attach - Feature: advanced probes - Mar 25, 2026
	// Attach every tracepoint/raw_tracepoint section found in the collection.
	links, programs, attachInfo, err := attachPrograms(logger, def.Name, collection.Programs, sectionByName)
	if err != nil {
		collection.Close()
		return nil, err
	}
	if len(programs) == 0 {
		collection.Close()
		return nil, fmt.Errorf("no tracepoint programs found in %s", def.Name)
	}

	mapName, eventMap := selectEventMap(collection.Maps, def.MapName)
	if eventMap == nil {
		closeLinks(links)
		collection.Close()
		return nil, fmt.Errorf("event map %s not found", def.MapName)
	}

	reader, err := createReader(eventMap, def, opts, logger)
	if err != nil {
		closeLinks(links)
		collection.Close()
		return nil, fmt.Errorf("create event reader: %w", err)
	}

	if logger != nil {
		for _, info := range attachInfo {
			logger.Info("loaded eBPF program",
				zap.String("program", def.Name),
				zap.String("section", info.Section),
				zap.String("map", mapName),
				zap.String("attach_type", info.AttachKind),
				zap.String("tracepoint", info.Tracepoint),
			)
		}
	}

	allMaps := make(map[string]*ebpf.Map, len(collection.Maps))
	for name, m := range collection.Maps {
		if m != nil {
			allMaps[name] = m
		}
	}

	var primary *ebpf.Program
	for _, prog := range programs {
		primary = prog
		break
	}

	return &ProgramSet{
		Program:  primary,
		Programs: programs,
		Maps:     allMaps,
		Reader:   reader,
		Links:    links,
		Logger:   logger,
	}, nil
}

// ANCHOR: Multi-tracepoint attach helpers - Feature: advanced probes - Mar 25, 2026
// Parses program sections and attaches every tracepoint/raw_tracepoint program.
type attachInfo struct {
	ProgramName string
	Section     string
	AttachKind  string
	Tracepoint  string
}

func attachPrograms(logger *zap.Logger, setName string, programs map[string]*ebpf.Program, sections map[string]string) ([]link.Link, map[string]*ebpf.Program, []attachInfo, error) {
	links := make([]link.Link, 0)
	attached := make(map[string]*ebpf.Program)
	infos := make([]attachInfo, 0)

	for name, prog := range programs {
		if prog == nil {
			continue
		}
		section := sections[name]
		kind, group, tpName, ok := parseTracepointSection(section)
		if !ok {
			continue
		}

		var (
			lnk link.Link
			err error
		)

		switch kind {
		case "tracepoint":
			lnk, err = link.Tracepoint(group, tpName, prog, nil)
		case "raw_tracepoint":
			lnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    tpName,
				Program: prog,
			})
		default:
			continue
		}

		if err != nil {
			if isMissingTracepointError(err) {
				if logger != nil {
					tracepoint := tpName
					if kind == "tracepoint" {
						tracepoint = fmt.Sprintf("%s/%s", group, tpName)
					}
					logger.Warn("skipping unavailable tracepoint",
						zap.String("program", setName),
						zap.String("section", section),
						zap.String("attach_type", kind),
						zap.String("tracepoint", tracepoint),
						zap.Error(err),
					)
				}
				continue
			}
			closeLinks(links)
			return nil, nil, nil, fmt.Errorf("attach program %s (%s): %w", name, section, err)
		}

		links = append(links, lnk)
		attached[name] = prog
		tracepoint := tpName
		if kind == "tracepoint" {
			tracepoint = fmt.Sprintf("%s/%s", group, tpName)
		}
		infos = append(infos, attachInfo{
			ProgramName: name,
			Section:     section,
			AttachKind:  kind,
			Tracepoint:  tracepoint,
		})
	}

	return links, attached, infos, nil
}

func isMissingTracepointError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "enoent") {
		return true
	}

	if strings.Contains(msg, "no such file or directory") &&
		(strings.Contains(msg, "/events/") || strings.Contains(msg, "tracepoint")) {
		return true
	}

	return false
}

func parseTracepointSection(section string) (kind, group, name string, ok bool) {
	if strings.HasPrefix(section, "tracepoint/") {
		parts := strings.Split(section, "/")
		if len(parts) < 3 {
			return "", "", "", false
		}
		group = parts[1]
		name = strings.Join(parts[2:], "/")
		if group == "" || name == "" {
			return "", "", "", false
		}
		return "tracepoint", group, name, true
	}
	if strings.HasPrefix(section, "raw_tracepoint/") {
		name = strings.TrimPrefix(section, "raw_tracepoint/")
		if name == "" {
			return "", "", "", false
		}
		return "raw_tracepoint", "", name, true
	}
	return "", "", "", false
}

func closeLinks(links []link.Link) {
	for _, lnk := range links {
		if lnk == nil {
			continue
		}
		_ = lnk.Close()
	}
}

// ANCHOR: Tracepoint program selection - Utility: pick tracepoint program - Mar 23, 2026
// Prefers tracepoint program types and falls back to any available program.
func selectTracepointProgram(programs map[string]*ebpf.Program) (string, *ebpf.Program) {
	for name, prog := range programs {
		if prog != nil && prog.Type() == ebpf.TracePoint {
			return name, prog
		}
	}
	for name, prog := range programs {
		if prog != nil && prog.Type() == ebpf.RawTracepoint {
			return name, prog
		}
	}
	for name, prog := range programs {
		if prog != nil {
			return name, prog
		}
	}
	return "", nil
}

func attachProgram(def programDefinition, prog *ebpf.Program) (link.Link, error) {
	if prog == nil {
		return nil, fmt.Errorf("program is nil")
	}

	switch prog.Type() {
	case ebpf.TracePoint:
		return link.Tracepoint(def.TracepointGroup, def.TracepointName, prog, nil)
	case ebpf.RawTracepoint:
		return link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    def.TracepointName,
			Program: prog,
		})
	default:
		return nil, fmt.Errorf("unsupported attach type %s", prog.Type())
	}
}

// ANCHOR: Event map selection - Utility: perf/ringbuf map lookup - Mar 23, 2026
// Chooses the preferred map name or the first perf/ringbuf map in the collection.
func selectEventMap(maps map[string]*ebpf.Map, preferred string) (string, *ebpf.Map) {
	if m, ok := maps[preferred]; ok {
		return preferred, m
	}
	for name, m := range maps {
		if m == nil {
			continue
		}
		if m.Type() == ebpf.PerfEventArray || m.Type() == ebpf.RingBuf {
			return name, m
		}
	}
	return "", nil
}

// ANCHOR: Event reader creation - Feature: perf/ringbuf reader wiring - Mar 23, 2026
// Builds a reader for the event map using perf or ring buffer settings.
func createReader(eventMap *ebpf.Map, def programDefinition, opts LoadOptions, logger *zap.Logger) (Reader, error) {
	if eventMap == nil {
		return nil, nil
	}

	switch eventMap.Type() {
	case ebpf.RingBuf:
		if !opts.RingBuffer.Enabled {
			return nil, fmt.Errorf("ring buffer reader disabled")
		}
		reader, err := ringbuf.NewReader(eventMap)
		if err != nil {
			return nil, fmt.Errorf("create ringbuf reader: %w", err)
		}
		return &RingBufferReader{
			reader:  reader,
			timeout: def.Config.Timeout,
			logger:  logger,
		}, nil
	case ebpf.PerfEventArray:
		if !opts.PerfBuffer.Enabled {
			return nil, fmt.Errorf("perf buffer reader disabled")
		}
		reader, err := perf.NewReader(eventMap, perfBufferSize(def, opts))
		if err != nil {
			return nil, fmt.Errorf("create perf reader: %w", err)
		}
		return &PerfBufferReader{
			reader:      reader,
			timeout:     def.Config.Timeout,
			lostHandler: opts.PerfBuffer.LostHandler,
			logger:      logger,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported event map type: %s", eventMap.Type())
	}
}

func perfBufferSize(def programDefinition, opts LoadOptions) int {
	if def.Config.BufferSize > 0 {
		return def.Config.BufferSize
	}
	if opts.PerfBuffer.PageCount > 0 {
		return opts.PerfBuffer.PageCount * os.Getpagesize()
	}
	return 64 * os.Getpagesize()
}

// ============================================================================
// LoadPrograms - Main entry point for loading eBPF programs
// ============================================================================

// LoadPrograms loads all compiled eBPF programs from embedded bytecode
// Returns Collection ready for use by agent monitors
//
// Flow:
// 1. Extract embedded .o bytecode files via GetProgram()
// 2. Parse ELF bytecode via cilium/ebpf.LoadCollectionSpec()
// 3. Load programs into kernel
// 4. Wrap in ProgramSet with Reader for event streaming
// 5. Return Collection for agent to use
func LoadPrograms(logger *zap.Logger) (*Collection, error) {
	return LoadProgramsWithOptions(logger, DefaultLoadOptions())
}

// ANCHOR: eBPF program loading and tracepoint attach - Feature: kernel attach - Mar 23, 2026
// Loads ELF bytecode, attaches tracepoints, and returns program sets for monitors.
func LoadProgramsWithOptions(logger *zap.Logger, opts LoadOptions) (*Collection, error) {
	coll := &Collection{
		Logger:   logger,
		bytecode: make(map[string][]byte),
	}

	if logger != nil {
		logger.Info("loading eBPF programs from embedded bytecode")
	}

	definitions := programDefinitions(opts)
	for _, def := range definitions {
		if !def.Config.Enabled {
			continue
		}

		programSet, err := loadProgramSet(logger, def, opts)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", def.Name, err)
		}

		switch def.Name {
		case ProcessProgramName:
			coll.Process = programSet
		case NetworkProgramName:
			coll.Network = programSet
		case FileProgramName:
			coll.File = programSet
		case CapabilityProgramName:
			coll.Capability = programSet
		case DNSProgramName:
			coll.DNS = programSet
		}
	}

	return coll, nil
}

// ============================================================================
// Close - Cleanup resources
// ============================================================================

// Close gracefully closes all eBPF programs and readers
// Called during agent shutdown
func (c *Collection) Close() error {
	if c == nil {
		return nil
	}

	var errs []error

	// Close all program sets in order
	if c.Process != nil {
		if err := c.Process.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close process program: %w", err))
		}
	}

	if c.Network != nil {
		if err := c.Network.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close network program: %w", err))
		}
	}

	if c.File != nil {
		if err := c.File.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close file program: %w", err))
		}
	}

	if c.Capability != nil {
		if err := c.Capability.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close capability program: %w", err))
		}
	}

	if c.DNS != nil {
		if err := c.DNS.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close dns program: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}

	return nil
}

// ============================================================================
// ProgramSet Methods
// ============================================================================

// Close closes the program set and all its resources
func (ps *ProgramSet) Close() error {
	if ps == nil {
		return nil
	}

	var errs []error

	// Close reader first (may be actively reading)
	if ps.Reader != nil {
		if err := ps.Reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close reader: %w", err))
		}
	}

	// ANCHOR: Detach eBPF links before closing programs - Safety: avoid dangling tracepoints - Mar 23, 2026
	// Close all attached links to detach programs from tracepoints.
	for _, lnk := range ps.Links {
		if lnk == nil {
			continue
		}
		if err := lnk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close link: %w", err))
		}
	}

	// ANCHOR: Close all loaded maps once - Fix: helper-map fd lifecycle - Mar 25, 2026
	// ProgramSet now tracks all maps from the collection; de-duplicate by pointer
	// in case multiple map names alias the same map object.
	closedMaps := make(map[*ebpf.Map]struct{}, len(ps.Maps))
	for name, m := range ps.Maps {
		if m == nil {
			continue
		}
		if _, seen := closedMaps[m]; seen {
			continue
		}
		closedMaps[m] = struct{}{}
		if err := m.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close map %s: %w", name, err))
		}
	}

	// Close programs (de-duplicate in case Program also appears in Programs)
	closedPrograms := make(map[*ebpf.Program]struct{}, len(ps.Programs))
	for name, prog := range ps.Programs {
		if prog == nil {
			continue
		}
		if _, seen := closedPrograms[prog]; seen {
			continue
		}
		closedPrograms[prog] = struct{}{}
		if err := prog.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close program %s: %w", name, err))
		}
	}
	if ps.Program != nil {
		if _, seen := closedPrograms[ps.Program]; !seen {
			if err := ps.Program.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close program: %w", err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("program set close errors: %v", errs)
	}

	return nil
}

// ============================================================================
// Helper Functions (Phase 2 Implementation)
// ============================================================================

// loadBytecode extracts embedded eBPF bytecode from compiled binaries
// Phase 2: Uses //go:embed to include .o files
func loadBytecode(progFiles embed.FS) (map[string][]byte, error) {
	// TODO (Phase 2): Implement bytecode loading
	// Walk programs/bin/*.o and load each file
	bytecode := make(map[string][]byte)

	// Phase 2 pseudocode:
	// fs.WalkDir(progFiles, "programs/bin", func(path string, d fs.DirEntry) error {
	//     if !strings.HasSuffix(path, ".o") {
	//         return nil
	//     }
	//     data, err := fs.ReadFile(progFiles, path)
	//     bytecode[filepath.Base(path)] = data
	//     return err
	// })

	return bytecode, nil
}

// newProgramSet creates a ProgramSet from loaded bytecode
// Phase 2: Parses ELF sections and attaches tracepoints
func newProgramSet(name string, bytecode []byte, logger *zap.Logger) (*ProgramSet, error) {
	// TODO (Phase 2): Implement program loading
	// 1. Parse ELF bytecode via cilium/ebpf spec
	// 2. Create ebpf.Program via CollectionSpec.Progs
	// 3. Load into kernel
	// 4. Create Reader (PerfBufferReader or RingBufferReader)
	// 5. Return ProgramSet

	return nil, fmt.Errorf("Phase 2 implementation: load %s program", name)
}

// attachTracepoint attaches eBPF program to kernel tracepoint
// Phase 2: Calls perf_event_open for tp_btf or raw_tracepoint
func attachTracepoint(prog *ebpf.Program, group, name string) error {
	// TODO (Phase 2): Implement tracepoint attachment
	// Use golang.org/x/sys/unix for perf_event_open syscall
	// Steps:
	// 1. Find tracepoint ID from /sys/kernel/debug/tracing/events/{group}/{name}/id
	// 2. Call perf_event_open with PERF_TYPE_TRACEPOINT
	// 3. Attach program via BPF_LINK_CREATE

	return fmt.Errorf("Phase 2 implementation: attach %s:%s", group, name)
}

// ============================================================================
// Event Reading (Phase 2 Implementation)
// ============================================================================

// ============================================================================
// Event Reader Implementations
// ============================================================================

// PerfBufferReader reads events from a perf buffer map
// Implements Reader interface for perf_event_array maps
// ANCHOR: Perf Buffer Reader - Phase 2: Monitor Implementation - Dec 27, 2025
// Reads events from per-CPU perf buffers (available on all eBPF kernels)
type PerfBufferReader struct {
	// perf.Reader handles multi-CPU perf event arrays
	reader *perf.Reader

	// Optional timeout for Read operations.
	timeout time.Duration

	// Log dropped samples when LostSamples > 0.
	lostHandler bool

	logger *zap.Logger
	closed bool
}

// Read returns next event from perf buffer
func (pr *PerfBufferReader) Read() ([]byte, error) {
	if pr.closed {
		return nil, fmt.Errorf("reader closed")
	}

	if pr.reader == nil {
		return nil, fmt.Errorf("perf reader not initialized")
	}

	if pr.timeout > 0 {
		pr.reader.SetDeadline(time.Now().Add(pr.timeout))
	} else {
		pr.reader.SetDeadline(time.Time{})
	}

	record, err := pr.reader.Read()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, nil
		}
		return nil, err
	}

	if record.LostSamples > 0 && pr.lostHandler && pr.logger != nil {
		pr.logger.Warn("perf buffer lost samples",
			zap.Uint64("lost_samples", record.LostSamples),
		)
	}

	if len(record.RawSample) == 0 {
		return nil, nil
	}

	payload := make([]byte, len(record.RawSample))
	copy(payload, record.RawSample)
	return payload, nil
}

// Close closes the perf buffer reader
func (pr *PerfBufferReader) Close() error {
	pr.closed = true
	if pr.reader == nil {
		return nil
	}
	if err := pr.reader.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}

// RingBufferReader reads events from a ring buffer map
// Implements Reader interface for ringbuf maps (kernel 5.8+)
// ANCHOR: Ring Buffer Reader - Phase 2: Monitor Implementation - Dec 27, 2025
// Reads events from single shared ring buffer (preferred for modern kernels)
type RingBufferReader struct {
	// ringbuf.Reader handles single shared ring buffer
	reader *ringbuf.Reader

	// Optional timeout for Read operations.
	timeout time.Duration

	logger *zap.Logger
	closed bool
}

// Read returns next event from ring buffer
func (rr *RingBufferReader) Read() ([]byte, error) {
	if rr.closed {
		return nil, fmt.Errorf("reader closed")
	}

	if rr.reader == nil {
		return nil, fmt.Errorf("ringbuf reader not initialized")
	}

	if rr.timeout > 0 {
		rr.reader.SetDeadline(time.Now().Add(rr.timeout))
	} else {
		rr.reader.SetDeadline(time.Time{})
	}

	record, err := rr.reader.Read()
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, nil
		}
		return nil, err
	}

	if len(record.RawSample) == 0 {
		return nil, nil
	}

	payload := make([]byte, len(record.RawSample))
	copy(payload, record.RawSample)
	return payload, nil
}

// Close closes the ring buffer reader
func (rr *RingBufferReader) Close() error {
	rr.closed = true
	if rr.reader == nil {
		return nil
	}
	if err := rr.reader.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}
