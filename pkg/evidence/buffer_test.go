package evidence

import (
	"testing"
	"time"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

func TestBufferEnqueueFlushAndCount(t *testing.T) {
	buf := NewBuffer(2, 100*time.Millisecond)

	event := &enrichment.EnrichedEvent{EventType: "process_execution"}
	buf.Enqueue(event, nil)
	if got := buf.Count(); got != 1 {
		t.Fatalf("expected count 1, got %d", got)
	}
	if buf.IsFull() {
		t.Fatalf("buffer should not be full yet")
	}

	buf.Enqueue(event, nil)
	if !buf.IsFull() {
		t.Fatalf("buffer should be full at max size")
	}

	flushed := buf.Flush()
	if len(flushed) != 2 {
		t.Fatalf("expected 2 buffered events, got %d", len(flushed))
	}
	if got := buf.Count(); got != 0 {
		t.Fatalf("expected count 0 after flush, got %d", got)
	}
}

func TestBufferStalenessAndClear(t *testing.T) {
	buf := NewBuffer(10, 30*time.Millisecond)
	buf.Enqueue(&enrichment.EnrichedEvent{EventType: "dns_query"}, nil)

	if buf.IsStale() {
		t.Fatalf("buffer should not be stale immediately")
	}
	time.Sleep(40 * time.Millisecond)
	if !buf.IsStale() {
		t.Fatalf("buffer should be stale after maxAge")
	}

	buf.Clear()
	if got := buf.Count(); got != 0 {
		t.Fatalf("expected count 0 after clear, got %d", got)
	}
}
