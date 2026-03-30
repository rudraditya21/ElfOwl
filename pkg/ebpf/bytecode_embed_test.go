package ebpf

import (
	"strings"
	"testing"
)

func TestGetProgramMissingIncludesBuildHint(t *testing.T) {
	_, err := GetProgram("missing-program")
	if err == nil {
		t.Fatalf("expected error for missing program")
	}

	if !strings.Contains(err.Error(), "make -C pkg/ebpf/programs all") {
		t.Fatalf("expected build hint in error, got: %v", err)
	}
}
