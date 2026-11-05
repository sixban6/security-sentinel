package patch

import (
	"testing"
)

func TestSafeCVETokenSanitizesInput(t *testing.T) {
	got := SafeCVEToken("CVE-2025-12345; rm -rf /")
	if got != "CVE-2025-12345__rm_-rf__" {
		t.Fatalf("unexpected SafeCVEToken: %q", got)
	}
}
