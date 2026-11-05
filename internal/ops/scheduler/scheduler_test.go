package scheduler

import (
	"strings"
	"testing"
)

func TestCronNormalizationAndPlistEscaping(t *testing.T) {
	norm, err := NormalizeScheduleExpr("08:30")
	if err != nil || norm != "30 8 * * *" {
		t.Fatalf("NormalizeScheduleExpr(08:30) = %q, %v", norm, err)
	}
	ivs, err := CronToLaunchdIntervals("0 9 * * 1,5")
	if err != nil || len(ivs) != 2 {
		t.Fatalf("expected 2 launchd intervals, got %d (%v)", len(ivs), err)
	}
	plist := GenerateLaunchdPlist(`/path/with & <special>/security-sentinel audit`, ivs, "/tmp/logs", "0 9 * * 1,5")
	if !strings.Contains(plist, "&amp;") || !strings.Contains(plist, "&lt;special&gt;") {
		t.Fatalf("expected XML escaping in plist:\n%s", plist)
	}
}
