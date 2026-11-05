package version

import (
	"testing"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestCompareSemVerPreRelease(t *testing.T) {
	cases := []struct {
		v1, op, v2 string
		want       bool
	}{
		{"1.2.0-rc.1", "<", "1.2.0", true},
		{"1.2.0-alpha.1", "<", "1.2.0-beta.1", true},
		{"1.2.0-beta.2", "<", "1.2.0-rc.1", true},
		{"1.2.0rc1", "<", "1.2.0", true},
		{"1.2.0.post1", ">", "1.2.0", true},
		{"2.31.0", ">=", "2.31.0", true},
		{"v1.24.2", "<", "1.24.3", true},
	}
	for _, tc := range cases {
		if got := CompareOp(model.EcoPyPI, tc.v1, tc.op, tc.v2); got != tc.want {
			t.Errorf("CompareOp(%q, %q, %q) = %v, want %v", tc.v1, tc.op, tc.v2, got, tc.want)
		}
	}
}

func TestCompareDebianAndAPK(t *testing.T) {
	if CompareDebian("2.1.28+dfsg-10", "2.1.28+dfsg-10+deb12u1") >= 0 {
		t.Fatal("expected Debian security revision +deb12u1 to be newer")
	}
	if CompareDebian("1:1.0.0-1", "2.9.9-9") <= 0 {
		t.Fatal("expected higher Debian epoch 1:1.0.0-1 > 2.9.9-9")
	}
	if CompareDebian("3.0~beta1-1", "3.0-1") >= 0 {
		t.Fatal("expected Debian tilde 3.0~beta1-1 < 3.0-1")
	}
	if CompareAPK("2.90-r1", "2.90-r2") >= 0 {
		t.Fatal("expected OpenWrt/Alpine 2.90-r1 < 2.90-r2")
	}
}

func TestIsVersionVulnerableRanges(t *testing.T) {
	if !IsVersionVulnerable(model.EcoNPM, "13.4.1", ">= 13.0.0, < 13.4.19") {
		t.Fatal("expected 13.4.1 to be vulnerable in >= 13.0.0, < 13.4.19")
	}
	if IsVersionVulnerable(model.EcoNPM, "13.4.19", ">= 13.0.0, < 13.4.19") {
		t.Fatal("expected 13.4.19 to be patched")
	}
	if !IsVersionVulnerable(model.EcoNPM, "2.0.5", "< 1.5.0 || >= 2.0.0, < 2.1.0") {
		t.Fatal("expected union range match")
	}
}

func TestIsKernelVulnerableMultiBranch(t *testing.T) {
	// Test fixture ONLY (never hardcoded in production advisories!)
	fixture := model.Advisory{
		ID:           "CVE-2026-98432",
		CVEID:        "CVE-2026-98432",
		Ecosystem:    model.EcoLinux,
		Package:      "linux",
		IntroducedIn: "4.4",
		FixedIn:      []string{"5.10.272", "5.15.223", "6.1.190", "6.6.159", "6.12.113", "7.3"},
	}

	cases := []struct {
		kernel string
		want   bool
	}{
		{"4.1.50", false},   // before introduced_in 4.4
		{"6.1.190", false},  // patched on 6.1 LTS branch
		{"6.1.195", false},  // newer on 6.1 LTS branch
		{"6.1.189", true},   // unpatched on 6.1 LTS branch
		{"6.12.112", true},  // unpatched on 6.12 LTS branch
		{"6.12.113", false}, // patched on 6.12 LTS branch
		{"7.4.0", false},    // above mainline fix
		{"6.8.12", true},    // EOL intermediate branch without backport < 7.3
	}
	for _, tc := range cases {
		if got := IsKernelVulnerable(tc.kernel, fixture); got != tc.want {
			t.Errorf("IsKernelVulnerable(%q) = %v, want %v", tc.kernel, got, tc.want)
		}
	}
}
