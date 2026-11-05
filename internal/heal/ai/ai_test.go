package ai

import (
	"testing"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestSafetyGatekeeperBlocksDangerousAndBashismsAndMissingRollback(t *testing.T) {
	openwrtCtx := model.OSContext{OSFamily: "openwrt", Shell: "BusyBox ash (/bin/sh -> busybox)"}

	if ok, _ := VerifyScriptSafety("#!/bin/sh\nrm -rf / *\n", openwrtCtx); ok {
		t.Fatal("expected rm -rf / to be blocked")
	}
	if ok, _ := VerifyScriptSafety("#!/bin/sh\nif [[ $a == 1 ]]; then echo hi; fi\n", openwrtCtx); ok {
		t.Fatal("expected bashism [[ ]] to be blocked on BusyBox ash")
	}
	if ok, msg := VerifyScriptSafety("#!/bin/sh\nsysctl -w net.ipv4.tcp_syncookies=1\n", openwrtCtx); !ok {
		t.Fatalf("expected valid POSIX script to pass, got error: %s", msg)
	}

	// Ensure missing rollback script is rejected (no fake tcp_fastopen fallback!)
	onlyOne := "```sh\n#!/bin/sh\nsysctl -w net.ipv4.tcp_syncookies=1\n```"
	res := parseModelAssessment(onlyOne, "CVE-2025-11111", openwrtCtx)
	if res.Success {
		t.Fatal("expected single script without paired rollback to be rejected by safety gate")
	}

	dual := "```sh\n#!/bin/sh\n# Strategy: Enable strict TCP syncookies\nsysctl -w net.ipv4.tcp_syncookies=1\n```\n" +
		ScriptDelimiter +
		"\n```sh\n#!/bin/sh\nsysctl -w net.ipv4.tcp_syncookies=1\n```"
	resOK := parseModelAssessment(dual, "CVE-2025-11111", openwrtCtx)
	if !resOK.Success || !resOK.HasWorkaround || resOK.Strategy != "Enable strict TCP syncookies" {
		t.Fatalf("expected valid dual script to succeed: %+v", resOK)
	}
}
