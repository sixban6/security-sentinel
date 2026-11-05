package inventory

import (
	"testing"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestParseMergedLinuxProbeOpenWrtLockdownAndDebianSourceMap(t *testing.T) {
	openwrtOut := `
===SEC:OS_RELEASE===
ID="openwrt"
VERSION_ID="24.10.0"
PRETTY_NAME="OpenWrt 24.10.0"
===SEC:ENV===
UNAME:Linux 6.6.73 x86_64
PROC_VER:Linux version 6.6.73 (builder@buildhost)
UID:0
SUDO:ROOT
SHELL:/bin/ash|/bin/busybox|
INIT:/sbin/procd
FW:/usr/sbin/fw4 /usr/sbin/nft
PM:/usr/bin/apk
===SEC:HW===
MemTotal:         128000 kB
MemAvailable:      64000 kB
---DF---
Filesystem           1M-blocks      Used Available Use% Mounted on
overlayfs:/overlay          64        52        12  81% /
---MOUNTS---
/dev/mtdblock5 /rom squashfs ro,relatime 0 0
===SEC:REBOOT===
NO
===SEC:PKGS===
FMT:APK
dnsmasq-full-2.90-r2 x86_64 {feeds/base/dnsmasq} (GPL-2.0) [installed]
===SEC:BINS===
__BIN__:sing-box:sing-box version 1.11.4
===SEC:MITIGATIONS===
__APPLIED__:CVE_2025_11111
`
	var inv model.HostInventory
	inv.Packages = make(map[string]string)
	inv.AppliedMitigations = make(map[string]string)
	inv.DockerContainers = make(map[string]string)

	parseMergedLinuxProbeOutput(openwrtOut, model.HostTarget{Name: "gw", SSHHost: "root@gw"}, &inv)

	if inv.OSContext.OSFamily != "openwrt" || inv.OSContext.PkgMgr != "apk" {
		t.Fatalf("unexpected OpenWrt context: %+v", inv.OSContext)
	}
	if !inv.OSContext.LockdownMode {
		t.Fatal("expected OpenWrt Flash overlay 12MB < 30MB to trigger anti-brick lockdown")
	}
	if inv.Packages["dnsmasq-full"] != "2.90-r2" || inv.Packages["sing-box"] != "1.11.4" {
		t.Fatalf("unexpected packages: %+v", inv.Packages)
	}
	if inv.AppliedMitigations["CVE-2025-11111"] != "APPLIED" {
		t.Fatalf("expected applied mitigation marker, got %+v", inv.AppliedMitigations)
	}
}

func TestParseAppleRecommendedUpdatesXML(t *testing.T) {
	sample := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<array>
	<dict>
		<key>Display Name</key>
		<string>macOS 15.4.1</string>
		<key>Display Version</key>
		<string>15.4.1</string>
		<key>Identifier</key>
		<string>MSU_UPDATE_PATCH</string>
		<key>MobileSoftwareUpdate</key>
		<true/>
	</dict>
</array>
</plist>`
	items := parseAppleRecommendedUpdatesXML(sample)
	if len(items) != 1 || items[0]["Display Version"] != "15.4.1" || items[0]["MobileSoftwareUpdate"] != "true" {
		t.Fatalf("unexpected Apple SoftwareUpdate plist parse: %+v", items)
	}
}
