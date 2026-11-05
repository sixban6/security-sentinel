package patch

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/transport"
)

const RemoteRemediationDir = "/etc/sentinel/remediations"

var safeIDRe = regexp.MustCompile(`[^A-Za-z0-9_\-]`)

func SafeCVEToken(cveID string) string {
	s := safeIDRe.ReplaceAllString(strings.TrimSpace(cveID), "_")
	if s == "" {
		return "UNKNOWN_CVE"
	}
	return s
}

// ApplyOSPlan executes a host's OSSecurity RemediationPlan safely via its HostTarget executor.
func ApplyOSPlan(ctx context.Context, target model.HostTarget, plan model.RemediationPlan) (ok bool, output string) {
	if !plan.SafeToExecute {
		return false, plan.Warning
	}
	if len(plan.Commands) == 0 {
		return true, "无待执行更新命令"
	}
	exec := transport.New(target)
	combined := strings.Join(plan.Commands, " && ")
	res, err := exec.Run(ctx, combined, 240*time.Second)
	if err != nil {
		return false, fmt.Sprintf("执行异常: %v (%s)", err, res.Stderr)
	}
	if res.Code != 0 {
		msg := res.Stderr
		if msg == "" {
			msg = res.Stdout
		}
		return false, fmt.Sprintf("退出码 %d: %s", res.Code, msg)
	}
	return true, res.Stdout
}

// DeployAndExecuteMitigation safely transfers base64-encoded mitigation & rollback scripts
// (100% immune to quote/heredoc injection), executes mitigation, probes multi-endpoint connectivity,
// and triggers automatic instant rollback if network connectivity drops!
func DeployAndExecuteMitigation(
	ctx context.Context,
	target model.HostTarget,
	osCtx model.OSContext,
	cveID string,
	mitigateScript string,
	rollbackScript string,
	strategy string,
	mem *store.Store,
) (ok bool, message string, rolledBack bool) {
	safeCVE := SafeCVEToken(cveID)
	mitPath := fmt.Sprintf("%s/%s_mitigate.sh", RemoteRemediationDir, safeCVE)
	rbPath := fmt.Sprintf("%s/%s_rollback.sh", RemoteRemediationDir, safeCVE)

	mitB64 := base64.StdEncoding.EncodeToString([]byte(mitigateScript + "\n"))
	rbB64 := base64.StdEncoding.EncodeToString([]byte(rollbackScript + "\n"))
	quotedCVE := transport.ShellQuote(cveID)
	quotedStrat := transport.ShellQuote(strategy)

	runnerScript := fmt.Sprintf(`set -e
REM_DIR=%s
mkdir -p "$REM_DIR"
printf '%%s' %s | base64 -d > %s
chmod 750 %s
printf '%%s' %s | base64 -d > %s
chmod 750 %s

echo "[*] Applying mitigation: %s"
%s

test_network() {
  curl -I -s --connect-timeout 4 --max-time 6 https://www.cloudflare.com >/dev/null 2>&1 || \
  curl -I -s --connect-timeout 4 --max-time 6 https://www.google.com >/dev/null 2>&1 || \
  ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 || \
  ping -c 2 -W 3 8.8.8.8 >/dev/null 2>&1 || \
  ping -c 2 -W 3 223.5.5.5 >/dev/null 2>&1
}

if ! test_network; then
  echo "[AUTO_ROLLBACK_TRIGGERED] Network probe failed; rolling back immediately!"
  %s
  printf '[%%s] ROLLED_BACK: %%s (Network failure)\n' "$(date '+%%Y-%%m-%%d %%H:%%M:%%S')" %s >> "$REM_DIR/history.log"
  exit 99
fi

printf '%%s\n' %s > "$REM_DIR/%s.applied"
printf '[%%s] APPLIED: %%s (%%s)\n' "$(date '+%%Y-%%m-%%d %%H:%%M:%%S')" %s %s >> "$REM_DIR/history.log"
echo "STATUS: MITIGATION_SUCCESSFUL"
`,
		transport.ShellQuote(RemoteRemediationDir),
		transport.ShellQuote(mitB64), transport.ShellQuote(mitPath), transport.ShellQuote(mitPath),
		transport.ShellQuote(rbB64), transport.ShellQuote(rbPath), transport.ShellQuote(rbPath),
		mitPath,
		transport.ShellQuote(mitPath),
		transport.ShellQuote(rbPath),
		quotedCVE,
		quotedCVE, safeCVE,
		quotedCVE, quotedStrat,
	)

	remoteShell := "sh -s"
	if !osCtx.IsRoot {
		if osCtx.CanSudoNoPass {
			remoteShell = "sudo -n sh -s"
		} else {
			return false, "目标主机非 root 用户且未开启免密 sudo，无法写入 /etc/sentinel/remediations", false
		}
	}

	exec := transport.New(target)
	res, err := exec.RunStdin(ctx, remoteShell, runnerScript, 45*time.Second)
	hostKey := target.EffectiveKey()

	if res.Code == 99 || strings.Contains(res.Stdout, "[AUTO_ROLLBACK_TRIGGERED]") {
		msg := "加固后网络探活失败，已自动执行回滚脚本恢复网络"
		if mem != nil {
			mem.RecordRemediation(model.RemediationRecord{
				HostKey:      hostKey,
				HostName:     target.Name,
				CVEID:        cveID,
				Kind:         "ai_workaround",
				Status:       "reverted",
				Strategy:     strategy,
				ScriptPath:   mitPath,
				RollbackPath: rbPath,
				Log:          msg,
			})
		}
		return false, msg, true
	}

	if err != nil {
		msg := fmt.Sprintf("SSH 传输异常: %v", err)
		if mem != nil {
			mem.RecordRemediation(model.RemediationRecord{
				HostKey:  hostKey,
				HostName: target.Name,
				CVEID:    cveID,
				Kind:     "ai_workaround",
				Status:   "transient_error",
				Log:      msg,
			})
		}
		return false, msg, false
	}

	if res.Code == 0 {
		msg := fmt.Sprintf("已归档至 %s 并通过网络健康自检", mitPath)
		if mem != nil {
			mem.RecordRemediation(model.RemediationRecord{
				HostKey:      hostKey,
				HostName:     target.Name,
				CVEID:        cveID,
				Kind:         "ai_workaround",
				Status:       "success",
				Strategy:     strategy,
				ScriptPath:   mitPath,
				RollbackPath: rbPath,
				CanRollback:  true,
				Log:          msg,
			})
		}
		return true, msg, false
	}

	errText := res.Stderr
	if errText == "" {
		errText = res.Stdout
	}
	msg := fmt.Sprintf("脚本执行异常 (code %d): %s", res.Code, errText)
	if mem != nil {
		mem.RecordRemediation(model.RemediationRecord{
			HostKey:  hostKey,
			HostName: target.Name,
			CVEID:    cveID,
			Kind:     "ai_workaround",
			Status:   "verification_failed",
			Log:      msg,
		})
	}
	return false, msg, false
}

// RollbackMitigation executes the archived <CVE>_rollback.sh on the target host, removes the .applied marker,
// and records the manual rollback in the local Time-Machine ledger.
func RollbackMitigation(
	ctx context.Context,
	target model.HostTarget,
	osCtx model.OSContext,
	cveID string,
	mem *store.Store,
) (bool, string) {
	safeCVE := SafeCVEToken(cveID)
	altCVE := strings.ReplaceAll(safeCVE, "-", "_")
	quotedCVE := transport.ShellQuote(cveID)

	rbRunner := fmt.Sprintf(`set -e
REM_DIR=%s
RB_SCRIPT="$REM_DIR/%s_rollback.sh"
if [ ! -f "$RB_SCRIPT" ]; then
  RB_SCRIPT="$REM_DIR/%s_rollback.sh"
fi
if [ ! -f "$RB_SCRIPT" ]; then
  echo "ERR_NO_ROLLBACK_SCRIPT"
  exit 44
fi
"$RB_SCRIPT"
rm -f "$REM_DIR/%s.applied" "$REM_DIR/%s.applied"
printf '[%%s] ROLLED_BACK_MANUAL: %%s\n' "$(date '+%%Y-%%m-%%d %%H:%%M:%%S')" %s >> "$REM_DIR/history.log"
echo "ROLLBACK_OK"
`,
		transport.ShellQuote(RemoteRemediationDir),
		safeCVE, altCVE,
		safeCVE, altCVE,
		quotedCVE,
	)

	remoteShell := "sh -s"
	if !osCtx.IsRoot && !target.IsLocal() {
		if osCtx.CanSudoNoPass {
			remoteShell = "sudo -n sh -s"
		} else {
			return false, "非 root 用户且未开启免密 sudo，无法执行 /etc/sentinel/remediations 回滚脚本"
		}
	}

	exec := transport.New(target)
	res, err := exec.RunStdin(ctx, remoteShell, rbRunner, 35*time.Second)
	if res.Code == 44 || strings.Contains(res.Stdout, "ERR_NO_ROLLBACK_SCRIPT") {
		return false, fmt.Sprintf("目标主机未找到 %s 对应的归档回滚脚本", cveID)
	}
	if err != nil || res.Code != 0 {
		errMsg := res.Stderr
		if errMsg == "" {
			errMsg = res.Stdout
		}
		return false, fmt.Sprintf("回滚执行失败 (code %d): %v %s", res.Code, err, errMsg)
	}

	msg := fmt.Sprintf("已成功执行 %s 回滚脚本并清理生效标记", cveID)
	if mem != nil {
		mem.RecordRemediation(model.RemediationRecord{
			HostKey:  target.EffectiveKey(),
			HostName: target.Name,
			CVEID:    cveID,
			Kind:     "rollback",
			Status:   "rolled_back_manual",
			Log:      msg,
		})
	}
	return true, msg
}
