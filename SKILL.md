---
name: security-sentinel
description: >-
  Proactively monitors, audits, and remediates security vulnerabilities (CVEs/GHSAs/OSV)
  across multi-host SSH clusters (macOS, Debian/Ubuntu, RHEL, Alpine, OpenWrt), Linux kernels,
  Docker containers, and local project lockfiles (.venv, npm/pnpm/yarn, go.mod, Cargo.lock).
  Use this skill whenever asked to check machine safety, run a security audit, diagnose SSH cluster
  security posture, apply safe OS security patches, or roll back mitigations.
---

# Security-Sentinel v2.1 (`sectl`): 多主机主动安全巡检与零中断自愈技能

本技能驱动纯 Go 编写的 `sectl`（兼容别名 `security-sentinel`）引擎，结合 **Google OSV 全量存量库 + GitHub GHSA + kernel.org Linux CNA 多 LTS 分支流**，对本机开发工作区与远程 SSH 服务器集群实施精准无误报的漏洞排查与闭环修复。

---

## 1. 标准执行工作流

1. **环境与连通性体检（首次或排障时）**：
   ```bash
   sectl doc
   ```
2. **执行全集群安全只读巡检**：
   ```bash
   # 默认 100% 安全只读，输出集群健康分 (0-100) 与各主机风险明细
   sectl audit

   # 需要机器可读 JSON 明细时：
   sectl audit --json
   ```
3. **预览并应用官方系统安全补丁（含防级联卸载与 OpenWrt 闪存防变砖熔断）**：
   ```bash
   # 先用 --dry-run 预览拟执行命令
   sectl fix --dry-run

   # 确认无误后定向升级并平滑热载服务
   sectl fix
   ```
4. **AI 无补丁漏洞现场规避与一键回滚**：
   ```bash
   # 针对暂无上游二进制补丁的系统/内核高危漏洞，启动 AI 可行性门禁与双脚本加固（断网秒级自动回滚）
   sectl audit --ai-heal

   # 查看历史加固账本或随时一键远程回滚
   sectl rb --list
   sectl rb --host <主机名> --cve <CVE编号>
   ```
5. **零中断平滑滚动重启（当升级内核出现 `/var/run/reboot-required` 时）**：
   ```bash
   sectl rs --auto
   ```
6. **导出可视化单文件 HTML 审计战报**：
   ```bash
   sectl rep --html sentinel_report.html
   ```

---

## 2. 核心安全准则

1. **CVE 编号强溯源**：向用户汇报任何风险或修复结果时，必须明确列出具体的 `CVE-*` / `GHSA-*` 编号、受影响包名及版本区间，严禁只写模糊描述。
2. **默认只读不越权**：未获用户授权或配置显式开启前，优先使用 `audit` 或 `fix --dry-run` 展示变更处方；对 macOS Homebrew 升级严格携带 `HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1`，对 OpenWrt 严格遵守内存 `<32MB` 与 Overlay `<30MB` 防变砖熔断锁。
3. **临时规避生命周期闭环**：若巡检报告提示某项 `RetirableMitigations`（官方内核/软件包补丁已就位），主动提醒并协助用户执行 `security-sentinel rollback` 清理过时的临时规避脚本。
