# Changelog

## [2.7.5] - 2026-11-11

### Security, Reliability & UX Enhancements

* **vault-encryption (零钥匙串弹窗本机加密保险箱):** 将凭据持久化存储从 macOS 传统钥匙串 (`SecItem*` / `/usr/bin/security`) 升级为**本机硬件指纹绑定的 AES-256-GCM + HKDF-SHA256 加密保险箱** (`~/.config/sentinel/vault.enc`, `0600`)。彻底解决因 Ad-hoc 签名应用热更新后 `CDHash` 变化及 CLI/GUI 双二进制 ACL 不一致导致的频繁弹出「想要使用您的机密信息 / 输入登录钥匙串密码」弹窗问题，并支持旧凭据一次性静默迁移与旧钥匙串条目自动清理。
* **latency-and-scan-speedup (主机延迟解耦与本机极速并发采集):** 修复将「全量资产采集总耗时」误记为「主机网络延迟 (`LatencyMS`)」以及锁屏后台触发 macOS TCC 文稿目录授权挂起导致本机延迟飙升至数万~两百万毫秒的缺陷。现已严格拆分网络 RTT 延迟（本机直连恒为 `0ms`，远端主机基于 SSH ControlMaster 测量真实毫秒级 RTT）与采集耗时 (`ScanDurationMS`)；新增锁屏 TCC 15 秒无阻塞超时护栏、macOS 五层资产并发采集及 `HOMEBREW_NO_AUTO_UPDATE=1` 静默加速，本机全量扫描由 `15.0s` 提速至 `1.0s`。
* **telegram-delivery-and-schedule (推送上下文隔离与每日双点准时巡检):** 解耦巡检扫描上下文与 Telegram 推送上下文（独立 35s/25s 超时预算 + 网络瞬断自动重试），根治因前序扫描超时取消连带吞掉 Telegram 通报的问题；新增 **`twice_daily`（每日双点巡检，锚定 `00:00` 与 `12:00`）** 调度模式，彻底消除传统定频间隔 (`interval`) 因中途手动重扫而引发的排期顺延漂移。
* **daily-cve-today-delta (每日最新 CVE「今日」窗口与增量去重推送):** 将「每日最新 CVE」时间窗口由「昨今两日」收敛为严格的本地自然日 **「今日 (`00:00~23:59`)」**（`FilterAdvisoriesToday`）；优化自动日报推送账本 (`SentIDs`)，每日首次命中推送完整 `今日` 情报，同日后续巡检仅推送 `今日新增` 增量 CVE，今日无披露或无新增时保持静默零打扰。

## [2.7.4] - 2026-11-10

### Performance & Features

* **gui-120fps:** 为凭据读取引入内存缓存，并为漏洞手术台、每日 CVE 列表、五层资产浏览器与托盘图标引入按需脏检查与派生缓存，根治 GUI 渲染卡顿。
* **ai-and-ha-gateway:** 支持自由配置 OpenAI / Anthropic / Gemini / agy 兼容网关 (`BaseURL` + 网关 Token + 一键连通性测试)，重构软路由 Clash/Sing-box 可视化切流面板，并支持在更新弹窗中完整展示中文更新日志。

## [2.7.3] - 2026-11-10

### Features

* **self-updater-ui:** 新增全局新版本自动检测、菜单栏与主界面一键热更新提示横幅及版本更新说明弹窗。

## [2.7.2] - 2026-11-10

### Features & Bug Fixes

* **workspace-diagnostics:** replace generic upgrade warning banner with fine-grained root-cause classification (`DiagnoseWorkspaceUpgradeOutcome`). Accurately distinguish 5 failure modes: (1) Major-version SemVer boundary locks (`需跨大版本 v2➔v4`), (2) Transitive sub-dependencies locked by parent packages (`间接依赖·跨大版本被锁死`), (3) Peer dependency / solver conflicts masked by `||` fallbacks (`ERESOLVE` / `ResolutionImpossible` / Go v2+ import path mismatch), (4) Unfixed upstream 0-day advisories (`官方未出补丁`), and (5) Registry/network timeouts, providing ecosystem-specific remediation advice (`package.json` `overrides`, Go `/vN` import paths, `pyproject.toml` constraints).
* **workspace-ui-prehints:** display pre-upgrade diagnostic badges (`需跨大版本`, `间接依赖`, `官方未出补丁`) directly on project dependency cards in both GUI and CLI (`sectl ws`), and disable the single-package upgrade button (`暂无补丁`) when no upstream fix version exists yet.

## [2.7.1] - 2026-11-10

### Bug Fixes

* **auditor-multistack:** isolate package managers in hybrid multi-stack projects (e.g. Go desktop GUI containing Python `.venv` worker scripts). Bind `ManifestKind` per dependency to eliminate cross-ecosystem upgrade contamination (such as mistakenly using `go get` to upgrade Python packages like `pillow`), composite project badges (`gomod+venv`), and add safety guardrails against running `go get` on non-Go package paths.

## [2.7.0] - 2026-11-05

### Features

* **panorama-5layer:** unify 5-layer host introspection across macOS & Linux — Homebrew (`Formulae` + `Casks`), macOS `/Applications`, Docker/OrbStack/Colima/Podman (`ServerVersion` + running containers + local images), global toolchains (`npm -g`, `bun`, `cargo install`, `uv`, `pyenv`, `conda`, `rustup`, `sdkman`, `mise`), and clickable Panorama Asset Explorer (`sectl assets` & GUI modal)
* **exemption-ux:** strip cross-generational Apple `_major` OS upgrades from security vulnerability counts, and add 3-tier `Skip-Version` / `Snooze 30d` / `Permanent Mute` controls (`sectl mute` / `sectl unmute` & GUI Triage `已豁免/暂缓` manager)

## [2.6.0] - 2026-11-05

### Features

* **cve-radar:** add dedicated Daily Latest CVE Intelligence Center (`sectl cve` & native GPU `每日最新 CVE` page) with multi-dimensional filtering across Language Ecosystems (GHSA), OS Distributions (Debian DSA / Ubuntu USN / Red Hat), Linux Kernel (NIST NVD 2.0), and Importance (`CRITICAL` / `HIGH` / `MEDIUM`)
* **telegram-digest:** push standalone categorized Daily CVE Digest cards to Telegram (`sectl cve --push`, GUI 1-click push, and automated daily digest with duplicate suppression)
* **arch:** organize `internal/` into 5 unidirectional domain layers (`infra`, `scan`, `heal`, `ops`, `app`)
* **workspace:** 6-worker Go concurrent dependency upgrades (`uv pip` + native Maven/Gradle `~/.m2` transitive POM resolver + safe OS Trash cleaner)
* **desktop:** native MyGo GPU Menu Bar Sentinel (`⌘⇧S`) + Mission Control (`DiffViewer`, OS Keychain vault, smart WezTerm tab launcher, streaming `~/.ssh/config` host discovery, and in-app visual scheduler)
