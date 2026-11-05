# 🤖 Google `agy` (Antigravity CLI) 智能体联动实战 (AI Agent Integration)

> 将 Security-Sentinel 注册为 Google Antigravity CLI 的系统级能力，实现由 AI 驱动的全网安全感知与自主闭环自愈。

---

## 1. 什么是 Google `agy` CLI？

Google Antigravity CLI (`agy`) 是下一代 AI-first 的智能体命令行工具。它允许大语言模型拥有终端执行、文件读写、工具链调用与自主长任务闭环能力。
当 `agy` 与 `security-sentinel` 结合后，AI 即可直接调动 Sentinel 的全网漏洞情报源、多主机资产探针与零中断自愈流水线。

---

## 2. 一键挂载为 `agy` 系统级技能 (Skill)

在终端中执行以下命令，将当前项目目录软链接至 `agy` 的技能发现目录：

```bash
# 创建 agy 全局技能目录
mkdir -p ~/.gemini/config/skills

# 将 security-sentinel 挂载为技能
ln -sf "$(pwd)" ~/.gemini/config/skills/security-sentinel
```

挂载完成后，`agy` 在启动时会自动加载根目录下的 [`SKILL.md`](../SKILL.md)，全面掌握集群拓扑结构与安全处置规范。

---

## 3. 自然语言交互场景

挂载技能后，您无需记住复杂的命令行参数，直接在终端中用自然语言对 `agy` 说话：

### 场景 1：日常自动化巡检与双端通报
```bash
agy "执行今日全主机安全巡检，如有风险自动自愈并推送通知"
```
AI 会自动调用 `security-sentinel audit`，检查近 3 天全网高危漏洞，采集所有机器资产并向 macOS 与 Telegram 推送结果。

### 场景 2：定向 CVE 排查与动态修复
```bash
agy "排查集群是否受 CVE-2026-98432 影响，若命中则结合机器现状动态生成补丁方案"
```
AI 会结合内核多分支研判算法，排查每台机器的运行内核，并在确认命中时生成安全升级命令。

### 场景 3：Docker 容器与关键服务审计
```bash
agy "检查云端服务器上的 Sub-Store 与 Caddy 镜像版本，排查有无已知提权风险"
```

---

## 4. 结合 `agy` 进阶斜杠命令 (Slash Commands)

### 🌟 `/goal`：长任务超视距自主闭环
当面临复杂加固任务（例如多台 VPS 需滚动升级内核、重新编译依赖并切流验证）时，推荐使用 `/goal`：
```text
/goal 对 sentinel.yaml 中配置的所有主机执行全盘加固，核实所有 CVE 影响区间，并在不中断网络的前提下完成滚动自愈
```
`agy` 将进入长任务执行模式，自主拆解子任务、串行重启服务器、验证连通性直至完全免疫，绝不提前终止。

### ⏰ `/schedule`：早间定时巡检守护
无需手动配置复杂的 crontab，直接让 `agy` 设置每日定时巡检：
```text
/schedule "0 8 * * *" 运行 security-sentinel audit --auto-reboot，完成每日早间安全巡检与双端播报
```

### 📋 `/plan`：重大安全变更是前的方案对齐
在生产环境进行跨大版本内核升级或核心代理重构前，输入：
```text
/plan 对云端 3 台服务器升级内核并验证平滑切流回滚机制
```
AI 会先输出详细的 step-by-step 实施与回滚方案供您审核确认。

---

## 5. 增强特性：AI 智能体无补丁漏洞现场规避 (AI Remediation)

很多高危漏洞（特别是 Linux 内核 UAF、缓冲区溢出或协议栈竞态）在官方 CVE 公布后，**各大 Linux 发行版（Debian / Ubuntu / OpenWrt 等）通常需要数天甚至数周才会打包发布最新内核升级包**。

在此期间，系统处于“已知风险但官方无补丁可打”的危险暴露窗口期。

### 5.1 工作机制

Security-Sentinel 内置了由 Google `agy` 驱动的现场加固引擎 (`sentinel/ai_remediator.py`)：

```mermaid
flowchart TD
    Vuln["💥 检测到高危漏洞 (如 CVE-2026-98432)<br/>官方发行版软件包尚未发版"] --> CheckCfg{"检查 YAML<br/>ai_remediation.enabled"}
    CheckCfg -->|false (默认)| Manual["输出 CVE 详情供人工跟踪"]
    CheckCfg -->|true| CheckAgy{"检测本机 Google agy CLI<br/>(which agy)"}
    CheckAgy -->|未安装| Warn["⚠️ 友好告警提示缺少 agy 并跳过"]
    CheckAgy -->|就绪| GeminiCall["🧠 调用 agy -p (Gemini 3.8 Flash High)<br/>深度推理漏洞利用机制与规避策略"]
    GeminiCall --> ScriptGen["📝 自动生成幂等加固脚本与探活命令<br/>(例如: sysctl net.ipv4.tcp_syncookies=2 & 持久化)"]
    ScriptGen --> ExecCheck{"auto_execute: true<br/>或 --ai-heal"}
    ExecCheck -->|false| Review["终端展示方案与脚本供人工审核"]
    ExecCheck -->|true| SSHExec["🚀 SSH 远程下发脚本 + 探活验证"]
    SSHExec --> Result["✅ 状态标记为 [已经免疫] 并推送通知"]
```

### 5.2 配置开关 (`sentinel.yaml`)

作为进阶增强特性，该功能在开源模板中默认关闭，用户可根据需要随时开启：

```yaml
# 4. 可选：AI 智能体无补丁漏洞现场规避
ai_remediation:
  enabled: true                    # 是否开启 AI 现场规避 (默认 false)
  model: "gemini-3.8-flash-high"   # 调用本地 agy 的 AI 模型 (推荐 gemini-3.8-flash-high)
  auto_execute: false              # true: 自动下发执行; false: 终端展示方案供审核
```

### 5.3 命令行按需触发

您也可以在日常巡检中通过 CLI 参数临时激活：

```bash
# 执行巡检并激活 AI 自动推理与自愈
security-sentinel audit --ai-heal

# 指定不同的 AI 模型进行推理
security-sentinel audit --ai-heal --ai-model gemini-3.8-flash-high
```

### 5.4 目标机器脚本持久化、断网自动回滚与 AI 自我纠错重构

为保障高可用生产环境的绝对安全与透明可溯源，系统设计了闭环的加固与回滚安全屏障：

1. **统一双脚本归档 (`/etc/sentinel/remediations/`)**：
   - **加固脚本**：`/etc/sentinel/remediations/<CVE_ID>_mitigate.sh` (权限 `750`，包含完整的参数持久化逻辑)
   - **回滚脚本**：`/etc/sentinel/remediations/<CVE_ID>_rollback.sh` (权限 `750`，永久保留，方便管理员随时**手动一键回滚**)
2. **目标机本地网络健康探活**：
   - 脚本执行后，目标机立即自主对公共 DNS / 全球 CDN (Cloudflare, Google, 阿里 DNS) 进行实时网络连通性探活。
3. **断网自动急停与秒级回滚**：
   - 若加固脚本引发网络断流或丢包，目标机本地守护逻辑**立即自动触发回滚脚本**，秒级恢复网络通信，彻底杜绝服务器因加固变砖断联的隐患。
4. **大模型自我诊断与二次重构自愈**：
   - 探活感知到断网并完成回滚后，Sentinel 会将故障上下文与失败日志反馈给 Gemini，自动诊断导致断网的根因参数，重新生成兼顾安全与网络畅通的修正版加固脚本并二次重试！
5. **审计日志与全端通知**：
   - 所有执行与回滚动作自动记录在 `/etc/sentinel/remediations/history.log`；
   - 无论是加固成功、自动回滚还是 AI 二次纠错，全量原因均 100% 显式汇报至终端、macOS 通知栏与 Telegram。



