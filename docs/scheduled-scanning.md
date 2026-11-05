# ⏰ 定时巡检与自动化守护指南 (Scheduled Scanning & Automation)

> 全自动安全巡检的核心在于“无需人工干预、定期自主研判、高危即时告警”。
> 本文详解如何在 macOS 与 Linux 环境下配置生产级定时任务，实现每日全网 CVE 抓取、集群资产探测、AI 自愈与双端通知。

---

## 1. 设计哲学：为什么无常驻守护进程？

`security-sentinel` 遵循轻量高效的 Unix 哲学设计：
- **零常驻内存开销**：不维持常驻后台 Daemon 占用 CPU 与内存；
- **按需唤醒、极速审计**：单次 `audit` 任务在 5~15 秒内并发完成全网情报拉取、多机 SSH 探针采集与三态分析；
- **安全快速退出**：状态落盘并发送 macOS/Telegram 告警后立即释放所有资源。

因此，最优雅、稳健的自动化运行方式是配合 **操作系统原生调度工具**（macOS `launchd` / Linux `cron` 或 `systemd`）或 **AI Agent 调度**。

---

## 2. ⚡ 极速一键配置（最推荐，零门槛）

为了彻底免去手动编写复杂 XML 或编辑 crontab 的心智负担，系统原生支持将任何 `audit` 巡检命令直接设定为定时计划：

### 2.1 方式一：直接对 `audit` 命令追加 `--schedule`（最自然直观 🌟）

无需额外思考复杂的子命令，将您想要运行的 `audit` 参数搭配 `--schedule` 即可一键固化为系统定时计划：

```bash
# 1. 每天上午 9 点整自动巡检
security-sentinel audit --schedule "0 9 * * *"

# 2. 搭配平滑滚动重启与 AI 自愈，在工作日早晨 08:30 自动执行
security-sentinel audit --auto-reboot --ai-heal --schedule "30 8 * * 1-5"

# 3. 每 4 小时整点巡检一次
security-sentinel audit --auto-reboot --schedule "0 */4 * * *"
```

### 2.2 方式二：使用 `schedule` 管理指令

```bash
# 传入 crontab 表达式或具体时间即可（无需冗余参数）
security-sentinel schedule "0 9 * * *"
security-sentinel schedule 09:00

# 明确指定目标是 audit 任务
security-sentinel schedule audit "30 8 * * 1-5"
```

### 2.3 查看任务状态
```bash
security-sentinel schedule
# 或
security-sentinel schedule --status
```
输出示例：
```text
⏰ 当前生效的定时任务 [macOS LaunchAgent]:
  • 状态: 运行就绪 (已加载)
  • 执行规则: 每日 09:00 (0 9 * * *) (Cron: 0 9 * * *)
  • 任务标识: com.security.sentinel.audit
  • 配置文件: ~/Library/LaunchAgents/com.security.sentinel.audit.plist
```

### 2.4 随时一键卸载
```bash
security-sentinel schedule --uninstall
```

---

## 3. 手动配置：macOS `launchd` 深度解析 (原理说明)

> [!TIP]
> **为什么在 macOS 上推荐 `launchd` 而非传统 `crontab`？**
> 1. **通知权限保障**：现代 macOS（Sonoma / Sequoia 等）对传统 `crontab` 限制了 GUI Session 交互，`cron` 触发的 AppleScript 原生横幅通常会被系统静默丢弃；而 LaunchAgent 运行在用户登录桌面会话下，**可 100% 正常弹出右上角通知中心横幅**。
> 2. **休眠智能补跑**：若电脑在预定时间处于合盖或休眠状态，macOS 唤醒后 `launchd` 会自动侦测并立即补跑错过的巡检任务。

### 步骤一：创建 LaunchAgent 配置文件

在终端执行以下命令，创建用户级任务定义：

```bash
mkdir -p ~/Library/LaunchAgents
cat << 'EOF' > ~/Library/LaunchAgents/com.security.sentinel.audit.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.security.sentinel.audit</string>

    <key>ProgramArguments</key>
    <array>
        <!-- 使用登录 Shell 包装执行，确保加载用户环境变量与 PATH -->
        <string>/bin/zsh</string>
        <string>-l</string>
        <string>-c</string>
        <string>security-sentinel audit --auto-reboot</string>
    </array>

    <!-- 定时策略：每天早上 08:30 自动执行一次 -->
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>8</integer>
        <key>Minute</key>
        <integer>30</integer>
    </dict>

    <!-- 标准输出与错误日志文件 (请将 /Users/yourname 替换为您的实际用户目录) -->
    <key>StandardOutPath</key>
    <string>/Users/yourname/.local/state/sentinel/launchd.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/yourname/.local/state/sentinel/launchd_err.log</string>

    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
EOF
```

> [!NOTE]
> 推荐使用 `security-sentinel schedule "0 8 * * *"` 自动生成包含您当前绝对路径的 LaunchAgent 文件，无需手工替换路径。

### 步骤二：加载并激活定时任务

```bash
# 1. 确保日志目录存在
mkdir -p ~/.gemini/logs/security_audit

# 2. 注册并激活任务
launchctl load -w ~/Library/LaunchAgents/com.security.sentinel.audit.plist

# 3. (可选) 立即手动触发一次以验证配置
launchctl start com.security.sentinel.audit
```

### 步骤三：常用管理命令

```bash
# 查看任务运行状态与最后退出代码
launchctl list | grep sentinel

# 停止并卸载任务
launchctl unload ~/Library/LaunchAgents/com.security.sentinel.audit.plist
```

---

## 3. Linux / 通用环境推荐：`crontab`

对于云服务器、Linux 研发机或边缘路由器，使用系统原生 `crontab` 最为简单直接。

### 避坑指南：Crontab 环境变量隔离
`cron` 在独立且极简的非交互式 Shell 中执行，**不会自动读取 `~/.zshrc` 或 `~/.bashrc` 中的环境变量**（例如 `PATH`、`TELEGRAM_BOT_TOKEN`、`TELEGRAM_CHAT_ID`）。

### 标准规范配置

编辑当前用户的 crontab：
```bash
crontab -e
```

在末尾添加以下内容（**显式补齐 PATH 并导入环境变量**）：

```cron
# 每日早晨 08:00 自动执行 Security-Sentinel 全网巡检并推送告警
0 8 * * * export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"; [ -f "$HOME/.zshrc" ] && source "$HOME/.zshrc" >/dev/null 2>&1; security-sentinel audit --auto-reboot >> "$HOME/.gemini/logs/security_audit/cron.log" 2>&1
```

> [!TIP]
> 如果您将 Telegram 配置写在单独的文件（如 `~/.config/sentinel/env`），可直接在 cron 中 source 该文件：
> ```cron
> 0 8 * * * export PATH="$HOME/.local/bin:$PATH"; . ~/.config/sentinel/env; security-sentinel audit --auto-reboot >> ~/.gemini/logs/security_audit/cron.log 2>&1
> ```

---

## 4. Linux 生产环境：`systemd.timer` (可选)

在 systemd 主导的 Linux 发行版（Debian / Ubuntu / Arch）上，使用用户级 `systemd.timer` 可以获得毫秒级调度精度、依赖管理与 `journalctl` 结构化日志追踪。

### 1. 创建 Service 单元
文件路径：`~/.config/systemd/user/security-sentinel.service`
```ini
[Unit]
Description=Security-Sentinel Daily Vulnerability Audit
After=network-online.target

[Service]
Type=oneshot
Environment="PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=-%h/.config/sentinel/env
ExecStart=%h/.local/bin/security-sentinel audit --auto-reboot
StandardOutput=journal
StandardError=journal
```

### 2. 创建 Timer 定时单元
文件路径：`~/.config/systemd/user/security-sentinel.timer`
```ini
[Unit]
Description=Run Security-Sentinel Daily at 08:00 AM

[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

### 3. 启用并启动
```bash
systemctl --user daemon-reload
systemctl --user enable --now security-sentinel.timer

# 查看下一次执行倒计时
systemctl --user list-timers
```

---

## 5. Google `agy` (Antigravity CLI) 智能体调度

如果您已在本地安装了 Google Antigravity CLI 并挂载了 Sentinel 技能（详见 [agy 联动指南](agy-integration.md)），无需手动编写任何系统脚本，直接向 AI 智能体下达自然语言调度指令：

```text
/schedule "0 8 * * *" 运行 security-sentinel audit --auto-reboot，完成每日早间安全巡检与双端播报
```

AI 智能体将接管全生命周期监控，并在检测到未免疫高危漏洞时自动进入深度推理与动态自愈流程。

---

## 6. 定时任务健康检查清单

在部署定时任务后，建议根据以下清单快速排查：

| 检查项 | 验证命令 / 检查方法 | 常见故障与解法 |
| :--- | :--- | :--- |
| **可执行文件寻址** | `which security-sentinel` | 确保定时配置中使用的路径正确（通常为 `$HOME/.local/bin/security-sentinel`） |
| **SSH 密钥免密** | `ssh user@host "hostname"` | 确保目标主机能免密登录；cron 执行时不会弹出密码提示输入框 |
| **Telegram 通知** | 检查 `TELEGRAM_BOT_TOKEN` | 确保 cron 或 launchd 环境中能够读取到 Telegram 环境变量 |
| **macOS 屏幕通知** | 观察屏幕右上角横幅 | 若未弹出，首选采用本文推荐的 `launchd` 方案运行 |
| **最新状态落盘** | `security-sentinel status` | 验证 `~/.gemini/logs/security_audit/latest_status.json` 是否准时更新 |
