package ha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
	"github.com/sixban6/security-sentinel/internal/infra/transport"
)

// EventSink receives real-time progress events during rolling reboot & gateway failover.
type EventSink func(ev model.HAProgressEvent)

// Manager orchestrates Clash/Mihomo traffic draining, serial rolling reboots, and gateway reloads.
type Manager struct {
	Cfg    config.Config
	HTTP   *http.Client
	OnStep EventSink
}

func NewManager(cfg config.Config, onStep EventSink) *Manager {
	return &Manager{
		Cfg:    cfg,
		HTTP:   &http.Client{Timeout: 8 * time.Second},
		OnStep: onStep,
	}
}

func (m *Manager) emit(nodeID, phase, level, msg string) {
	if m.OnStep != nil {
		m.OnStep(model.HAProgressEvent{
			Timestamp: time.Now().Format("15:04:05"),
			NodeID:    nodeID,
			Phase:     phase,
			Level:     level,
			Message:   msg,
		})
	}
}

func (m *Manager) clashHeaders() http.Header {
	h := make(http.Header)
	h.Set("User-Agent", "Security-Sentinel/2.0")
	h.Set("Content-Type", "application/json")
	if sec := secrets.Get(secrets.KeyClashAPISecret); sec != "" {
		h.Set("Authorization", "Bearer "+sec)
	}
	return h
}

// DiscoverGatewayGroups queries /proxies on the Clash/Sing-box/Mihomo gateway, returns all available
// Selector groups, auto-resolves the best matching group if the configured SelectorGroup was renamed (e.g. DIY-Node -> #VPS),
// and returns the active node + candidate nodes for that group.
func (m *Manager) DiscoverGatewayGroups(ctx context.Context) (resolvedSelector string, selectorGroups []string, active string, all []string, err error) {
	gw := m.Cfg.Gateway
	if !gw.Enabled {
		return "", nil, "", nil, nil
	}
	apiURL := strings.TrimRight(strings.TrimSpace(gw.ClashAPIURL), "/")
	if apiURL == "" {
		apiURL = "http://127.0.0.1:9090"
	}
	prefSelector := strings.TrimSpace(gw.SelectorGroup)
	if prefSelector == "" {
		prefSelector = "Proxy"
	}

	// 1. Try querying /proxies (full map of groups & nodes)
	uAll := fmt.Sprintf("%s/proxies", apiURL)
	reqAll, err := http.NewRequestWithContext(ctx, http.MethodGet, uAll, nil)
	if err == nil {
		reqAll.Header = m.clashHeaders()
		if resp, errDo := m.HTTP.Do(reqAll); errDo == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				type proxyGroupItem struct {
					Type string   `json:"type"`
					Now  string   `json:"now"`
					All  []string `json:"all"`
				}
				var parsed struct {
					Proxies map[string]proxyGroupItem `json:"proxies"`
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
				if json.Unmarshal(body, &parsed) == nil && len(parsed.Proxies) > 0 {
					// Collect all Selector groups
					for name, item := range parsed.Proxies {
						tLow := strings.ToLower(item.Type)
						if tLow == "selector" || (name == prefSelector && len(item.All) > 0) {
							if name != "GLOBAL" {
								selectorGroups = append(selectorGroups, name)
							}
						}
					}
					// Sort selectorGroups deterministically while prioritizing #VPS, #Nodes, Proxy
					prioritizeSelectorGroups(selectorGroups)

					// Exact match on configured selector
					if g, ok := parsed.Proxies[prefSelector]; ok && len(g.All) > 0 {
						return prefSelector, selectorGroups, g.Now, g.All, nil
					}

					// Smart fallback 1: Find the Selector group whose candidate nodes match rolling_nodes keywords!
					var keywords []string
					for _, rn := range m.Cfg.RollingNodes {
						keywords = append(keywords, rn.Keywords...)
					}
					bestGroup := ""
					bestHits := 0
					for _, gName := range selectorGroups {
						g := parsed.Proxies[gName]
						hits := 0
						for _, cand := range g.All {
							for _, kw := range keywords {
								if kw != "" && strings.Contains(cand, kw) {
									hits++
									break
								}
							}
						}
						if hits > bestHits {
							bestHits = hits
							bestGroup = gName
						}
					}
					if bestGroup != "" {
						g := parsed.Proxies[bestGroup]
						return bestGroup, selectorGroups, g.Now, g.All, nil
					}

					// Smart fallback 2: Common selector group names (#VPS, #Nodes, Proxy)
					for _, common := range []string{"#VPS", "#Nodes", "Proxy", "节点选择", "自动选择"} {
						if g, ok := parsed.Proxies[common]; ok && len(g.All) > 0 {
							return common, selectorGroups, g.Now, g.All, nil
						}
					}
					if len(selectorGroups) > 0 {
						first := selectorGroups[0]
						g := parsed.Proxies[first]
						return first, selectorGroups, g.Now, g.All, nil
					}
				}
			}
		}
	}

	// 2. Direct fallback to /proxies/{selector} (also used by mock servers in unit tests)
	u := fmt.Sprintf("%s/proxies/%s", apiURL, url.PathEscape(prefSelector))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", nil, "", nil, err
	}
	req.Header = m.clashHeaders()
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return "", nil, "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, "", nil, fmt.Errorf("Clash API HTTP %d (策略组 %s 不存在或未授权)", resp.StatusCode, prefSelector)
	}
	var data struct {
		Now string   `json:"now"`
		All []string `json:"all"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &data); err != nil {
		return "", nil, "", nil, err
	}
	return prefSelector, []string{prefSelector}, data.Now, data.All, nil
}

func prioritizeSelectorGroups(groups []string) {
	rank := func(s string) int {
		switch s {
		case "#VPS":
			return 0
		case "#Nodes":
			return 1
		case "Proxy":
			return 2
		default:
			return 10
		}
	}
	for i := 0; i < len(groups); i++ {
		for j := i + 1; j < len(groups); j++ {
			ri, rj := rank(groups[i]), rank(groups[j])
			if rj < ri || (ri == rj && groups[j] < groups[i]) {
				groups[i], groups[j] = groups[j], groups[i]
			}
		}
	}
}

// GetGatewayActiveNode returns the active node name and all candidate node names in the configured (or auto-discovered) selector group.
func (m *Manager) GetGatewayActiveNode(ctx context.Context) (active string, all []string, err error) {
	resolved, _, active, all, err := m.DiscoverGatewayGroups(ctx)
	if err == nil && resolved != "" {
		m.Cfg.Gateway.SelectorGroup = resolved
	}
	return active, all, err
}

// SwitchGatewayNode switches the Clash/Mihomo selector group to targetNode.
func (m *Manager) SwitchGatewayNode(ctx context.Context, targetNode string) error {
	gw := m.Cfg.Gateway
	if !gw.Enabled {
		return nil
	}
	apiURL := strings.TrimRight(strings.TrimSpace(gw.ClashAPIURL), "/")
	if apiURL == "" {
		apiURL = "http://127.0.0.1:9090"
	}
	selector := strings.TrimSpace(gw.SelectorGroup)
	if selector == "" {
		selector = "Proxy"
	}
	if resolved, _, _, _, err := m.DiscoverGatewayGroups(ctx); err == nil && resolved != "" {
		selector = resolved
		m.Cfg.Gateway.SelectorGroup = resolved
	}
	u := fmt.Sprintf("%s/proxies/%s", apiURL, url.PathEscape(selector))
	payload, _ := json.Marshal(map[string]string{"name": targetNode})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header = m.clashHeaders()
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Clash PUT HTTP %d", resp.StatusCode)
	}
	return nil
}

// TestNodeDelay measures proxy node latency in milliseconds via Clash/Mihomo /delay endpoint (-1 on failure).
func (m *Manager) TestNodeDelay(ctx context.Context, nodeName string) int {
	gw := m.Cfg.Gateway
	if !gw.Enabled {
		return -1
	}
	apiURL := strings.TrimRight(gw.ClashAPIURL, "/")
	u := fmt.Sprintf("%s/proxies/%s/delay?timeout=5000&url=%s",
		apiURL,
		url.PathEscape(nodeName),
		url.QueryEscape("https://captive.apple.com/hotspot-detect.html"),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return -1
	}
	req.Header = m.clashHeaders()
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	var data struct {
		Delay int `json:"delay"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if json.Unmarshal(body, &data) != nil || data.Delay <= 0 {
		return -1
	}
	return data.Delay
}

func (m *Manager) resolveNodeTarget(nodeID string) (model.HostTarget, config.RollingNodeConfig) {
	nodes := m.Cfg.RollingNodesMap()
	if nCfg, ok := nodes[nodeID]; ok {
		sshHost := nCfg.SSHHost
		if sshHost == "" {
			sshHost = "root@" + nodeID
		}
		return config.NormalizeStringHost(sshHost), nCfg
	}
	sshHost := nodeID
	if !strings.Contains(sshHost, "@") {
		sshHost = "root@" + nodeID
	}
	return config.NormalizeStringHost(sshHost), config.RollingNodeConfig{ID: nodeID, SSHHost: sshHost}
}

// CheckRebootRequired checks /var/run/reboot-required on a remote node.
func (m *Manager) CheckRebootRequired(ctx context.Context, nodeID string) bool {
	target, _ := m.resolveNodeTarget(nodeID)
	exec := transport.New(target)
	res, err := exec.Run(ctx, "[ -f /var/run/reboot-required ] && echo YES || echo NO", 8*time.Second)
	return err == nil && res.Code == 0 && strings.Contains(res.Stdout, "YES")
}

// DrainTrafficIfActive drains gateway traffic away from nodeID onto a healthy peer before reboot.
func (m *Manager) DrainTrafficIfActive(ctx context.Context, nodeID string) error {
	if !m.Cfg.Gateway.Enabled {
		m.emit(nodeID, "drain", "INFO", "旁路网关切流未启用，直接进入单机重启")
		return nil
	}
	nodes := m.Cfg.RollingNodesMap()
	nCfg, exists := nodes[nodeID]
	if !exists || len(nCfg.Keywords) == 0 {
		return nil
	}

	active, allNodes, err := m.GetGatewayActiveNode(ctx)
	if err != nil {
		m.emit(nodeID, "drain", "WARN", fmt.Sprintf("查询网关活跃节点异常 (%v)，继续执行", err))
		return nil
	}

	activeOnTarget := false
	for _, kw := range nCfg.Keywords {
		if kw != "" && strings.Contains(active, kw) {
			activeOnTarget = true
			break
		}
	}
	if !activeOnTarget {
		m.emit(nodeID, "drain", "INFO", fmt.Sprintf("当前网关流量位于 [%s]，%s 非主力承载节点，可无感重启", active, nodeID))
		return nil
	}

	m.emit(nodeID, "drain", "WARN", fmt.Sprintf("检测到 %s 正在承载活跃流量 (%s)，正在探测备用对端...", nodeID, active))
	var peers []string
	if nCfg.Peer != "" {
		if _, ok := nodes[nCfg.Peer]; ok {
			peers = append(peers, nCfg.Peer)
		}
	}
	for id := range nodes {
		if id != nodeID && id != nCfg.Peer {
			peers = append(peers, id)
		}
	}

	chosenNode := ""
	bestDelay := -1
	for _, pid := range peers {
		pCfg := nodes[pid]
		for _, cand := range allNodes {
			matched := false
			for _, kw := range pCfg.Keywords {
				if kw != "" && strings.Contains(cand, kw) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			d := m.TestNodeDelay(ctx, cand)
			m.emit(nodeID, "drain", "INFO", fmt.Sprintf("备用节点 %s (%s) 延迟: %dms", cand, pid, d))
			if d > 0 && d < 2000 {
				chosenNode = cand
				bestDelay = d
				break
			}
			if chosenNode == "" {
				chosenNode = cand
			}
		}
		if chosenNode != "" && bestDelay > 0 {
			break
		}
	}

	if chosenNode == "" {
		return fmt.Errorf("未找到可切换的备用代理节点，为避免断网中止重启 %s", nodeID)
	}
	if err := m.SwitchGatewayNode(ctx, chosenNode); err != nil {
		return fmt.Errorf("切换网关至 %s 失败: %w", chosenNode, err)
	}
	m.emit(nodeID, "drain", "SUCCESS", fmt.Sprintf("流量已平滑旁路切换至备用节点: %s", chosenNode))
	return nil
}

// ExecuteRollingReboot performs zero-downtime serial rolling reboot + credential sync + gateway reload.
func (m *Manager) ExecuteRollingReboot(ctx context.Context, nodeIDs []string, forceGateway bool) error {
	if len(nodeIDs) == 0 {
		if forceGateway {
			return m.ReloadGateway(ctx)
		}
		return nil
	}

	for _, nid := range nodeIDs {
		if err := m.rebootSingleNode(ctx, nid); err != nil {
			m.emit(nid, "error", "ERROR", err.Error())
			return err
		}
	}
	return m.ReloadGateway(ctx)
}

func (m *Manager) rebootSingleNode(ctx context.Context, nodeID string) error {
	target, nCfg := m.resolveNodeTarget(nodeID)
	exec := transport.New(target)

	if err := m.DrainTrafficIfActive(ctx, nodeID); err != nil {
		return err
	}

	m.emit(nodeID, "reboot", "INFO", fmt.Sprintf("向 %s (%s) 下发 reboot 指令...", nodeID, target.SSHHost))
	rebootCmd := "reboot"
	if target.User != "" && target.User != "root" {
		rebootCmd = "sudo -n reboot || reboot"
	}
	_, _ = exec.Run(ctx, rebootCmd, 10*time.Second)

	select {
	case <-time.After(8 * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	}

	host, port := transport.ResolveSSHHostPort(target)
	m.emit(nodeID, "wait_ssh", "INFO", fmt.Sprintf("等待 %s (%s:%d) 重启恢复连通...", nodeID, host, port))
	deadline := time.Now().Add(180 * time.Second)
	sshReady := false
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 3*time.Second)
		if err == nil {
			_ = conn.Close()
			res, err2 := exec.Run(ctx, "uptime", 8*time.Second)
			if err2 == nil && res.Code == 0 {
				sshReady = true
				m.emit(nodeID, "wait_ssh", "SUCCESS", fmt.Sprintf("%s 已重新上线: %s", nodeID, res.Stdout))
				break
			}
		}
		time.Sleep(4 * time.Second)
	}
	if !sshReady {
		return fmt.Errorf("%s 重启等待恢复超时 (180s)", nodeID)
	}

	// Wait briefly for core systemd services
	svcDeadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(svcDeadline) {
		res, err := exec.Run(ctx, "systemctl is-active sing-box docker caddy nginx 2>/dev/null || true", 8*time.Second)
		if err == nil && strings.Contains(res.Stdout, "active") {
			break
		}
		time.Sleep(3 * time.Second)
	}

	if strings.TrimSpace(nCfg.SyncCommand) != "" {
		m.emit(nodeID, "sync", "INFO", fmt.Sprintf("执行节点强同步指令: %s", nCfg.SyncCommand))
		res, err := exec.Run(ctx, nCfg.SyncCommand, 40*time.Second)
		if err != nil || res.Code != 0 {
			m.emit(nodeID, "sync", "WARN", fmt.Sprintf("同步指令返回非零 (%d): %s", res.Code, res.Stderr))
		} else {
			m.emit(nodeID, "sync", "SUCCESS", fmt.Sprintf("%s 凭据与容器强同步完成", nodeID))
		}
	}

	m.emit(nodeID, "done", "SUCCESS", fmt.Sprintf("%s 平滑重启与自愈闭环完成", nodeID))
	return nil
}

// ReloadGateway executes gateway reload_commands and probes node latencies.
func (m *Manager) ReloadGateway(ctx context.Context) error {
	gw := m.Cfg.Gateway
	if !gw.Enabled {
		return nil
	}
	if gw.SSHHost != "" && len(gw.ReloadCommands) > 0 {
		gwTarget := config.NormalizeStringHost(gw.SSHHost)
		exec := transport.New(gwTarget)
		for _, cmd := range gw.ReloadCommands {
			m.emit("gateway", "gateway_reload", "INFO", fmt.Sprintf("网关执行重载: %s", cmd))
			res, err := exec.Run(ctx, cmd, 60*time.Second)
			if err != nil || res.Code != 0 {
				return fmt.Errorf("网关重载命令 [%s] 失败: %v %s", cmd, err, res.Stderr)
			}
		}
	}
	active, all, err := m.GetGatewayActiveNode(ctx)
	if err == nil && active != "" {
		d := m.TestNodeDelay(ctx, active)
		m.emit("gateway", "gateway_reload", "SUCCESS", fmt.Sprintf("网关重载完毕 · 当前活跃节点: %s (%dms, 共 %d 个节点)", active, d, len(all)))
	}
	return nil
}
