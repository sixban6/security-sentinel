package gui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/scan/inventory"
)

type exploredAssetRow struct {
	HostName string
	Item     model.AssetItem
}

func classifyAssetLayerLabel(a model.AssetItem) (layerCode string, badge string) {
	loc := strings.ToLower(a.Location)
	switch {
	case strings.HasPrefix(loc, "homebrew"):
		if loc == "homebrew-cask" {
			return "brew", "Homebrew Cask"
		}
		return "brew", "Homebrew Formula"
	case strings.HasPrefix(loc, "docker") || loc == "container-engine" || a.Ecosystem == model.EcoDocker:
		if a.Kind == "container" {
			return "docker", "运行中容器"
		}
		if a.Kind == "container-image" {
			return "docker", "Docker 镜像"
		}
		return "docker", "容器引擎"
	case strings.HasPrefix(loc, "global-") || a.Kind == "binary":
		return "tools", "全局工具链 (" + a.Ecosystem + ")"
	case a.Kind == "venv" || a.Kind == "lockfile":
		return "workspace", "项目依赖 (" + a.Ecosystem + ")"
	default:
		return "os", "系统与内核 (" + firstNonEmptyStr(a.Ecosystem, a.Location) + ")"
	}
}

// OpenAssetExplorerModal loads the full 5-layer discovered asset snapshot and opens the Panorama Asset Explorer.
func (s *AppState) OpenAssetExplorerModal(initialLayerTab int) {
	s.DiscoveredAssetsMap = inventory.LoadDiscoveredInventories()
	s.AssetExplorerLayerTab = initialLayerTab
	s.ShowAssetExplorer = true
}

// renderAssetExplorerModal renders the searchable, 120fps virtualized 5-Layer Panorama Asset Explorer dialog.
func (s *AppState) renderAssetExplorerModal(c *ui.Context) {
	t := c.Theme()
	ui.Modal(c, &s.ShowAssetExplorer, func() {
		hostOptions := []string{"全部主机"}
		var hostNames []string
		for k := range s.DiscoveredAssetsMap {
			hostNames = append(hostNames, k)
		}
		sort.Strings(hostNames)
		hostOptions = append(hostOptions, hostNames...)
		if s.AssetExplorerHost == "" {
			s.AssetExplorerHost = "全部主机"
		}

		layerCode := "all"
		switch s.AssetExplorerLayerTab {
		case 1:
			layerCode = "brew"
		case 2:
			layerCode = "docker"
		case 3:
			layerCode = "tools"
		case 4:
			layerCode = "os"
		case 5:
			layerCode = "workspace"
		}

		qLow := strings.ToLower(strings.TrimSpace(s.AssetExplorerQuery))
		var rows []exploredAssetRow
		for _, hName := range hostNames {
			if s.AssetExplorerHost != "全部主机" && s.AssetExplorerHost != hName {
				continue
			}
			inv := s.DiscoveredAssetsMap[hName]
			for _, a := range inv.Assets {
				lc, _ := classifyAssetLayerLabel(a)
				if layerCode != "all" && lc != layerCode {
					continue
				}
				if qLow != "" {
					hay := strings.ToLower(a.Name + " " + a.Version + " " + a.Ecosystem + " " + a.Location + " " + a.ProjectName)
					if !strings.Contains(hay, qLow) {
						continue
					}
				}
				rows = append(rows, exploredAssetRow{HostName: hName, Item: a})
			}
		}

		ui.Column(c).Width(840).Height(560).Gap(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, "🔍 五层全景资产透明浏览器 (Panorama Asset Explorer)").FontSize(18).Bold()
					ui.Text(c, fmt.Sprintf("当前筛选共命中 %d 项已纳管真实组件（支持按层级、主机与关键词即时检索）", len(rows))).
						FontSize(12).TextColor(t.TextMuted)
				})
				if ui.Button(c.Key("ae-close"), "关闭").Clicked() {
					s.ShowAssetExplorer = false
				}
			})

			ui.Row(c).Gap(8).Wrap().AlignItems(ui.Center).Children(func() {
				ui.Segmented(c.Key("ae-layer-seg"), &s.AssetExplorerLayerTab,
					"全部", "Homebrew", "Docker容器/镜像", "全局工具链", "系统与内核", "项目锁文件").Label("资产层级")

				if len(hostOptions) > 1 {
					ui.Select(c.Key("ae-host-sel"), &s.AssetExplorerHost, hostOptions).Width(150).Label("筛选主机")
				}

				ui.TextInput(c.Key("ae-search-in"), &s.AssetExplorerQuery).
					Placeholder("输入软件名、镜像名或版本号过滤 (如 docker, openssl, metube)…").Grow(1).Label("搜索资产")
			})

			if len(rows) == 0 {
				ui.Column(c).Grow(1).Center().Gap(8).
					Radius(10).Background(t.Surface).Border(1, t.Border).
					Children(func() {
						ui.Text(c, "未找到匹配资产（若刚升级版本，点击主界面「立即全量巡检」即可采集最新五层画像）").
							FontSize(13).TextColor(t.TextMuted)
					})
				return
			}

			s.AssetExplorerList.Key = func(i int) any {
				if i >= 0 && i < len(rows) {
					r := rows[i]
					return fmt.Sprintf("%s|%s|%s|%s", r.HostName, r.Item.Location, r.Item.Name, r.Item.Version)
				}
				return i
			}
			ui.List(c, &s.AssetExplorerList, len(rows), func(idx int) {
				r := rows[idx]
				_, badge := classifyAssetLayerLabel(r.Item)
				locText := r.Item.Location
				if r.Item.ProjectName != "" {
					locText = r.Item.ProjectName + " (" + r.Item.ManifestKind + ")"
				}

				ui.Row(c.Key(fmt.Sprintf("ae-r-%d", idx))).
					Padding(8, 12).Radius(8).Gap(10).AlignItems(ui.Center).
					Background(t.Surface).Border(1, t.Border).
					Children(func() {
						ui.Badge(c, badge)
						ui.Text(c, r.Item.Name).Bold().FontSize(13)
						ui.Badge(c, r.Item.Version).Background(t.Accent.Alpha(0.14)).TextColor(t.Accent)
						ui.Spacer(c)
						ui.Text(c, fmt.Sprintf("%s · %s", r.HostName, locText)).
							FontSize(11).TextColor(t.TextMuted).SingleLine()
					})
			}).Grow(1).Gap(6)
		})
	})
}
