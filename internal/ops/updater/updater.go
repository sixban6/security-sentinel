package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
	"github.com/sixban6/security-sentinel/internal/scan/version"
)

const DefaultRepo = "sixban6/security-sentinel"

type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type ReleaseInfo struct {
	TagName     string         `json:"tag_name"`
	Version     string         `json:"version"`
	HTMLURL     string         `json:"html_url"`
	PublishedAt string         `json:"published_at"`
	Body        string         `json:"body"`
	Assets      []ReleaseAsset `json:"assets"`
	HasUpdate   bool           `json:"has_update"`
}

type Client struct {
	Repo       string
	APIBaseURL string
	HTTP       *http.Client
}

func NewClient() *Client {
	return &Client{
		Repo:       DefaultRepo,
		APIBaseURL: "https://api.github.com",
		HTTP:       &http.Client{Timeout: 60 * time.Second},
	}
}

// CLIAssetName returns the primary GitHub Actions artifact name ("sectl-<os>-<arch>").
func CLIAssetName(goos, goarch string) string {
	switch goos {
	case "darwin":
		return fmt.Sprintf("sectl-darwin-%s", goarch)
	case "linux":
		if goarch == "mipsle" || goarch == "mips" {
			return fmt.Sprintf("sectl-openwrt-%s", goarch)
		}
		return fmt.Sprintf("sectl-linux-%s", goarch)
	case "windows":
		return fmt.Sprintf("sectl-windows-%s.exe", goarch)
	default:
		return fmt.Sprintf("sectl-%s-%s", goos, goarch)
	}
}

func legacyCLIAssetName(goos, goarch string) string {
	return strings.Replace(CLIAssetName(goos, goarch), "sectl-", "security-sentinel-", 1)
}

// AppArchiveAssetName returns the expected macOS .app.tar.gz artifact name.
func AppArchiveAssetName(goarch string) string {
	return fmt.Sprintf("Security-Sentinel-darwin-%s.app.tar.gz", goarch)
}

// CheckLatest fetches the latest published GitHub Release and compares it with currentVersion.
func (c *Client) CheckLatest(ctx context.Context, currentVersion string) (ReleaseInfo, error) {
	u := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(c.APIBaseURL, "/"), c.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ReleaseInfo{}, err
	}
	req.Header.Set("User-Agent", "Security-Sentinel/"+model.Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := secrets.Get(secrets.KeyGitHubToken); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("连接 GitHub Releases 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ReleaseInfo{}, fmt.Errorf("仓库 %s 尚未发布正式 GitHub Release 版本", c.Repo)
	}
	if resp.StatusCode != http.StatusOK {
		return ReleaseInfo{}, fmt.Errorf("GitHub API 返回 HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return ReleaseInfo{}, err
	}
	var rel ReleaseInfo
	if err := json.Unmarshal(body, &rel); err != nil {
		return ReleaseInfo{}, err
	}
	rel.Version = strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	curClean := strings.TrimPrefix(strings.TrimSpace(currentVersion), "v")
	if rel.Version != "" && version.CompareSemVerLike(curClean, rel.Version) < 0 {
		rel.HasUpdate = true
	}
	return rel, nil
}

// UpgradeCLI downloads, SHA-256 verifies, and atomically replaces targetBinPath (or the running CLI binary),
// maintaining the backwards-compatible `security-sentinel -> sectl` symlink when installed in bin directories.
func (c *Client) UpgradeCLI(ctx context.Context, rel ReleaseInfo, targetBinPath string) (string, error) {
	assetName := CLIAssetName(runtime.GOOS, runtime.GOARCH)
	asset, ok := findAsset(rel.Assets, assetName)
	if !ok {
		asset, ok = findAsset(rel.Assets, legacyCLIAssetName(runtime.GOOS, runtime.GOARCH))
	}
	if !ok {
		return "", fmt.Errorf("最新 Release (%s) 中未找到适配当前架构 (%s/%s) 的二进制文件 %s",
			rel.TagName, runtime.GOOS, runtime.GOARCH, assetName)
	}

	checksums, err := c.fetchChecksums(ctx, rel.Assets)
	if err != nil {
		return "", err
	}

	if targetBinPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		if realExe, err := filepath.EvalSymlinks(exe); err == nil {
			targetBinPath = realExe
		} else {
			targetBinPath = exe
		}
	}

	rawBin, err := c.downloadAndVerify(ctx, asset, checksums[asset.Name])
	if err != nil {
		return "", err
	}

	if err := atomicReplaceExecutable(targetBinPath, rawBin); err != nil {
		return "", err
	}

	// Ensure sibling symlink exists so both `sectl` and `security-sentinel` stay in sync!
	if runtime.GOOS != "windows" {
		dir := filepath.Dir(targetBinPath)
		base := filepath.Base(targetBinPath)
		if base == "sectl" {
			compatLink := filepath.Join(dir, "security-sentinel")
			_ = os.Remove(compatLink)
			_ = os.Symlink("sectl", compatLink)
		} else if base == "security-sentinel" {
			shortLink := filepath.Join(dir, "sectl")
			if _, err := os.Lstat(shortLink); os.IsNotExist(err) {
				_ = os.Symlink("security-sentinel", shortLink)
			}
		}
	}
	return targetBinPath, nil
}

// UpgradeMacOSApp downloads Security-Sentinel-darwin-<arch>.app.tar.gz, verifies SHA-256,
// clears Gatekeeper quarantine attributes, and atomically replaces the .app bundle.
func (c *Client) UpgradeMacOSApp(ctx context.Context, rel ReleaseInfo, destAppBundle string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("仅 macOS 支持 .app 应用包自动升级")
	}
	archiveName := AppArchiveAssetName(runtime.GOARCH)
	asset, ok := findAsset(rel.Assets, archiveName)
	if !ok {
		return "", fmt.Errorf("Release (%s) 中未找到桌面应用包 %s", rel.TagName, archiveName)
	}
	checksums, err := c.fetchChecksums(ctx, rel.Assets)
	if err != nil {
		return "", err
	}
	archiveBytes, err := c.downloadAndVerify(ctx, asset, checksums[asset.Name])
	if err != nil {
		return "", err
	}

	if destAppBundle == "" {
		destAppBundle = detectRunningOrInstalledAppBundle()
	}

	parentDir := filepath.Dir(destAppBundle)
	stageDir, err := os.MkdirTemp(parentDir, ".sentinel-app-stage-*")
	if err != nil {
		return "", fmt.Errorf("创建升级暂存目录失败 (%s): %w", parentDir, err)
	}
	defer os.RemoveAll(stageDir)

	tarFile := filepath.Join(stageDir, archiveName)
	if err := os.WriteFile(tarFile, archiveBytes, 0o600); err != nil {
		return "", err
	}
	if out, err := exec.CommandContext(ctx, "tar", "-xzf", tarFile, "-C", stageDir).CombinedOutput(); err != nil {
		return "", fmt.Errorf("解压应用包失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	extractedApp := filepath.Join(stageDir, "Security Sentinel.app")
	if _, err := os.Stat(extractedApp); err != nil {
		return "", fmt.Errorf("升级压缩包内未找到 Security Sentinel.app")
	}
	_ = exec.Command("xattr", "-cr", extractedApp).Run()

	backupApp := destAppBundle + ".old"
	_ = os.RemoveAll(backupApp)
	if _, err := os.Stat(destAppBundle); err == nil {
		if err := os.Rename(destAppBundle, backupApp); err != nil {
			return "", fmt.Errorf("替换旧版应用失败: %w", err)
		}
	}
	if err := os.Rename(extractedApp, destAppBundle); err != nil {
		_ = os.Rename(backupApp, destAppBundle)
		return "", fmt.Errorf("写入新版应用失败: %w", err)
	}
	_ = os.RemoveAll(backupApp)
	return destAppBundle, nil
}

func detectRunningOrInstalledAppBundle() string {
	if exe, err := os.Executable(); err == nil {
		if idx := strings.Index(exe, ".app/Contents/MacOS/"); idx > 0 {
			return exe[:idx+4]
		}
	}
	if _, err := os.Stat("/Applications/Security Sentinel.app"); err == nil {
		return "/Applications/Security Sentinel.app"
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", "Security Sentinel.app")
}

func findAsset(assets []ReleaseAsset, name string) (ReleaseAsset, bool) {
	for _, a := range assets {
		if a.Name == name {
			return a, true
		}
	}
	return ReleaseAsset{}, false
}

func (c *Client) fetchChecksums(ctx context.Context, assets []ReleaseAsset) (map[string]string, error) {
	out := make(map[string]string)
	csAsset, ok := findAsset(assets, "checksums.txt")
	if !ok {
		return out, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, csAsset.BrowserDownloadURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Security-Sentinel/"+model.Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("下载 checksums.txt 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 checksums.txt 返回 HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return nil, err
	}
	return ParseChecksums(string(raw)), nil
}

// ParseChecksums parses standard sha256sum lines ("<hex>  <filename>" or "<hex> *<filename>").
func ParseChecksums(text string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			hash := strings.ToLower(fields[0])
			fname := filepath.Base(strings.TrimPrefix(strings.Join(fields[1:], " "), "*"))
			m[fname] = hash
		}
	}
	return m
}

func (c *Client) downloadAndVerify(ctx context.Context, asset ReleaseAsset, expectedSHA256 string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Security-Sentinel/"+model.Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("下载更新包 %s 失败: %w", asset.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载 %s 返回 HTTP %d", asset.Name, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
	if err != nil {
		return nil, err
	}
	if len(data) < 1024 {
		return nil, fmt.Errorf("下载产物 %s 体积异常 (%d bytes)，已中止替换", asset.Name, len(data))
	}
	if expectedSHA256 != "" {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, expectedSHA256) {
			return nil, fmt.Errorf("安全校验失败：%s 的 SHA-256 (%s) 与官方 checksums.txt (%s) 不一致，已拦截更新",
				asset.Name, got[:16], expectedSHA256[:16])
		}
	}
	return data, nil
}

func atomicReplaceExecutable(targetPath string, newBytes []byte) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmpPath := fmt.Sprintf("%s.new.%d", targetPath, os.Getpid())
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("写入升级目录 %s 权限不足: %w", dir, err)
	}
	if _, err := f.Write(newBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	_ = f.Sync()
	_ = f.Close()
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("原子替换二进制失败: %w", err)
	}
	return nil
}
