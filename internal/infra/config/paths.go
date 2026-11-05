package config

import (
	"os"
	"path/filepath"
	"strings"
)

// ExpandHome expands a leading "~/" to the user's home directory.
func ExpandHome(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if p == "~" {
		if h, err := os.UserHomeDir(); err == nil {
			return h
		}
		return p
	}
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}

// ConfigDir returns XDG_CONFIG_HOME/sentinel (~/.config/sentinel).
func ConfigDir() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "sentinel")
	}
	return ExpandHome("~/.config/sentinel")
}

// CacheDir returns XDG_CACHE_HOME/sentinel (~/.cache/sentinel).
func CacheDir() string {
	if v := os.Getenv("XDG_CACHE_HOME"); v != "" {
		return filepath.Join(v, "sentinel")
	}
	return ExpandHome("~/.cache/sentinel")
}

// MemoryDir returns ~/.cache/sentinel/memory.
func MemoryDir() string {
	return filepath.Join(CacheDir(), "memory")
}

// StateDir returns XDG_STATE_HOME/sentinel (~/.local/state/sentinel).
func StateDir() string {
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "sentinel")
	}
	return ExpandHome("~/.local/state/sentinel")
}

// DefaultStatusFile returns the primary latest_status.json location,
// falling back to legacy ~/.gemini/logs/security_audit/latest_status.json on read if needed.
func DefaultStatusFile() string {
	primary := filepath.Join(StateDir(), "latest_status.json")
	if _, err := os.Stat(primary); err == nil {
		return primary
	}
	legacy := LegacyStatusFile()
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return primary
}

// PrimaryStatusFile always returns ~/.local/state/sentinel/latest_status.json.
func PrimaryStatusFile() string {
	return filepath.Join(StateDir(), "latest_status.json")
}

// LegacyStatusFile returns ~/.gemini/logs/security_audit/latest_status.json for v1 compatibility.
func LegacyStatusFile() string {
	return ExpandHome("~/.gemini/logs/security_audit/latest_status.json")
}

// GlobalConfigFile returns ~/.config/sentinel/sentinel.yaml.
func GlobalConfigFile() string {
	return filepath.Join(ConfigDir(), "sentinel.yaml")
}
