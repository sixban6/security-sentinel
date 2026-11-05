package store

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

// IgnoreRuleKey builds a canonical lookup key for (hostKey, vulnID, package).
func IgnoreRuleKey(hostKey, vulnID, pkg string) string {
	return fmt.Sprintf("%s|%s|%s",
		strings.ToLower(strings.TrimSpace(hostKey)),
		strings.ToUpper(strings.TrimSpace(vulnID)),
		strings.ToLower(strings.TrimSpace(pkg)),
	)
}

// AddIgnoreRule saves or updates a Mute / Skip-Version / Snooze rule atomically.
func (s *Store) AddIgnoreRule(rule model.IgnoreRule, snoozeDays int) model.IgnoreRule {
	now := time.Now()
	rule.Key = IgnoreRuleKey(rule.HostKey, rule.VulnID, rule.Package)
	rule.CreatedAt = now.Format("2006-01-02 15:04")
	if rule.Mode == "snooze" {
		if snoozeDays <= 0 {
			snoozeDays = 30
		}
		rule.ExpiresAt = now.Add(time.Duration(snoozeDays) * 24 * time.Hour).Format(time.RFC3339)
		if rule.Reason == "" {
			rule.Reason = fmt.Sprintf("暂缓提醒 %d 天", snoozeDays)
		}
	} else if rule.Mode == "skip_version" {
		rule.ExpiresAt = ""
		if rule.Reason == "" {
			rule.Reason = fmt.Sprintf("已跳过目标版本 %s", rule.SkippedVersion)
		}
	} else {
		rule.Mode = "permanent"
		rule.ExpiresAt = ""
		if rule.Reason == "" {
			rule.Reason = "用户确认风险自担并永久豁免"
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.loadStateLocked()
	st.IgnoreRules[rule.Key] = rule
	_ = s.saveStateLocked(st)
	return rule
}

// RemoveIgnoreRule deletes an ignore rule (restoring active monitoring).
func (s *Store) RemoveIgnoreRule(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.loadStateLocked()
	if _, exists := st.IgnoreRules[key]; !exists {
		return false
	}
	delete(st.IgnoreRules, key)
	_ = s.saveStateLocked(st)
	return true
}

// ListIgnoreRules returns all currently active (non-expired) ignore rules sorted newest-first.
func (s *Store) ListIgnoreRules() []model.IgnoreRule {
	s.mu.Lock()
	st := s.loadStateLocked()
	s.mu.Unlock()

	now := time.Now()
	var out []model.IgnoreRule
	for _, r := range st.IgnoreRules {
		if r.Mode == "snooze" && r.ExpiresAt != "" {
			if exp, err := time.Parse(time.RFC3339, r.ExpiresAt); err == nil && now.After(exp) {
				continue
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out
}

// MatchIgnoreRule checks whether a vulnerability match on hostKey is currently muted by an active IgnoreRule.
// For "skip_version" rules, if upstream releases a NEWER candidate/fixed version than SkippedVersion,
// MatchIgnoreRule returns false so the user is automatically notified of the new release!
func (s *Store) MatchIgnoreRule(hostKey string, v model.VulnerabilityMatch) (matched bool, note string) {
	if s == nil {
		return false, ""
	}
	s.mu.Lock()
	st := s.loadStateLocked()
	s.mu.Unlock()
	if len(st.IgnoreRules) == 0 {
		return false, ""
	}

	keysToTry := []string{
		IgnoreRuleKey(hostKey, v.EffectiveID(), v.Package),
		IgnoreRuleKey("*", v.EffectiveID(), v.Package),
	}
	now := time.Now()

	for _, k := range keysToTry {
		r, ok := st.IgnoreRules[k]
		if !ok {
			continue
		}
		switch r.Mode {
		case "snooze":
			if r.ExpiresAt != "" {
				exp, err := time.Parse(time.RFC3339, r.ExpiresAt)
				if err != nil || now.After(exp) {
					continue
				}
				remDays := max(1, int(exp.Sub(now).Hours()/24)+1)
				return true, fmt.Sprintf("已暂缓提醒 (剩余 %d 天)", remDays)
			}
		case "skip_version":
			// Only suppress while candidate/fixed version matches the skipped version!
			if r.SkippedVersion != "" && v.FixedVersion != "" && v.FixedVersion != r.SkippedVersion {
				continue
			}
			return true, fmt.Sprintf("已跳过版本 %s", r.SkippedVersion)
		default:
			return true, "已永久豁免 (" + r.Reason + ")"
		}
	}
	return false, ""
}
