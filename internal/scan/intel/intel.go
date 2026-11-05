package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
)

var ghsaEcoToModel = map[string]string{
	"composer": model.EcoPackagist,
	"pip":      model.EcoPyPI,
	"npm":      model.EcoNPM,
	"maven":    model.EcoMaven,
	"go":       model.EcoGo,
	"rust":     model.EcoCrates,
	"nuget":    model.EcoNuGet,
	"rubygems": model.EcoRubyGems,
	"pub":      model.EcoPub,
	"swift":    model.EcoSwift,
	"erlang":   model.EcoHex,
	"actions":  model.EcoActions,
}

var (
	cveTitleRe   = regexp.MustCompile(`(CVE-\d{4}-\d+)`)
	fixedInRe    = regexp.MustCompile(`fixed in\s+(\d+\.\d+(?:\.\d+)?)`)
	introInRe    = regexp.MustCompile(`Issue introduced in\s+(\d+\.\d+(?:\.\d+)?)`)
	httpClient   = &http.Client{Timeout: 12 * time.Second}
)

// Client fetches live advisories and queries Google OSV in batches.
type Client struct {
	HTTP          *http.Client
	Mem           *store.Store
	GHBaseURL     string
	OSVBaseURL    string
	KernelAtomURL string
	NVDBaseURL    string
	DebianRSSURL  string
	UbuntuRSSURL  string
	RedHatBaseURL string
}

func NewClient(mem *store.Store) *Client {
	return &Client{
		HTTP:          httpClient,
		Mem:           mem,
		GHBaseURL:     "https://api.github.com",
		OSVBaseURL:    "https://api.osv.dev",
		KernelAtomURL: "https://lore.kernel.org/linux-cve-announce/new.atom",
		NVDBaseURL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		DebianRSSURL:  "https://www.debian.org/security/dsa-long",
		UbuntuRSSURL:  "https://ubuntu.com/security/notices/rss.xml",
		RedHatBaseURL: "https://access.redhat.com/hydra/rest/securitydata",
	}
}

// FetchAllAdvisories concurrently fetches Language Ecosystems (GHSA), OS Distributions (Debian/Ubuntu/RHEL),
// and Linux Kernel (NVD 2.0 + CNA Atom) advisories with L2 caching.
func (c *Client) FetchAllAdvisories(ctx context.Context, days int, includeKernel bool, useCache bool) (map[string]model.Advisory, error) {
	if days <= 0 {
		days = 3
	}
	if useCache && c.Mem != nil {
		if cached, ok := c.Mem.GetAdvisories(days, includeKernel); ok {
			return cached, nil
		}
	}

	var (
		wg                     sync.WaitGroup
		langAdvs, osAdvs, kAdvs map[string]model.Advisory
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		langAdvs = c.FetchEcosystemAdvisories(ctx, days)
	}()
	go func() {
		defer wg.Done()
		osAdvs = c.FetchOSDistroAdvisories(ctx, days)
	}()

	if includeKernel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			kAdvs = c.FetchKernelAdvisories(ctx, days)
			if len(kAdvs) == 0 {
				kAdvs = c.FetchNVDLinuxKernelAdvisories(ctx, days)
			} else {
				for k, v := range c.FetchNVDLinuxKernelAdvisories(ctx, days) {
					if _, exists := kAdvs[k]; !exists {
						kAdvs[k] = v
					}
				}
			}
		}()
	}
	wg.Wait()

	out := make(map[string]model.Advisory, len(langAdvs)+len(osAdvs)+len(kAdvs))
	for k, v := range langAdvs {
		out[k] = v
	}
	for k, v := range osAdvs {
		if !includeKernel && v.EffectiveCategory() == "kernel" {
			continue
		}
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	for k, v := range kAdvs {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}

	if useCache && c.Mem != nil && len(out) > 0 {
		_ = c.Mem.SaveAdvisories(out, days, includeKernel)
	}
	return out, nil
}

type ghAdvisoryResp struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	CVSS        struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	CVSSSeverities struct {
		CVSSv3 struct {
			Score float64 `json:"score"`
		} `json:"cvss_v3"`
		CVSSv4 struct {
			Score float64 `json:"score"`
		} `json:"cvss_v4"`
	} `json:"cvss_severities"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    string `json:"first_patched_version"`
		PatchedVersions        string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

// FetchEcosystemAdvisories fetches reviewed Critical/High/Medium advisories across all 12 language ecosystems
// in just 3 concurrent requests (sorted newest-first by GitHub API, avoiding HTTP 422 date range rejections).
func (c *Client) FetchEcosystemAdvisories(ctx context.Context, days int) map[string]model.Advisory {
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	ghToken := secrets.Get(secrets.KeyGitHubToken)

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = make(map[string]model.Advisory)
	)

	for _, sev := range []string{"critical", "high", "medium"} {
		wg.Add(1)
		go func(severity string) {
			defer wg.Done()
			for page := 1; page <= 2; page++ {
				u := fmt.Sprintf("%s/advisories?type=reviewed&severity=%s&per_page=100&page=%d",
					strings.TrimRight(c.GHBaseURL, "/"),
					url.QueryEscape(severity),
					page,
				)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Security-Sentinel/"+model.Version)
				req.Header.Set("Accept", "application/vnd.github+json")
				if ghToken != "" {
					req.Header.Set("Authorization", "Bearer "+ghToken)
				}

				resp, err := c.HTTP.Do(req)
				if err != nil {
					return
				}
				body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
				resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusOK {
					return
				}
				var items []ghAdvisoryResp
				if err := json.Unmarshal(body, &items); err != nil || len(items) == 0 {
					return
				}

				reachedOlder := false
				mu.Lock()
				for _, it := range items {
					if it.PublishedAt != "" {
						if pubDT, err := time.Parse(time.RFC3339, it.PublishedAt); err == nil && pubDT.Before(cutoff) {
							reachedOlder = true
							continue
						}
					}
					baseID := it.CVEID
					if baseID == "" {
						baseID = it.GHSAID
					}
					if baseID == "" {
						continue
					}
					score := it.CVSS.Score
					if it.CVSSSeverities.CVSSv3.Score > score {
						score = it.CVSSSeverities.CVSSv3.Score
					}
					if it.CVSSSeverities.CVSSv4.Score > score {
						score = it.CVSSSeverities.CVSSv4.Score
					}
					sevNorm := strings.ToUpper(it.Severity)
					if sevNorm == "MODERATE" {
						sevNorm = "MEDIUM"
					}

					for idx, v := range it.Vulnerabilities {
						pkgName := strings.TrimSpace(v.Package.Name)
						if pkgName == "" {
							continue
						}
						ecoRaw := strings.ToLower(strings.TrimSpace(v.Package.Ecosystem))
						normEco := ghsaEcoToModel[ecoRaw]
						if normEco == "" {
							normEco = v.Package.Ecosystem
						}
						var fixed []string
						if v.FirstPatchedVersion != "" {
							fixed = append(fixed, v.FirstPatchedVersion)
						} else if v.PatchedVersions != "" {
							fixed = append(fixed, v.PatchedVersions)
						}

						mapKey := baseID
						if idx > 0 {
							mapKey = fmt.Sprintf("%s#%s", baseID, pkgName)
						}
						if _, exists := out[mapKey]; exists {
							continue
						}
						out[mapKey] = model.Advisory{
							ID:              baseID,
							CVEID:           it.CVEID,
							GHSAID:          it.GHSAID,
							Category:        "language",
							Ecosystem:       normEco,
							Severity:        sevNorm,
							CVSS:            score,
							Summary:         it.Summary,
							Package:         pkgName,
							VulnerableRange: v.VulnerableVersionRange,
							FixedIn:         fixed,
							PublishedAt:     it.PublishedAt,
							URL:             it.HTMLURL,
						}
					}
				}
				mu.Unlock()
				if reachedOlder || len(items) < 100 {
					break
				}
			}
		}(sev)
	}

	wg.Wait()
	return out
}

type atomFeed struct {
	Entries []struct {
		Title   string `xml:"title"`
		Updated string `xml:"updated"`
		Content string `xml:"content"`
		RawBody string `xml:",innerxml"`
		Link    struct {
			Href string `xml:"href,attr"`
		} `xml:"link"`
	} `xml:"entry"`
}

// FetchKernelAdvisories parses the official kernel.org Linux CNA Atom stream (zero fake CVEs).
func (c *Client) FetchKernelAdvisories(ctx context.Context, days int) map[string]model.Advisory {
	out := make(map[string]model.Advisory)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.KernelAtomURL, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", "Security-Sentinel/2.0")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	rawXML, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return out
	}

	var feed atomFeed
	if err := xml.Unmarshal(rawXML, &feed); err != nil {
		return out
	}

	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	for _, e := range feed.Entries {
		title := strings.TrimSpace(e.Title)
		if title == "" {
			continue
		}
		if e.Updated != "" {
			if upDT, err := time.Parse(time.RFC3339, strings.TrimSpace(e.Updated)); err == nil && upDT.Before(cutoff) {
				continue
			}
		}
		m := cveTitleRe.FindStringSubmatch(title)
		if m == nil {
			continue
		}
		cveID := m[1]

		fullBody := e.Title + "\n" + e.Content + "\n" + e.RawBody
		var fixed []string
		seenFix := make(map[string]bool)
		for _, fm := range fixedInRe.FindAllStringSubmatch(fullBody, -1) {
			if !seenFix[fm[1]] {
				seenFix[fm[1]] = true
				fixed = append(fixed, fm[1])
			}
		}
		intro := ""
		if im := introInRe.FindStringSubmatch(fullBody); im != nil {
			intro = im[1]
		}

		low := strings.ToLower(fullBody)
		sev := "HIGH"
		if strings.Contains(low, "use-after-free") ||
			strings.Contains(low, "out-of-bounds write") ||
			strings.Contains(low, "privilege escalation") ||
			strings.Contains(low, "remote code execution") ||
			strings.Contains(low, "arbitrary code") {
			sev = "CRITICAL"
		}

		summary := title
		if idx := strings.IndexByte(title, ':'); idx >= 0 {
			summary = strings.TrimSpace(title[idx+1:])
		}
		link := e.Link.Href
		if link == "" {
			link = "https://cve.org/CVERecord/?id=" + cveID
		}
		vulnRange := ""
		if len(fixed) > 0 {
			vulnRange = "< " + fixed[len(fixed)-1]
		}
		out[cveID] = model.Advisory{
			ID:              cveID,
			CVEID:           cveID,
			Ecosystem:       model.EcoLinux,
			Severity:        sev,
			Summary:         summary,
			Package:         "linux",
			VulnerableRange: vulnRange,
			FixedIn:         fixed,
			IntroducedIn:    intro,
			PublishedAt:     strings.TrimSpace(e.Updated),
			URL:             link,
		}
	}
	return out
}

// OSVQuery represents a single package@version query for Google OSV /v1/querybatch.
type OSVQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

type osvBatchReq struct {
	Queries []osvSingleQuery `json:"queries"`
}

type osvSingleQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvBatchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVulnDetail struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// QueryOSVAssets deduplicates queries across all hosts, invokes /v1/querybatch in chunks,
// and concurrently enriches full Advisory metadata (CVEs, fixed versions, CVSS severity).
func (c *Client) QueryOSVAssets(ctx context.Context, queries []OSVQuery) map[string][]model.Advisory {
	result := make(map[string][]model.Advisory)
	if len(queries) == 0 {
		return result
	}

	var unique []OSVQuery
	seenQ := make(map[string]bool)
	for _, q := range queries {
		if q.Ecosystem == "" || q.Name == "" || q.Version == "" || q.Version == "unknown" {
			continue
		}
		key := QueryKey(q.Ecosystem, q.Name, q.Version)
		if !seenQ[key] {
			seenQ[key] = true
			unique = append(unique, q)
		}
	}
	if len(unique) == 0 {
		return result
	}

	queryHits := make(map[string][]string)
	neededVulnIDs := make(map[string]bool)

	const chunkSize = 400
	for start := 0; start < len(unique); start += chunkSize {
		end := start + chunkSize
		if end > len(unique) {
			end = len(unique)
		}
		chunk := unique[start:end]

		var payload osvBatchReq
		payload.Queries = make([]osvSingleQuery, len(chunk))
		for i, q := range chunk {
			payload.Queries[i].Package.Name = q.Name
			payload.Queries[i].Package.Ecosystem = q.Ecosystem
			payload.Queries[i].Version = q.Version
		}
		rawReq, err := json.Marshal(payload)
		if err != nil {
			continue
		}
		u := strings.TrimRight(c.OSVBaseURL, "/") + "/v1/querybatch"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(rawReq))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Security-Sentinel/2.0")

		resp, err := c.HTTP.Do(req)
		if err != nil {
			continue
		}
		respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}

		var bResp osvBatchResp
		if err := json.Unmarshal(respBytes, &bResp); err != nil {
			continue
		}
		for i, r := range bResp.Results {
			if i >= len(chunk) || len(r.Vulns) == 0 {
				continue
			}
			qk := QueryKey(chunk[i].Ecosystem, chunk[i].Name, chunk[i].Version)
			for _, v := range r.Vulns {
				if v.ID != "" {
					queryHits[qk] = append(queryHits[qk], v.ID)
					neededVulnIDs[v.ID] = true
				}
			}
		}
	}

	if len(neededVulnIDs) == 0 {
		return result
	}

	detailMap := c.enrichOSVDetails(ctx, neededVulnIDs)
	for qk, ids := range queryHits {
		for _, id := range ids {
			if adv, ok := detailMap[id]; ok {
				result[qk] = append(result[qk], adv)
			}
		}
	}
	return result
}

func QueryKey(eco, name, ver string) string {
	return eco + "|" + strings.ToLower(name) + "|" + ver
}

func (c *Client) enrichOSVDetails(ctx context.Context, ids map[string]bool) map[string]model.Advisory {
	out := make(map[string]model.Advisory, len(ids))
	var cached map[string]model.Advisory
	if c.Mem != nil {
		cached = c.Mem.LoadOSVDetails()
	}

	var missing []string
	for id := range ids {
		if adv, ok := cached[id]; ok {
			out[id] = adv
		} else {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return out
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 8)
		fetched = make(map[string]model.Advisory)
	)

	for _, vid := range missing {
		wg.Add(1)
		go func(vulnID string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			adv, ok := c.fetchSingleOSVDetail(ctx, vulnID)
			if !ok {
				return
			}
			mu.Lock()
			out[vulnID] = adv
			fetched[vulnID] = adv
			mu.Unlock()
		}(vid)
	}
	wg.Wait()

	if c.Mem != nil && len(fetched) > 0 {
		c.Mem.SaveOSVDetails(fetched)
	}
	return out
}

func (c *Client) fetchSingleOSVDetail(ctx context.Context, vulnID string) (model.Advisory, bool) {
	u := fmt.Sprintf("%s/v1/vulns/%s", strings.TrimRight(c.OSVBaseURL, "/"), url.PathEscape(vulnID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return model.Advisory{}, false
	}
	req.Header.Set("User-Agent", "Security-Sentinel/2.0")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return model.Advisory{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return model.Advisory{}, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return model.Advisory{}, false
	}
	var det osvVulnDetail
	if err := json.Unmarshal(body, &det); err != nil {
		return model.Advisory{}, false
	}

	cveID, ghsaID := "", ""
	if strings.HasPrefix(det.ID, "CVE-") {
		cveID = det.ID
	} else if strings.HasPrefix(det.ID, "GHSA-") {
		ghsaID = det.ID
	}
	for _, al := range det.Aliases {
		if cveID == "" && strings.HasPrefix(al, "CVE-") {
			cveID = al
		}
		if ghsaID == "" && strings.HasPrefix(al, "GHSA-") {
			ghsaID = al
		}
	}
	if cveID == "" {
		if m := cveTitleRe.FindStringSubmatch(det.ID); m != nil {
			cveID = m[1]
		}
	}

	var fixed []string
	fixedByPkg := make(map[string][]string)
	seenFix := make(map[string]bool)
	eco, pkg := "", ""
	for _, aff := range det.Affected {
		pKey := strings.ToLower(strings.TrimSpace(aff.Package.Name))
		if eco == "" {
			eco = aff.Package.Ecosystem
			pkg = aff.Package.Name
		}
		for _, rng := range aff.Ranges {
			if strings.EqualFold(rng.Type, "GIT") {
				continue
			}
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					if pKey != "" {
						fixedByPkg[pKey] = append(fixedByPkg[pKey], ev.Fixed)
					}
					if !seenFix[ev.Fixed] {
						seenFix[ev.Fixed] = true
						fixed = append(fixed, ev.Fixed)
					}
				}
			}
		}
	}

	sev := strings.ToUpper(strings.TrimSpace(det.DatabaseSpecific.Severity))
	var cvss float64
	for _, s := range det.Severity {
		if v, err := strconv.ParseFloat(s.Score, 64); err == nil && v > cvss {
			cvss = v
		} else if vecScore := parseCVSSv3Vector(s.Score); vecScore > cvss {
			cvss = vecScore
		}
	}
	if sev == "" || (sev == "MODERATE" && cvss >= 7.0) {
		switch {
		case cvss >= 9.0:
			sev = "CRITICAL"
		case cvss >= 7.0:
			sev = "HIGH"
		case cvss > 0:
			sev = "MEDIUM"
		case sev == "":
			sev = "HIGH"
		}
	}
	if sev == "MODERATE" {
		sev = "MEDIUM"
	}

	summary := strings.TrimSpace(det.Summary)
	if summary == "" {
		summary = strings.TrimSpace(det.Details)
	}
	summary = strings.ReplaceAll(summary, "\n", " ")
	if len(summary) > 160 {
		summary = strings.TrimSpace(summary[:160]) + "..."
	}

	refURL := ""
	for _, r := range det.References {
		if r.URL != "" {
			refURL = r.URL
			if r.Type == "ADVISORY" {
				break
			}
		}
	}
	if refURL == "" && cveID != "" {
		refURL = "https://osv.dev/vulnerability/" + det.ID
	}

	return model.Advisory{
		ID:        det.ID,
		CVEID:     cveID,
		GHSAID:    ghsaID,
		Aliases:   det.Aliases,
		Ecosystem: eco,
		Package:   pkg,
		Severity:  sev,
		CVSS:      cvss,
		Summary:   summary,
		Details:    det.Details,
		FixedIn:    fixed,
		FixedByPkg: fixedByPkg,
		URL:        refURL,
	}, true
}

// parseCVSSv3Vector computes the standard FIRST.org CVSS v3.0/v3.1 Base Score from a vector string
// such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
func parseCVSSv3Vector(vec string) float64 {
	vec = strings.TrimSpace(vec)
	if !strings.HasPrefix(vec, "CVSS:3.") {
		return 0
	}
	m := make(map[string]string)
	for _, part := range strings.Split(vec, "/") {
		if kv := strings.SplitN(part, ":", 2); len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	scopeChanged := m["S"] == "C"
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		if scopeChanged {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if scopeChanged {
			pr = 0.50
		} else {
			pr = 0.27
		}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c, i, a := cia[m["C"]], cia[m["I"]], cia[m["A"]]
	if av == 0 || ac == 0 || pr == 0 || ui == 0 {
		return 0
	}
	iscBase := 1.0 - (1.0-c)*(1.0-i)*(1.0-a)
	if iscBase <= 0 {
		return 0
	}
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * av * ac * pr * ui
	raw := impact + exploitability
	if scopeChanged {
		raw = 1.08 * raw
	}
	if raw > 10.0 {
		raw = 10.0
	}
	// CVSS v3 Roundup to 1 decimal place
	intInput := math.Round(raw * 100000.0)
	if int64(intInput)%10000 == 0 {
		return intInput / 100000.0
	}
	return (math.Floor(intInput/10000.0) + 1.0) / 10.0
}

// MapOSContextToOSVEcosystem maps OSContext to Google OSV's distro ecosystem string.
func MapOSContextToOSVEcosystem(osCtx model.OSContext) string {
	switch osCtx.OSFamily {
	case "debian":
		major := strings.Split(osCtx.DistroVersion, ".")[0]
		if major == "" {
			major = "12"
		}
		return "Debian:" + major
	case "ubuntu":
		v := osCtx.DistroVersion
		if len(v) > 5 {
			v = v[:5]
		}
		if v == "" {
			v = "22.04"
		}
		return "Ubuntu:" + v
	case "alpine":
		v := osCtx.DistroVersion
		parts := strings.Split(v, ".")
		if len(parts) >= 2 {
			return fmt.Sprintf("Alpine:v%s.%s", parts[0], parts[1])
		}
		return "Alpine:v3.20"
	case "rhel":
		if osCtx.DistroID == "almalinux" {
			return "AlmaLinux"
		}
		return "Rocky Linux"
	default:
		return ""
	}
}
