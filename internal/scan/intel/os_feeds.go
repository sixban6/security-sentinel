package intel

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

var (
	htmlTagRe = regexp.MustCompile(`<[^>]+>`)
	dsaPkgRe  = regexp.MustCompile(`^(DSA-\d+-\d+)\s+(\S+)\s*-\s*(.*)$`)
	usnPkgRe  = regexp.MustCompile(`^(USN-\d+-\d+):\s*(.+?)\s+vulnerabilit`)
)

// FetchOSDistroAdvisories concurrently pulls daily OS security advisories from Debian DSA, Ubuntu USN, and Red Hat Security Data API.
func (c *Client) FetchOSDistroAdvisories(ctx context.Context, days int) map[string]model.Advisory {
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = make(map[string]model.Advisory)
	)

	merge := func(m map[string]model.Advisory) {
		mu.Lock()
		defer mu.Unlock()
		for k, v := range m {
			if _, exists := out[k]; !exists {
				out[k] = v
			}
		}
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		merge(c.fetchDebianDSA(ctx, cutoff))
	}()
	go func() {
		defer wg.Done()
		merge(c.fetchUbuntuUSN(ctx, cutoff))
	}()
	go func() {
		defer wg.Done()
		merge(c.fetchRedHatCVEs(ctx, cutoff))
	}()
	wg.Wait()
	return out
}

func (c *Client) fetchDebianDSA(ctx context.Context, cutoff time.Time) map[string]model.Advisory {
	out := make(map[string]model.Advisory)
	if c.DebianRSSURL == "" {
		return out
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.DebianRSSURL, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", "Security-Sentinel/"+model.Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return out
	}

	var rdf struct {
		Items []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			Date        string `xml:"date"`
			Description string `xml:"description"`
		} `xml:"item"`
	}
	if err := xml.Unmarshal(raw, &rdf); err != nil {
		return out
	}

	cutoffDate := cutoff.Format("2006-01-02")
	for _, it := range rdf.Items {
		dtStr := strings.TrimSpace(it.Date)
		if len(dtStr) >= 10 && dtStr[:10] < cutoffDate {
			continue
		}
		title := strings.TrimSpace(it.Title)
		dsaID := title
		pkg := "debian"
		if m := dsaPkgRe.FindStringSubmatch(title); m != nil {
			dsaID = m[1]
			pkg = m[2]
		}
		desc := cleanFeedDescription(it.Description)
		cves := cveTitleRe.FindAllString(desc, -1)
		cveID := ""
		if len(cves) > 0 {
			cveID = cves[0]
		}
		sev := classifyTextSeverity(desc)
		cat := "os"
		if strings.HasPrefix(strings.ToLower(pkg), "linux") {
			cat = "kernel"
		}
		id := dsaID
		if cveID != "" {
			id = cveID
		}
		summary := desc
		if summary == "" {
			summary = title
		}
		out[dsaID] = model.Advisory{
			ID:          id,
			CVEID:       cveID,
			Aliases:     cves,
			Category:    cat,
			Ecosystem:   "Debian",
			Severity:    sev,
			Package:     pkg,
			Summary:     fmt.Sprintf("[%s] %s", dsaID, truncateSummary(summary, 140)),
			PublishedAt: dtStr,
			URL:         strings.TrimSpace(it.Link),
		}
	}
	return out
}

func (c *Client) fetchUbuntuUSN(ctx context.Context, cutoff time.Time) map[string]model.Advisory {
	out := make(map[string]model.Advisory)
	if c.UbuntuRSSURL == "" {
		return out
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.UbuntuRSSURL, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", "Security-Sentinel/"+model.Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return out
	}

	var rss struct {
		Items []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			PubDate     string `xml:"pubDate"`
			Description string `xml:"description"`
		} `xml:"channel>item"`
	}
	if err := xml.Unmarshal(raw, &rss); err != nil {
		return out
	}

	for _, it := range rss.Items {
		pubStr := strings.TrimSpace(it.PubDate)
		isoDate := pubStr
		if pubDT, err := time.Parse(time.RFC1123Z, pubStr); err == nil {
			if pubDT.Before(cutoff) {
				continue
			}
			isoDate = pubDT.UTC().Format(time.RFC3339)
		} else if pubDT2, err2 := time.Parse(time.RFC1123, pubStr); err2 == nil {
			if pubDT2.Before(cutoff) {
				continue
			}
			isoDate = pubDT2.UTC().Format(time.RFC3339)
		}

		title := strings.TrimSpace(it.Title)
		usnID := title
		pkg := "ubuntu"
		if m := usnPkgRe.FindStringSubmatch(title); m != nil {
			usnID = m[1]
			pkg = strings.TrimSpace(m[2])
		}
		desc := cleanFeedDescription(it.Description)
		cves := cveTitleRe.FindAllString(desc, -1)
		cveID := ""
		if len(cves) > 0 {
			cveID = cves[0]
		}
		cat := "os"
		if strings.Contains(strings.ToLower(pkg), "linux kernel") || strings.EqualFold(pkg, "linux") {
			cat = "kernel"
		}
		id := usnID
		if cveID != "" {
			id = cveID
		}
		out[usnID] = model.Advisory{
			ID:          id,
			CVEID:       cveID,
			Aliases:     cves,
			Category:    cat,
			Ecosystem:   "Ubuntu",
			Severity:    classifyTextSeverity(desc),
			Package:     pkg,
			Summary:     fmt.Sprintf("[%s] %s", usnID, truncateSummary(firstLineOrText(desc, title), 140)),
			PublishedAt: isoDate,
			URL:         strings.TrimSpace(it.Link),
		}
	}
	return out
}

func (c *Client) fetchRedHatCVEs(ctx context.Context, cutoff time.Time) map[string]model.Advisory {
	out := make(map[string]model.Advisory)
	if c.RedHatBaseURL == "" {
		return out
	}
	u := fmt.Sprintf("%s/cve.json?after=%s&per_page=50",
		strings.TrimRight(c.RedHatBaseURL, "/"),
		url.QueryEscape(cutoff.Format("2006-01-02")),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", "Security-Sentinel/"+model.Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return out
	}

	var items []struct {
		CVE                 string `json:"CVE"`
		Severity            string `json:"severity"`
		PublicDate          string `json:"public_date"`
		BugzillaDescription string `json:"bugzilla_description"`
		CVSS3Score          string `json:"cvss3_score"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return out
	}

	for _, it := range items {
		if it.CVE == "" {
			continue
		}
		sev := "MEDIUM"
		switch strings.ToLower(strings.TrimSpace(it.Severity)) {
		case "critical":
			sev = "CRITICAL"
		case "important", "high":
			sev = "HIGH"
		case "moderate", "medium":
			sev = "MEDIUM"
		default:
			continue
		}
		var score float64
		if v, err := strconv.ParseFloat(it.CVSS3Score, 64); err == nil {
			score = v
			if score >= 9.0 {
				sev = "CRITICAL"
			} else if score >= 7.0 && sev == "MEDIUM" {
				sev = "HIGH"
			}
		}

		desc := strings.TrimSpace(it.BugzillaDescription)
		pkg := "rhel"
		if colon := strings.IndexByte(desc, ':'); colon > 0 && colon < 45 {
			cand := strings.TrimSpace(desc[:colon])
			if !strings.Contains(cand, " ") {
				pkg = cand
				desc = strings.TrimSpace(desc[colon+1:])
			}
		}
		// Skip language-library duplicates (e.g. github.com/... or org.apache...) from RHEL Bugzilla so OS category stays focused on OS components
		if strings.Contains(pkg, "/") || strings.Count(pkg, ".") >= 2 {
			continue
		}
		cat := "os"
		if pkg == "kernel" || strings.HasPrefix(pkg, "linux") {
			cat = "kernel"
		}
		out[it.CVE] = model.Advisory{
			ID:          it.CVE,
			CVEID:       it.CVE,
			Category:    cat,
			Ecosystem:   "RHEL",
			Severity:    sev,
			CVSS:        score,
			Package:     pkg,
			Summary:     truncateSummary(desc, 150),
			PublishedAt: it.PublicDate,
			URL:         "https://access.redhat.com/security/cve/" + it.CVE,
		}
	}
	return out
}

// FetchNVDLinuxKernelAdvisories fetches official NIST NVD 2.0 Linux Kernel CVEs published in the last N days.
func (c *Client) FetchNVDLinuxKernelAdvisories(ctx context.Context, days int) map[string]model.Advisory {
	out := make(map[string]model.Advisory)
	if c.NVDBaseURL == "" {
		return out
	}
	now := time.Now().UTC()
	startDT := now.Add(-time.Duration(days)*24*time.Hour).Format("2006-01-02") + "T00:00:00.000"
	endDT := now.Format("2006-01-02") + "T23:59:59.000"
	u := fmt.Sprintf("%s?keywordSearch=Linux%%20kernel&pubStartDate=%s&pubEndDate=%s&resultsPerPage=200",
		strings.TrimRight(c.NVDBaseURL, "/"),
		startDT,
		endDT,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Security-Sentinel/2.6)")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return out
	}

	var doc struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return out
	}

	for _, w := range doc.Vulnerabilities {
		cv := w.CVE
		if cv.ID == "" {
			continue
		}
		enDesc := ""
		for _, d := range cv.Descriptions {
			if d.Lang == "en" {
				enDesc = strings.TrimSpace(d.Value)
				break
			}
		}
		if !strings.Contains(strings.ToLower(enDesc), "linux kernel") {
			continue
		}
		summary := extractCleanKernelSummary(enDesc)
		var score float64
		sev := ""
		if len(cv.Metrics.CVSSMetricV31) > 0 {
			score = cv.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			sev = strings.ToUpper(cv.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)
		}
		if sev == "" {
			sev = classifyTextSeverity(enDesc)
		}
		out[cv.ID] = model.Advisory{
			ID:          cv.ID,
			CVEID:       cv.ID,
			Category:    "kernel",
			Ecosystem:   model.EcoLinux,
			Severity:    sev,
			CVSS:        score,
			Package:     "linux",
			Summary:     summary,
			Details:     enDesc,
			PublishedAt: cv.Published,
			URL:         "https://nvd.nist.gov/vuln/detail/" + cv.ID,
		}
	}
	return out
}

func extractCleanKernelSummary(desc string) string {
	const prefix = "In the Linux kernel, the following vulnerability has been resolved:"
	s := strings.TrimSpace(desc)
	if strings.HasPrefix(s, prefix) {
		s = strings.TrimSpace(strings.TrimPrefix(s, prefix))
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return truncateSummary(line, 140)
		}
	}
	return truncateSummary(s, 140)
}

func cleanFeedDescription(raw string) string {
	unesc := html.UnescapeString(raw)
	noTags := htmlTagRe.ReplaceAllString(unesc, " ")
	return strings.Join(strings.Fields(noTags), " ")
}

func firstLineOrText(text, fallback string) string {
	if strings.TrimSpace(text) != "" {
		return text
	}
	return fallback
}

func classifyTextSeverity(text string) string {
	low := strings.ToLower(text)
	switch {
	case strings.Contains(low, "remote code execution") ||
		strings.Contains(low, "arbitrary code") ||
		strings.Contains(low, "use-after-free") ||
		strings.Contains(low, "freed memory") ||
		strings.Contains(low, "out-of-bounds write") ||
		strings.Contains(low, "privilege escalation"):
		return "CRITICAL"
	case strings.Contains(low, "buffer overflow") ||
		strings.Contains(low, "bypass") ||
		strings.Contains(low, "injection") ||
		strings.Contains(low, "memory corruption") ||
		strings.Contains(low, "race condition"):
		return "HIGH"
	default:
		return "MEDIUM"
	}
}

func truncateSummary(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return strings.TrimSpace(s[:maxLen]) + "..."
}
