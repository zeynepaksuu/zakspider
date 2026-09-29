package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/fatih/color"
)

type PageInfo struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
	Depth       int    `json:"depth"`
	RedirectTo  string `json:"redirect_to,omitempty"`
}

type FormReport struct {
	URL         string      `json:"url"`
	Action      string      `json:"action"`
	Method      string      `json:"method"`
	Inputs      []FormInput `json:"inputs"`
	HasCSRF     bool        `json:"has_csrf"`
	HasPassword bool        `json:"has_password"`
}

type CommentReport struct {
	URL     string `json:"url"`
	Comment string `json:"comment"`
}

type BruteResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}

type FlagFinding struct {
	Flag string `json:"flag"`
	URL  string `json:"url"`
}

type RobotsPath struct {
	Path   string `json:"path"`
	Source string `json:"source"`
	Status int    `json:"status"`
}

type RobotsInfo struct {
	URL      string       `json:"url"`
	Found    bool         `json:"found"`
	Raw      string       `json:"raw,omitempty"`
	Paths    []RobotsPath `json:"paths"`
	Sitemaps []string     `json:"sitemaps"`
}

type Report struct {
	Target         string            `json:"target"`
	Scope          string            `json:"scope"`
	Workers        int               `json:"workers"`
	DurationMs     int64             `json:"duration_ms"`
	PagesCrawled   int               `json:"pages_crawled"`
	URLsDiscovered int               `json:"urls_discovered"`
	StatusCounts   map[int]int       `json:"status_counts"`
	Pages          []PageInfo        `json:"pages"`
	NotableStatus  map[string][]int  `json:"notable_status"`
	Interesting    map[string]string `json:"interesting"`
	JSEndpoints    []string          `json:"js_endpoints"`
	Forms          []FormReport      `json:"forms"`
	Comments       []CommentReport   `json:"comments"`
	Secrets        []Secret          `json:"secrets"`
	Flags          []FlagFinding     `json:"flags"`
	BruteFound     []BruteResult     `json:"brute_found"`
	Robots         *RobotsInfo       `json:"robots,omitempty"`
	Redirects      map[string]string `json:"redirects"`
	Duplicates     map[string]string `json:"duplicates"`
}

func writeJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

type streamEvent struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

func newJSONLEmitter(w io.Writer) func(string, any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	var mu sync.Mutex
	return func(t string, data any) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(streamEvent{Type: t, Data: data})
	}
}

var (
	colorGreen   = color.New(color.FgGreen).SprintfFunc()
	colorCyan    = color.New(color.FgCyan).SprintfFunc()
	colorYellow  = color.New(color.FgYellow).SprintfFunc()
	colorMagenta = color.New(color.FgMagenta).SprintfFunc()
	colorRed     = color.New(color.FgRed).SprintfFunc()
	colorGray    = color.New(color.FgHiBlack).SprintfFunc()
)

func colorStatus(code int) string {
	s := fmt.Sprintf("%d", code)
	switch {
	case code >= 200 && code < 300:
		return colorGreen("%s", s)
	case code >= 300 && code < 400:
		return colorCyan("%s", s)
	case code == 401 || code == 403:
		return colorYellow("%s", s)
	case code >= 400 && code < 500:
		return colorMagenta("%s", s)
	case code >= 500:
		return colorRed("%s", s)
	default:
		return s
	}
}

func setColorEnabled(enabled bool) {
	color.NoColor = !enabled
}

func printTextReport(w io.Writer, r *Report) {
	fmt.Fprintf(w, "\n==================== SUMMARY ====================\n")
	fmt.Fprintf(w, "  Duration        : %d ms\n", r.DurationMs)
	fmt.Fprintf(w, "  Workers         : %d\n", r.Workers)
	fmt.Fprintf(w, "  Pages crawled   : %d\n", r.PagesCrawled)
	fmt.Fprintf(w, "  URLs discovered : %d\n", r.URLsDiscovered)
	fmt.Fprintf(w, "  Status breakdown:\n")
	kodlar := make([]int, 0, len(r.StatusCounts))
	for k := range r.StatusCounts {
		kodlar = append(kodlar, k)
	}
	sort.Ints(kodlar)
	for _, k := range kodlar {
		fmt.Fprintf(w, "    %s : %d\n", colorStatus(k), r.StatusCounts[k])
	}

	fmt.Fprintf(w, "\n==================== RECON FINDINGS ====================\n")

	if len(r.Flags) > 0 {
		fmt.Fprintf(w, "\n%s CTF flags found: %d\n", colorGreen("[FLAG]"), len(r.Flags))
		for _, f := range r.Flags {
			fmt.Fprintf(w, "    %s\n      %s\n", colorGreen("%s", f.Flag), colorGray("source: %s", f.URL))
		}
	}

	if r.Robots != nil && r.Robots.Found {
		fmt.Fprintf(w, "\n%s robots.txt found -> crawling its paths as targets (bypassed): %s\n",
			colorRed("[!]"), colorGray("%s", r.Robots.URL))
		for _, p := range r.Robots.Paths {
			durum := "not reached"
			if p.Status > 0 {
				durum = colorStatus(p.Status)
			}
			fmt.Fprintf(w, "    [%s] %-9s %s\n", durum, "("+p.Source+")", p.Path)
		}
		if len(r.Robots.Sitemaps) > 0 {
			fmt.Fprintf(w, "    %s\n", colorGray("sitemaps: %v", r.Robots.Sitemaps))
		}
	}

	if len(r.NotableStatus) > 0 {
		fmt.Fprintf(w, "\n%s Notable status (401/403/5xx): %d\n", colorYellow("[!]"), len(r.NotableStatus))
		for _, u := range sortedKeys(r.NotableStatus) {
			fmt.Fprintf(w, "    %v  %s\n", r.NotableStatus[u], u)
		}
	}

	if len(r.Interesting) > 0 {
		fmt.Fprintf(w, "\n%s Interesting/sensitive paths: %d\n", colorRed("[!]"), len(r.Interesting))
		for _, u := range sortedKeysStr(r.Interesting) {
			fmt.Fprintf(w, "    %s  %s\n", colorGray("(%s)", r.Interesting[u]), u)
		}
	}

	if len(r.Secrets) > 0 {
		fmt.Fprintf(w, "\n%s Secrets / tokens leaked: %d\n", colorRed("[!!]"), len(r.Secrets))
		for _, s := range r.Secrets {
			fmt.Fprintf(w, "    %s %s\n      %s\n", colorRed("[%s]", s.Type), s.Match, colorGray("source: %s", s.URL))
		}
	}

	if len(r.JSEndpoints) > 0 {
		fmt.Fprintf(w, "\n%s Endpoints extracted from JS: %d\n", colorCyan("[!]"), len(r.JSEndpoints))
		for _, e := range r.JSEndpoints {
			fmt.Fprintf(w, "    %s\n", e)
		}
	}

	if len(r.Forms) > 0 {
		fmt.Fprintf(w, "\n%s Forms found: %d\n", colorYellow("[!]"), len(r.Forms))
		for _, f := range r.Forms {
			alanlar := make([]string, 0, len(f.Inputs))
			for _, in := range f.Inputs {
				alanlar = append(alanlar, fmt.Sprintf("%s(%s)", in.Name, in.Type))
			}
			etiketler := ""
			if f.HasPassword {
				etiketler += colorYellow(" [login]")
			}
			if !f.HasCSRF && (f.Method == "POST" || f.HasPassword) {
				etiketler += colorRed(" [no-csrf]")
			}
			fmt.Fprintf(w, "    [%s %s]%s fields: %v\n      %s\n",
				f.Method, f.Action, etiketler, alanlar, colorGray("source: %s", f.URL))
		}
	}

	if len(r.Comments) > 0 {
		fmt.Fprintf(w, "\n%s HTML comments: %d\n", colorCyan("[!]"), len(r.Comments))
		for _, c := range r.Comments {
			y := c.Comment
			if len(y) > 120 {
				y = y[:120] + "..."
			}
			fmt.Fprintf(w, "    <!-- %s -->\n      %s\n", y, colorGray("source: %s", c.URL))
		}
	}

	if len(r.BruteFound) > 0 {
		fmt.Fprintf(w, "\n%s Paths found via brute-force: %d\n", colorRed("[!]"), len(r.BruteFound))
		for _, b := range r.BruteFound {
			fmt.Fprintf(w, "    [%s] %s\n", colorStatus(b.Status), b.URL)
		}
	}

	if len(r.Redirects) > 0 {
		fmt.Fprintf(w, "\n%s Redirects observed: %d\n", colorCyan("[!]"), len(r.Redirects))
		for _, u := range sortedKeysStr(r.Redirects) {
			fmt.Fprintf(w, "    %s -> %s\n", u, r.Redirects[u])
		}
	}

	if len(r.Duplicates) > 0 {
		fmt.Fprintf(w, "\n%s Duplicate content (same body, different URL): %d\n", colorGray("[i]"), len(r.Duplicates))
		for _, u := range sortedKeysStr(r.Duplicates) {
			fmt.Fprintf(w, "    %s == %s\n", u, r.Duplicates[u])
		}
	}

	if len(r.NotableStatus) == 0 && len(r.Interesting) == 0 && len(r.Secrets) == 0 &&
		len(r.JSEndpoints) == 0 && len(r.Forms) == 0 && len(r.Comments) == 0 &&
		len(r.BruteFound) == 0 {
		fmt.Fprintln(w, "  (no findings)")
	}
}

func sortedKeys(m map[string][]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sortedKeysStr(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
