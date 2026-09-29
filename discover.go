package main

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

type discovery struct {
	url    string
	source string
}

var sitemapLocRe = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)

func scanRobotsSitemap(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, seedURL *url.URL) ([]discovery, *RobotsInfo) {
	origin := seedURL.Scheme + "://" + seedURL.Host
	var results []discovery
	info := &RobotsInfo{URL: origin + "/robots.txt"}

	if res, err := fetch(ctx, client, rm, cfg, origin+"/robots.txt"); err == nil && res.StatusCode == 200 {
		info.Found = true

		raw := string(res.Body)
		if len(raw) > 8192 {
			raw = raw[:8192] + "\n...(truncated)"
		}
		info.Raw = raw

		disallow, allow, sitemaps := parseRobots(string(res.Body))
		for _, p := range disallow {
			if abs, ok := toAbsolute(origin, p); ok {
				results = append(results, discovery{url: abs, source: "robots-disallow"})
			}
		}

		for _, p := range allow {
			if abs, ok := toAbsolute(origin, p); ok {
				results = append(results, discovery{url: abs, source: "robots-allow"})
			}
		}
		info.Sitemaps = sitemaps

		for _, sm := range sitemaps {
			results = append(results, scanSitemap(ctx, client, rm, cfg, sm)...)
		}
	}

	results = append(results, scanSitemap(ctx, client, rm, cfg, origin+"/sitemap.xml")...)

	return results, info
}

func scanSitemap(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, sitemapURL string) []discovery {
	res, err := fetch(ctx, client, rm, cfg, sitemapURL)
	if err != nil || res.StatusCode != 200 {
		return nil
	}
	var results []discovery
	for _, m := range sitemapLocRe.FindAllStringSubmatch(string(res.Body), -1) {
		loc := strings.TrimSpace(m[1])
		if loc != "" {
			results = append(results, discovery{url: loc, source: "sitemap"})
		}
	}
	return results
}

func parseRobots(body string) (disallow []string, allow []string, sitemaps []string) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "disallow":

			if p := cleanRobotsPath(value); p != "" {
				disallow = append(disallow, p)
			}
		case "allow":
			if p := cleanRobotsPath(value); p != "" {
				allow = append(allow, p)
			}
		case "sitemap":
			if value != "" {
				sitemaps = append(sitemaps, value)
			}
		}
	}
	return disallow, allow, sitemaps
}

func cleanRobotsPath(value string) string {
	value = strings.TrimSpace(value)
	if i := strings.IndexByte(value, '*'); i >= 0 {
		value = value[:i]
	}
	value = strings.TrimSuffix(value, "$")
	value = strings.TrimSpace(value)
	if value == "" || value == "/" {
		return ""
	}
	return value
}

func loadWordlist(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		k := strings.TrimSpace(sc.Text())
		if k == "" || strings.HasPrefix(k, "#") {
			continue
		}
		words = append(words, k)
	}
	return words, sc.Err()
}

func bruteForce(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, seedURL *url.URL, words []string) []BruteResult {
	origin := seedURL.Scheme + "://" + seedURL.Host

	softStatus, softLen, softVar := soft404Baseline(ctx, client, rm, cfg, origin)

	maxDepth := 0
	if cfg.BruteRecursive {
		maxDepth = cfg.BruteDepth
		if maxDepth < 1 {
			maxDepth = 1
		}
	}

	seenURL := make(map[string]struct{})
	seenBase := map[string]struct{}{"": {}}
	bases := []string{""}
	var results []BruteResult

	for depth := 0; depth <= maxDepth && len(bases) > 0; depth++ {
		cands := bruteCandidates(origin, bases, words, cfg.Extensions)
		found := bruteFetch(ctx, client, rm, cfg, cands, softStatus, softLen, softVar, seenURL)
		var nextBases []string
		for _, br := range found {
			results = append(results, br)
			if cfg.BruteRecursive && depth < maxDepth && looksLikeDir(br) {
				if u, err := url.Parse(br.URL); err == nil {
					b := strings.TrimRight(u.Path, "/")
					if _, ok := seenBase[b]; !ok {
						seenBase[b] = struct{}{}
						nextBases = append(nextBases, b)
					}
				}
			}
		}
		bases = nextBases
	}
	return results
}

func bruteCandidates(origin string, bases, words, exts []string) []string {
	var cands []string
	for _, base := range bases {
		base = strings.TrimRight(base, "/")
		for _, k := range words {
			k = strings.Trim(strings.TrimSpace(k), "/")
			if k == "" {
				continue
			}
			cands = append(cands, origin+base+"/"+k)
			for _, e := range exts {
				e = strings.TrimPrefix(strings.TrimSpace(e), ".")
				if e == "" {
					continue
				}
				cands = append(cands, origin+base+"/"+k+"."+e)
			}
		}
	}
	return cands
}

func bruteFetch(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, cands []string, softStatus, softLen int, softVar bool, seenURL map[string]struct{}) []BruteResult {
	jobs := make(chan string)
	var mu sync.Mutex
	var results []BruteResult

	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				res, err := fetch(ctx, client, rm, cfg, u)
				if err != nil || res.StatusCode == 404 {
					continue
				}
				if softVar && res.StatusCode == softStatus && sizeClose(len(res.Body), softLen) {
					continue
				}
				mu.Lock()
				results = append(results, BruteResult{URL: u, Status: res.StatusCode})
				mu.Unlock()
			}
		}()
	}

feed:
	for _, u := range cands {
		mu.Lock()
		_, seen := seenURL[u]
		if !seen {
			seenURL[u] = struct{}{}
		}
		mu.Unlock()
		if seen {
			continue
		}
		select {
		case jobs <- u:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func looksLikeDir(br BruteResult) bool {
	switch br.Status {
	case 200, 301, 302, 307, 308, 403:
	default:
		return false
	}
	u, err := url.Parse(br.URL)
	if err != nil {
		return false
	}
	seg := path.Base(u.Path)
	return seg != "" && seg != "/" && !strings.Contains(seg, ".")
}

func soft404Baseline(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, origin string) (status, length int, ok bool) {
	r1 := probe404(ctx, client, rm, cfg, origin)
	r2 := probe404(ctx, client, rm, cfg, origin)
	if r1 == nil || r2 == nil {
		return 0, 0, false
	}

	if r1.StatusCode == 404 || r2.StatusCode == 404 {
		return 0, 0, false
	}

	if r1.StatusCode != r2.StatusCode || !sizeClose(len(r1.Body), len(r2.Body)) {
		return 0, 0, false
	}
	return r1.StatusCode, (len(r1.Body) + len(r2.Body)) / 2, true
}

func probe404(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, origin string) *FetchResult {
	urlPath := fmt.Sprintf("/zakspider-notfound-%d-%d", time.Now().UnixNano(), rand.Intn(1_000_000))
	res, err := fetch(ctx, client, rm, cfg, origin+urlPath)
	if err != nil {
		return nil
	}
	return res
}

func sizeClose(a, b int) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	tol := b / 20
	if tol < 32 {
		tol = 32
	}
	return d <= tol
}

func toAbsolute(origin, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, true
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return origin + path, true
}
