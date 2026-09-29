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

type kesif struct {
	url    string
	kaynak string
}

var sitemapLocRe = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)

func scanRobotsSitemap(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, seedURL *url.URL) ([]kesif, *RobotsInfo) {
	origin := seedURL.Scheme + "://" + seedURL.Host
	var sonuc []kesif
	info := &RobotsInfo{URL: origin + "/robots.txt"}

	if res, err := fetch(ctx, client, rm, cfg, origin+"/robots.txt"); err == nil && res.StatusCode == 200 {
		info.Found = true

		raw := string(res.Body)
		if len(raw) > 8192 {
			raw = raw[:8192] + "\n...(kirpildi)"
		}
		info.Raw = raw

		disallow, allow, sitemaps := parseRobots(string(res.Body))
		for _, p := range disallow {
			if abs, ok := toAbsolute(origin, p); ok {
				sonuc = append(sonuc, kesif{url: abs, kaynak: "robots-disallow"})
			}
		}

		for _, p := range allow {
			if abs, ok := toAbsolute(origin, p); ok {
				sonuc = append(sonuc, kesif{url: abs, kaynak: "robots-allow"})
			}
		}
		info.Sitemaps = sitemaps

		for _, sm := range sitemaps {
			sonuc = append(sonuc, scanSitemap(ctx, client, rm, cfg, sm)...)
		}
	}

	sonuc = append(sonuc, scanSitemap(ctx, client, rm, cfg, origin+"/sitemap.xml")...)

	return sonuc, info
}

func scanSitemap(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, sitemapURL string) []kesif {
	res, err := fetch(ctx, client, rm, cfg, sitemapURL)
	if err != nil || res.StatusCode != 200 {
		return nil
	}
	var sonuc []kesif
	for _, m := range sitemapLocRe.FindAllStringSubmatch(string(res.Body), -1) {
		loc := strings.TrimSpace(m[1])
		if loc != "" {
			sonuc = append(sonuc, kesif{url: loc, kaynak: "sitemap"})
		}
	}
	return sonuc
}

func parseRobots(body string) (disallow []string, allow []string, sitemaps []string) {
	for _, satir := range strings.Split(body, "\n") {
		satir = strings.TrimSpace(satir)
		if satir == "" || strings.HasPrefix(satir, "#") {
			continue
		}
		anahtar, deger, ok := strings.Cut(satir, ":")
		if !ok {
			continue
		}
		anahtar = strings.ToLower(strings.TrimSpace(anahtar))
		deger = strings.TrimSpace(deger)
		switch anahtar {
		case "disallow":

			if p := cleanRobotsPath(deger); p != "" {
				disallow = append(disallow, p)
			}
		case "allow":
			if p := cleanRobotsPath(deger); p != "" {
				allow = append(allow, p)
			}
		case "sitemap":
			if deger != "" {
				sitemaps = append(sitemaps, deger)
			}
		}
	}
	return disallow, allow, sitemaps
}

func cleanRobotsPath(deger string) string {
	deger = strings.TrimSpace(deger)
	if i := strings.IndexByte(deger, '*'); i >= 0 {
		deger = deger[:i]
	}
	deger = strings.TrimSuffix(deger, "$")
	deger = strings.TrimSpace(deger)
	if deger == "" || deger == "/" {
		return ""
	}
	return deger
}

func loadWordlist(dosya string) ([]string, error) {
	f, err := os.Open(dosya)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var kelimeler []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		k := strings.TrimSpace(sc.Text())
		if k == "" || strings.HasPrefix(k, "#") {
			continue
		}
		kelimeler = append(kelimeler, k)
	}
	return kelimeler, sc.Err()
}

func bruteForce(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, seedURL *url.URL, kelimeler []string) []BruteResult {
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
	var bulunan []BruteResult

	for depth := 0; depth <= maxDepth && len(bases) > 0; depth++ {
		cands := bruteCandidates(origin, bases, kelimeler, cfg.Extensions)
		found := bruteFetch(ctx, client, rm, cfg, cands, softStatus, softLen, softVar, seenURL)
		var nextBases []string
		for _, br := range found {
			bulunan = append(bulunan, br)
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
	return bulunan
}

func bruteCandidates(origin string, bases, kelimeler, exts []string) []string {
	var cands []string
	for _, base := range bases {
		base = strings.TrimRight(base, "/")
		for _, k := range kelimeler {
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
	var bulunan []BruteResult

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
				bulunan = append(bulunan, BruteResult{URL: u, Status: res.StatusCode})
				mu.Unlock()
			}
		}()
	}

feed:
	for _, u := range cands {
		mu.Lock()
		_, gorildi := seenURL[u]
		if !gorildi {
			seenURL[u] = struct{}{}
		}
		mu.Unlock()
		if gorildi {
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
	return bulunan
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
	yol := fmt.Sprintf("/zakspider-yok-%d-%d", time.Now().UnixNano(), rand.Intn(1_000_000))
	res, err := fetch(ctx, client, rm, cfg, origin+yol)
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
