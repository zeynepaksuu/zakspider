package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestFetchHeaders(t *testing.T) {
	var received http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	cfg := &Config{
		UserAgent: "test-agent/9.9",
		Cookie:    "session=secret123",
		Headers:   []string{"X-Custom: value42", "Authorization: Bearer tok"},
		Retries:   0,
	}
	rm := newRateManager(0, false)

	res, err := fetch(context.Background(), srv.Client(), rm, cfg, srv.URL)
	if err != nil {
		t.Fatalf("fetch error: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected status 200, got: %d", res.StatusCode)
	}

	if got := received.Get("User-Agent"); got != "test-agent/9.9" {
		t.Errorf("User-Agent = %q, expected 'test-agent/9.9'", got)
	}
	if got := received.Get("Cookie"); got != "session=secret123" {
		t.Errorf("Cookie = %q, expected 'session=secret123'", got)
	}
	if got := received.Get("X-Custom"); got != "value42" {
		t.Errorf("X-Custom = %q, expected 'value42'", got)
	}
	if got := received.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("Authorization = %q, expected 'Bearer tok'", got)
	}
}

func TestCrawlIntegration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><!-- hidden note: admin/admin -->
			<a href="/page2">2</a> <a href="/backup.zip">backup</a>
			<form action="/login" method="post"><input name="user" type="text"></form></html>`))
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><a href="/">back</a></html>`))
	})
	mux.HandleFunc("/backup.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte("PK-fake-zip"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Output: "json"}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	if rep.PagesCrawled < 3 {
		t.Errorf("expected at least 3 pages (/, /page2, /backup.zip), got: %d", rep.PagesCrawled)
	}
	if len(rep.Comments) == 0 {
		t.Errorf("the hidden comment should have been found")
	}
	if len(rep.Forms) == 0 {
		t.Errorf("the login form should have been found")
	}
	if len(rep.Interesting) == 0 {
		t.Errorf("backup.zip should have been flagged as interesting")
	}
}

func TestFetchRetry(t *testing.T) {
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		c := n
		mu.Unlock()
		if c < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := &Config{Retries: 3}
	rm := newRateManager(0, false)
	res, err := fetch(context.Background(), srv.Client(), rm, cfg, srv.URL)
	if err != nil {
		t.Fatalf("expected success after retry: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("expected status 200 (after retry), got: %d", res.StatusCode)
	}
}

func TestBodySizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(make([]byte, maxBodyBytes+5000))
	}))
	defer srv.Close()

	cfg := &Config{Retries: 0}
	rm := newRateManager(0, false)
	res, err := fetch(context.Background(), srv.Client(), rm, cfg, srv.URL)
	if err != nil {
		t.Fatalf("fetch error: %v", err)
	}
	if len(res.Body) > maxBodyBytes {
		t.Errorf("body limit exceeded: %d > %d", len(res.Body), maxBodyBytes)
	}
}

func TestCrawlGracefulShutdown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a></html>`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &Config{ScopeMode: "strict", MaxPages: 100000, Workers: 4, Output: "json"}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)

	rep := crawl(ctx, client, rm, srv.URL, cfg, nil)
	if rep == nil {
		t.Fatal("a report should be returned even after cancellation")
	}
	if rep.PagesCrawled > 50 {
		t.Errorf("cancelled but %d pages were crawled (should have stopped early)", rep.PagesCrawled)
	}
}

func benchServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var sb strings.Builder
		sb.WriteString("<html>")
		for i := 0; i < 20; i++ {
			fmt.Fprintf(&sb, `<a href="/p%d">%d</a>`, i, i)
		}
		sb.WriteString("</html>")
		_, _ = w.Write([]byte(sb.String()))
	}))
}

func BenchmarkCrawl1(b *testing.B)  { benchCrawl(b, 1) }
func BenchmarkCrawl8(b *testing.B)  { benchCrawl(b, 8) }
func BenchmarkCrawl16(b *testing.B) { benchCrawl(b, 16) }

func benchCrawl(b *testing.B, workers int) {
	srv := benchServer()
	defer srv.Close()
	cfg := &Config{ScopeMode: "strict", MaxPages: 100, Workers: workers, Output: "json", Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crawl(context.Background(), client, rm, srv.URL, cfg, nil)
	}
}

func TestBruteForce(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>no links</html>"))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{Workers: 4}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	seedURL, _ := url.Parse(srv.URL)

	words := []string{"admin", "secret", "nosuchthing", "definitelynot"}
	found := bruteForce(context.Background(), client, rm, cfg, seedURL, words)

	set := map[string]int{}
	for _, b := range found {
		set[b.URL] = b.Status
	}
	if set[srv.URL+"/admin"] != 200 {
		t.Errorf("/admin should have been found as 200, got: %v", found)
	}
	if set[srv.URL+"/secret"] != 403 {
		t.Errorf("/secret should have been found as 403")
	}
	if len(found) != 2 {
		t.Errorf("only 2 paths should have been found (404s filtered out), got: %d", len(found))
	}
}

func TestParseRobots(t *testing.T) {
	body := `# comment
User-agent: *
Disallow: /admin/
Disallow: /backup
Disallow: /tmp/*
Allow: /public
Sitemap: https://x.com/sitemap.xml`

	disallow, allow, sitemaps := parseRobots(body)

	dset := map[string]bool{}
	for _, p := range disallow {
		dset[p] = true
	}
	aset := map[string]bool{}
	for _, p := range allow {
		aset[p] = true
	}
	if !dset["/admin/"] || !dset["/backup"] {
		t.Errorf("expected disallow paths missing: %v", disallow)
	}
	if !aset["/public"] {
		t.Errorf("expected allow path missing: %v", allow)
	}
	if dset["/tmp/*"] {
		t.Errorf("raw wildcard path should not have been kept")
	}
	if !dset["/tmp/"] {
		t.Errorf("wildcard prefix /tmp/ should have been extracted: %v", disallow)
	}
	if len(sitemaps) != 1 || sitemaps[0] != "https://x.com/sitemap.xml" {
		t.Errorf("wrong sitemap: %v", sitemaps)
	}
}

func TestRobotsDiscovery(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>empty page, no links</html>"))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /hidden-panel/\n"))
	})
	mux.HandleFunc("/hidden-panel/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>SECRET ADMIN</html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Output: "json", Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	found := false
	for _, p := range rep.Pages {
		if strings.Contains(p.URL, "/hidden-panel/") {
			found = true
		}
	}
	if !found {
		t.Errorf("/hidden-panel/ from robots.txt should have been crawled. Crawled: %d pages", rep.PagesCrawled)
	}

	robotsHint := false
	for _, reason := range rep.Interesting {
		if reason == "robots-disallow" {
			robotsHint = true
		}
	}
	if !robotsHint {
		t.Errorf("robots-disallow hint should have been flagged")
	}
}

func TestAllowedPath(t *testing.T) {
	cases := []struct {
		include, exclude, url string
		expected              bool
	}{
		{"", "", "https://x.com/anything", true},
		{"/api/", "", "https://x.com/api/users", true},
		{"/api/", "", "https://x.com/about", false},
		{"", "/logout", "https://x.com/logout", false},
		{"", "/logout", "https://x.com/dashboard", true},
		{"/admin", "/admin/delete", "https://x.com/admin/x", true},
		{"/admin", "/admin/delete", "https://x.com/admin/delete", false},
	}
	for _, tc := range cases {
		cfg := &Config{Include: tc.include, Exclude: tc.exclude}
		if got := allowedPath(cfg, tc.url); got != tc.expected {
			t.Errorf("allowedPath(inc=%q exc=%q, %q) = %v, expected %v",
				tc.include, tc.exclude, tc.url, got, tc.expected)
		}
	}
}

func TestInScope(t *testing.T) {
	cases := []struct {
		base, url, mode string
		expected        bool
	}{
		{"go.dev", "https://go.dev/x", "strict", true},
		{"go.dev", "https://pkg.go.dev/x", "strict", false},
		{"go.dev", "https://pkg.go.dev/x", "subdomain", true},
		{"go.dev", "https://evilgo.dev/x", "subdomain", false},
		{"go.dev", "https://go.dev.attacker.com", "subdomain", false},
	}
	for _, tc := range cases {
		if got := inScope(tc.base, tc.url, tc.mode); got != tc.expected {
			t.Errorf("inScope(%q, %q, %q) = %v, expected %v",
				tc.base, tc.url, tc.mode, got, tc.expected)
		}
	}
}
