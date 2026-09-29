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
	var gelen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gelen = r.Header.Clone()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	cfg := &Config{
		UserAgent: "test-agent/9.9",
		Cookie:    "session=gizli123",
		Headers:   []string{"X-Custom: deger42", "Authorization: Bearer tok"},
		Retries:   0,
	}
	rm := newRateManager(0, false)

	res, err := fetch(context.Background(), srv.Client(), rm, cfg, srv.URL)
	if err != nil {
		t.Fatalf("fetch hatasi: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("status 200 beklendi, gelen: %d", res.StatusCode)
	}

	if got := gelen.Get("User-Agent"); got != "test-agent/9.9" {
		t.Errorf("User-Agent = %q, beklenen 'test-agent/9.9'", got)
	}
	if got := gelen.Get("Cookie"); got != "session=gizli123" {
		t.Errorf("Cookie = %q, beklenen 'session=gizli123'", got)
	}
	if got := gelen.Get("X-Custom"); got != "deger42" {
		t.Errorf("X-Custom = %q, beklenen 'deger42'", got)
	}
	if got := gelen.Get("Authorization"); got != "Bearer tok" {
		t.Errorf("Authorization = %q, beklenen 'Bearer tok'", got)
	}
}

func TestCrawlIntegration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><!-- gizli not: admin/admin -->
			<a href="/sayfa2">2</a> <a href="/backup.zip">yedek</a>
			<form action="/login" method="post"><input name="user" type="text"></form></html>`))
	})
	mux.HandleFunc("/sayfa2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><a href="/">geri</a></html>`))
	})
	mux.HandleFunc("/backup.zip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write([]byte("PK-sahte-zip"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Output: "json"}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	if rep.PagesCrawled < 3 {
		t.Errorf("en az 3 sayfa beklendi (/, /sayfa2, /backup.zip), gelen: %d", rep.PagesCrawled)
	}
	if len(rep.Comments) == 0 {
		t.Errorf("gizli yorum bulunmaliydi")
	}
	if len(rep.Forms) == 0 {
		t.Errorf("login formu bulunmaliydi")
	}
	if len(rep.Interesting) == 0 {
		t.Errorf("backup.zip ilginc olarak isaretlenmeliydi")
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
		t.Fatalf("retry sonrasi basari beklendi: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("status 200 beklendi (retry ile), gelen: %d", res.StatusCode)
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
		t.Fatalf("fetch hatasi: %v", err)
	}
	if len(res.Body) > maxBodyBytes {
		t.Errorf("govde limiti asildi: %d > %d", len(res.Body), maxBodyBytes)
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
		t.Fatal("iptal sonrasi bile rapor donmeliydi")
	}

	if rep.PagesCrawled > 50 {
		t.Errorf("iptal edildi ama %d sayfa gezildi (erken durmaliydi)", rep.PagesCrawled)
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
		_, _ = w.Write([]byte("<html>link yok</html>"))
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

	kelimeler := []string{"admin", "secret", "yokboyle", "kesinlikleyok"}
	found := bruteForce(context.Background(), client, rm, cfg, seedURL, kelimeler)

	set := map[string]int{}
	for _, b := range found {
		set[b.URL] = b.Status
	}
	if set[srv.URL+"/admin"] != 200 {
		t.Errorf("/admin 200 olarak bulunmaliydi, gelen: %v", found)
	}
	if set[srv.URL+"/secret"] != 403 {
		t.Errorf("/secret 403 olarak bulunmaliydi")
	}
	if len(found) != 2 {
		t.Errorf("sadece 2 yol bulunmaliydi (404'ler elenmeli), gelen: %d", len(found))
	}
}

func TestParseRobots(t *testing.T) {
	body := `# yorum
User-agent: *
Disallow: /admin/
Disallow: /backup
Disallow: /tmp/*
Allow: /public
Sitemap: https://x.com/sitemap.xml`

	disallow, allow, sitemaps := parseRobots(body)

	dset := map[string]bool{}
	for _, y := range disallow {
		dset[y] = true
	}
	aset := map[string]bool{}
	for _, y := range allow {
		aset[y] = true
	}
	if !dset["/admin/"] || !dset["/backup"] {
		t.Errorf("beklenen disallow yollari eksik: %v", disallow)
	}
	if !aset["/public"] {
		t.Errorf("beklenen allow yolu eksik: %v", allow)
	}

	if dset["/tmp/*"] {
		t.Errorf("ham wildcard yol saklanmamaliydi")
	}
	if !dset["/tmp/"] {
		t.Errorf("wildcard prefix'i /tmp/ cikarilmaliydi: %v", disallow)
	}
	if len(sitemaps) != 1 || sitemaps[0] != "https://x.com/sitemap.xml" {
		t.Errorf("sitemap yanlis: %v", sitemaps)
	}
}

func TestRobotsDiscovery(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>bos sayfa, link yok</html>"))
	})

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /gizli-panel/\n"))
	})

	mux.HandleFunc("/gizli-panel/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>SECRET ADMIN</html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Output: "json", Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	bulundu := false
	for _, p := range rep.Pages {
		if strings.Contains(p.URL, "/gizli-panel/") {
			bulundu = true
		}
	}
	if !bulundu {
		t.Errorf("robots.txt'deki /gizli-panel/ gezilmeliydi. Gezilen: %d sayfa", rep.PagesCrawled)
	}

	robotsHint := false
	for _, sebep := range rep.Interesting {
		if sebep == "robots-disallow" {
			robotsHint = true
		}
	}
	if !robotsHint {
		t.Errorf("robots-disallow ipucu isaretlenmeliydi")
	}
}

func TestAllowedPath(t *testing.T) {
	testler := []struct {
		include, exclude, url string
		beklenen              bool
	}{
		{"", "", "https://x.com/anything", true},
		{"/api/", "", "https://x.com/api/users", true},
		{"/api/", "", "https://x.com/about", false},
		{"", "/logout", "https://x.com/logout", false},
		{"", "/logout", "https://x.com/dashboard", true},
		{"/admin", "/admin/delete", "https://x.com/admin/x", true},
		{"/admin", "/admin/delete", "https://x.com/admin/delete", false},
	}
	for _, tc := range testler {
		cfg := &Config{Include: tc.include, Exclude: tc.exclude}
		if got := allowedPath(cfg, tc.url); got != tc.beklenen {
			t.Errorf("allowedPath(inc=%q exc=%q, %q) = %v, beklenen %v",
				tc.include, tc.exclude, tc.url, got, tc.beklenen)
		}
	}
}

func TestInScope(t *testing.T) {
	testler := []struct {
		base, url, mode string
		beklenen        bool
	}{
		{"go.dev", "https://go.dev/x", "strict", true},
		{"go.dev", "https://pkg.go.dev/x", "strict", false},
		{"go.dev", "https://pkg.go.dev/x", "subdomain", true},
		{"go.dev", "https://evilgo.dev/x", "subdomain", false},
		{"go.dev", "https://go.dev.attacker.com", "subdomain", false},
	}
	for _, tc := range testler {
		if got := inScope(tc.base, tc.url, tc.mode); got != tc.beklenen {
			t.Errorf("inScope(%q, %q, %q) = %v, beklenen %v",
				tc.base, tc.url, tc.mode, got, tc.beklenen)
		}
	}
}
