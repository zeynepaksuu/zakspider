package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRelativeLinkBase(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><a href="/docs/">docs</a></html>`))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/docs/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><a href="chapter2.html">chapter2</a></html>`))
	})
	mux.HandleFunc("/docs/chapter2.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>CORRECT PAGE</html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	correct, wrong := false, false
	for _, p := range rep.Pages {
		if strings.HasSuffix(p.URL, "/docs/chapter2.html") && p.Status == 200 {
			correct = true
		}
		if strings.HasSuffix(p.URL, "/chapter2.html") && !strings.Contains(p.URL, "/docs/") {
			wrong = true
		}
	}
	if !correct {
		t.Errorf("/docs/chapter2.html should have been crawled (relative link must resolve against the page)")
	}
	if wrong {
		t.Errorf("/chapter2.html (root) should not have been crawled (relative link resolved against wrong base)")
	}
}

func TestRedirectScope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><a href="/old">old</a><a href="/outside">outside</a></html>`))
	})
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/new", http.StatusFound)
	})
	mux.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>NEW</html>`))
	})
	mux.HandleFunc("/outside", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://external.invalid/hidden", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	if _, ok := rep.Redirects[srv.URL+"/old"]; !ok {
		t.Errorf("/old -> /new redirect should have been recorded: %v", rep.Redirects)
	}

	for _, p := range rep.Pages {
		if strings.Contains(p.URL, "external.invalid") {
			t.Errorf("off-scope host was crawled: %s", p.URL)
		}
	}

	target, ok := rep.Redirects[srv.URL+"/outside"]
	if !ok || !strings.Contains(target, "external.invalid") {
		t.Errorf("off-scope target for /outside should have been recorded: %v", rep.Redirects)
	}
}

func TestContentTypeSniffing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte(`<html><a href="/found">link</a></html>`))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/found", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>FOUND</html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	found := false
	for _, p := range rep.Pages {
		if strings.HasSuffix(p.URL, "/found") {
			found = true
		}
	}
	if !found {
		t.Errorf("octet-stream should have been sniffed as HTML and /found crawled")
	}
}

func TestRobotsAllowDisallowLabels(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>empty</html>`))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /sec/\nAllow: /pub\n"))
	})
	mux.HandleFunc("/sec/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/pub", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	var gotAllow, gotDisallow bool
	for _, reason := range rep.Interesting {
		switch reason {
		case "robots-allow":
			gotAllow = true
		case "robots-disallow":
			gotDisallow = true
		}
	}
	if !gotAllow {
		t.Errorf("robots-allow label was expected: %v", rep.Interesting)
	}
	if !gotDisallow {
		t.Errorf("robots-disallow label was expected: %v", rep.Interesting)
	}
}

func TestBruteExtensions(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>ok</html>"))
	})
	mux.HandleFunc("/config.bak", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{Workers: 4, Extensions: []string{"bak"}}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	seedURL, _ := url.Parse(srv.URL)

	found := bruteForce(context.Background(), client, rm, cfg, seedURL, []string{"config"})
	var bakFound bool
	for _, b := range found {
		if strings.HasSuffix(b.URL, "/config.bak") {
			bakFound = true
		}
	}
	if !bakFound {
		t.Errorf("config.bak should have been found via the extension: %v", found)
	}
}

func TestBruteRecursive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>ok</html>"))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/admin/secret", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{Workers: 4, BruteRecursive: true, BruteDepth: 1}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	seedURL, _ := url.Parse(srv.URL)

	found := bruteForce(context.Background(), client, rm, cfg, seedURL, []string{"admin", "secret"})
	set := map[string]bool{}
	for _, b := range found {
		set[b.URL] = true
	}
	if !set[srv.URL+"/admin"] {
		t.Errorf("/admin should have been found: %v", found)
	}
	if !set[srv.URL+"/admin/secret"] {
		t.Errorf("/admin/secret should have been found recursively: %v", found)
	}
}

func TestExtractSecrets(t *testing.T) {
	body := []byte(`
		const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123456";
		aws = "AKIAIOSFODNN7EXAMPLE";
		var conf = { api_key: "s3cr3t_value_123" };
	`)
	got := extractSecrets(body)
	types := map[string]bool{}
	for _, s := range got {
		types[s.Type] = true
	}
	for _, expected := range []string{"jwt", "aws-access-key", "generic-secret"} {
		if !types[expected] {
			t.Errorf("secret type not found: %s (got: %+v)", expected, got)
		}
	}
}

func TestBodyDedup(t *testing.T) {
	same := `<html>SAME CONTENT</html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><a href="/a">a</a><a href="/b">b</a></html>`))
		case "/a", "/b":
			_, _ = w.Write([]byte(same))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 1, Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	if len(rep.Duplicates) == 0 {
		t.Errorf("/a and /b share the same body -> at least 1 duplicate expected")
	}
}

func TestDepthLimit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><a href="/level1">1</a></html>`))
		case "/level1":
			_, _ = w.Write([]byte(`<html><a href="/level2">2</a></html>`))
		case "/level2":
			_, _ = w.Write([]byte(`<html>deep</html>`))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 2, Quiet: true, MaxDepth: 1}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	for _, p := range rep.Pages {
		if strings.HasSuffix(p.URL, "/level2") {
			t.Errorf("with depth=1, /level2 (depth 2) should not have been crawled")
		}
	}

	var s1 bool
	for _, p := range rep.Pages {
		if strings.HasSuffix(p.URL, "/level1") {
			s1 = true
		}
	}
	if !s1 {
		t.Errorf("with depth=1, /level1 should have been crawled")
	}
}

func TestRateManagerPerHost(t *testing.T) {
	g := newRateManager(5, false)
	if g.forHost("a.com") != g.forHost("b.com") {
		t.Errorf("in global mode all hosts should share the same limiter")
	}

	p := newRateManager(5, true)
	if p.forHost("a.com") != p.forHost("a.com") {
		t.Errorf("the same host should return the same limiter")
	}
	if p.forHost("a.com") == p.forHost("b.com") {
		t.Errorf("different hosts should get different limiters")
	}
}

func TestExtractFlags(t *testing.T) {
	re := flagRegex("HTB")
	body := []byte(`on the page HTB{first_flag_123} appears, again HTB{first_flag_123},
		and also HTB{second-flag} and unrelated FLAG{not_this} plus HTB{} empty.`)
	got := extractFlags(body, re)
	set := map[string]bool{}
	for _, f := range got {
		set[f] = true
	}
	if !set["HTB{first_flag_123}"] || !set["HTB{second-flag}"] {
		t.Errorf("expected flags not found: %v", got)
	}
	if set["FLAG{not_this}"] {
		t.Errorf("non-HTB format should not have been extracted: %v", got)
	}
	if set["HTB{}"] {
		t.Errorf("empty flag should not have been extracted")
	}

	count := 0
	for _, f := range got {
		if f == "HTB{first_flag_123}" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("a repeated flag should have been deduplicated, count: %d", count)
	}

	if extractFlags(body, nil) != nil {
		t.Errorf("no flag should be searched when flagRe is nil")
	}
}

func TestFlagInCrawl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><!-- HTB{flag_in_comment} --><a href="/hidden">g</a></html>`))
		case "/hidden":
			_, _ = w.Write([]byte(`<html>congrats: HTB{flag_in_body}</html>`))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Quiet: true, FlagFormat: "HTB"}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	set := map[string]bool{}
	for _, f := range rep.Flags {
		set[f.Flag] = true
	}
	if !set["HTB{flag_in_comment}"] {
		t.Errorf("the flag in the comment should have been found: %v", rep.Flags)
	}
	if !set["HTB{flag_in_body}"] {
		t.Errorf("the flag in the page body should have been found: %v", rep.Flags)
	}
}

func TestRobotsAsTargets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>no links</html>`))
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin/*\nDisallow: /secret-backup\n"))
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>ADMIN INDEX</html>`))
	})
	mux.HandleFunc("/secret-backup", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	if rep.Robots == nil || !rep.Robots.Found {
		t.Fatalf("robots.txt should have been found and reported")
	}

	status := map[string]int{}
	for _, p := range rep.Robots.Paths {
		status[p.Path] = p.Status
	}
	if status[srv.URL+"/admin/"] != 200 {
		t.Errorf("/admin/ (wildcard prefix) should have been crawled as a target with 200: %+v", rep.Robots.Paths)
	}
	if status[srv.URL+"/secret-backup"] != 403 {
		t.Errorf("/secret-backup should have been targeted from robots and reported as 403: %+v", rep.Robots.Paths)
	}

	var adminCrawled bool
	for _, p := range rep.Pages {
		if strings.HasSuffix(p.URL, "/admin/") {
			adminCrawled = true
		}
	}
	if !adminCrawled {
		t.Errorf("/admin/ should have been queued and crawled (robots bypass)")
	}
}

func TestNormalizeDeepBase(t *testing.T) {
	base, _ := url.Parse("https://t.com/docs/guide/")
	got, ok := normalize(base, "chapter2.html")
	if !ok || got != "https://t.com/docs/guide/chapter2.html" {
		t.Errorf("relative resolution wrong: got=%q ok=%v", got, ok)
	}
	got2, ok2 := normalize(base, "../parent")
	if !ok2 || got2 != "https://t.com/docs/parent" {
		t.Errorf("parent-directory resolution wrong: got=%q", got2)
	}
}
