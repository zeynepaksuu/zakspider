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
		_, _ = w.Write([]byte(`<html><a href="chapter2.html">bolum2</a></html>`))
	})
	mux.HandleFunc("/docs/chapter2.html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>DOGRU SAYFA</html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	dogru, yanlis := false, false
	for _, p := range rep.Pages {
		if strings.HasSuffix(p.URL, "/docs/chapter2.html") && p.Status == 200 {
			dogru = true
		}
		if strings.HasSuffix(p.URL, "/chapter2.html") && !strings.Contains(p.URL, "/docs/") {
			yanlis = true
		}
	}
	if !dogru {
		t.Errorf("/docs/chapter2.html gezilmeliydi (goreli link sayfaya gore cozulmeli)")
	}
	if yanlis {
		t.Errorf("/chapter2.html (kok) gezilmemeliydi (goreli link yanlis base'e cozulmus)")
	}
}

func TestRedirectScope(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><a href="/eski">eski</a><a href="/disari">disari</a></html>`))
	})
	mux.HandleFunc("/eski", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/yeni", http.StatusFound)
	})
	mux.HandleFunc("/yeni", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>YENI</html>`))
	})
	mux.HandleFunc("/disari", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://external.invalid/gizli", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	if _, ok := rep.Redirects[srv.URL+"/eski"]; !ok {
		t.Errorf("/eski -> /yeni yonlendirmesi kaydedilmeliydi: %v", rep.Redirects)
	}

	for _, p := range rep.Pages {
		if strings.Contains(p.URL, "external.invalid") {
			t.Errorf("scope disi host gezildi: %s", p.URL)
		}
	}

	hedef, ok := rep.Redirects[srv.URL+"/disari"]
	if !ok || !strings.Contains(hedef, "external.invalid") {
		t.Errorf("/disari icin scope disi hedef kaydedilmeliydi: %v", rep.Redirects)
	}
}

func TestContentTypeSniffing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte(`<html><a href="/bulundu">link</a></html>`))
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/bulundu", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>BULUNDU</html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{ScopeMode: "strict", MaxPages: 50, Workers: 4, Quiet: true}
	client, _ := newClient(cfg)
	rm := newRateManager(0, false)
	rep := crawl(context.Background(), client, rm, srv.URL, cfg, nil)

	bulundu := false
	for _, p := range rep.Pages {
		if strings.HasSuffix(p.URL, "/bulundu") {
			bulundu = true
		}
	}
	if !bulundu {
		t.Errorf("octet-stream HTML sniff edilip /bulundu gezilmeliydi")
	}
}

func TestRobotsAllowDisallowLabels(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html>bos</html>`))
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
	for _, sebep := range rep.Interesting {
		switch sebep {
		case "robots-allow":
			gotAllow = true
		case "robots-disallow":
			gotDisallow = true
		}
	}
	if !gotAllow {
		t.Errorf("robots-allow etiketi bekleniyordu: %v", rep.Interesting)
	}
	if !gotDisallow {
		t.Errorf("robots-disallow etiketi bekleniyordu: %v", rep.Interesting)
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
	var bakBulundu bool
	for _, b := range found {
		if strings.HasSuffix(b.URL, "/config.bak") {
			bakBulundu = true
		}
	}
	if !bakBulundu {
		t.Errorf("config.bak uzanti ile bulunmaliydi: %v", found)
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
		t.Errorf("/admin bulunmaliydi: %v", found)
	}
	if !set[srv.URL+"/admin/secret"] {
		t.Errorf("/admin/secret recursive olarak bulunmaliydi: %v", found)
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
	for _, beklenen := range []string{"jwt", "aws-access-key", "generic-secret"} {
		if !types[beklenen] {
			t.Errorf("secret tipi bulunamadi: %s (cikan: %+v)", beklenen, got)
		}
	}
}

func TestBodyDedup(t *testing.T) {
	ayni := `<html>AYNI ICERIK</html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><a href="/a">a</a><a href="/b">b</a></html>`))
		case "/a", "/b":
			_, _ = w.Write([]byte(ayni))
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
		t.Errorf("/a ve /b ayni govdeye sahip -> en az 1 duplicate beklenirdi")
	}
}

func TestDepthLimit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><a href="/seviye1">1</a></html>`))
		case "/seviye1":
			_, _ = w.Write([]byte(`<html><a href="/seviye2">2</a></html>`))
		case "/seviye2":
			_, _ = w.Write([]byte(`<html>derin</html>`))
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
		if strings.HasSuffix(p.URL, "/seviye2") {
			t.Errorf("depth=1 iken /seviye2 (derinlik 2) gezilmemeliydi")
		}
	}

	var s1 bool
	for _, p := range rep.Pages {
		if strings.HasSuffix(p.URL, "/seviye1") {
			s1 = true
		}
	}
	if !s1 {
		t.Errorf("depth=1 iken /seviye1 gezilmeliydi")
	}
}

func TestRateManagerPerHost(t *testing.T) {

	g := newRateManager(5, false)
	if g.forHost("a.com") != g.forHost("b.com") {
		t.Errorf("global modda tum host'lar ayni limiter'i paylasmali")
	}

	p := newRateManager(5, true)
	if p.forHost("a.com") != p.forHost("a.com") {
		t.Errorf("ayni host ayni limiter'i vermeli")
	}
	if p.forHost("a.com") == p.forHost("b.com") {
		t.Errorf("farkli host'lar farkli limiter almali")
	}
}

func TestExtractFlags(t *testing.T) {
	re := flagRegex("HTB")
	body := []byte(`sayfada HTB{ilk_flag_123} var, tekrar HTB{ilk_flag_123},
		bir de HTB{ikinci-flag} ve alakasiz FLAG{bu_olmaz} plus HTB{} bos.`)
	got := extractFlags(body, re)
	set := map[string]bool{}
	for _, f := range got {
		set[f] = true
	}
	if !set["HTB{ilk_flag_123}"] || !set["HTB{ikinci-flag}"] {
		t.Errorf("beklenen flag'ler bulunamadi: %v", got)
	}
	if set["FLAG{bu_olmaz}"] {
		t.Errorf("HTB disi format alinmamaliydi: %v", got)
	}

	if set["HTB{}"] {
		t.Errorf("bos flag alinmamaliydi")
	}

	say := 0
	for _, f := range got {
		if f == "HTB{ilk_flag_123}" {
			say++
		}
	}
	if say != 1 {
		t.Errorf("tekrar eden flag tekillestirilmeliydi, adet: %d", say)
	}

	if extractFlags(body, nil) != nil {
		t.Errorf("flagRe nil iken flag aranmamali")
	}
}

func TestFlagInCrawl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><!-- HTB{yorumdaki_flag} --><a href="/gizli">g</a></html>`))
		case "/gizli":
			_, _ = w.Write([]byte(`<html>tebrikler: HTB{sayfa_govdesindeki_flag}</html>`))
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
	if !set["HTB{yorumdaki_flag}"] {
		t.Errorf("yorumdaki flag bulunmaliydi: %v", rep.Flags)
	}
	if !set["HTB{sayfa_govdesindeki_flag}"] {
		t.Errorf("sayfa govdesindeki flag bulunmaliydi: %v", rep.Flags)
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
		_, _ = w.Write([]byte(`<html>link yok</html>`))
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
		t.Fatalf("robots.txt bulunup raporlanmaliydi")
	}

	durum := map[string]int{}
	for _, p := range rep.Robots.Paths {
		durum[p.Path] = p.Status
	}
	if durum[srv.URL+"/admin/"] != 200 {
		t.Errorf("/admin/ (wildcard prefix) hedef olarak 200 gezilmeliydi: %+v", rep.Robots.Paths)
	}
	if durum[srv.URL+"/secret-backup"] != 403 {
		t.Errorf("/secret-backup robots'tan hedef alinip 403 raporlanmaliydi: %+v", rep.Robots.Paths)
	}

	var adminGezildi bool
	for _, p := range rep.Pages {
		if strings.HasSuffix(p.URL, "/admin/") {
			adminGezildi = true
		}
	}
	if !adminGezildi {
		t.Errorf("/admin/ frontier'a alinip gezilmeliydi (robots bypass)")
	}
}

func TestNormalizeDeepBase(t *testing.T) {
	base, _ := url.Parse("https://t.com/docs/guide/")
	got, ok := normalize(base, "chapter2.html")
	if !ok || got != "https://t.com/docs/guide/chapter2.html" {
		t.Errorf("goreli cozum yanlis: got=%q ok=%v", got, ok)
	}
	got2, ok2 := normalize(base, "../ust")
	if !ok2 || got2 != "https://t.com/docs/ust" {
		t.Errorf("bir ust dizin cozumu yanlis: got=%q", got2)
	}
}
