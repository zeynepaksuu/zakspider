package main

import (
	"net/url"
	"testing"
)

// mustURL: test icin URL parse eder, hata olursa testi durdurur.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("gecersiz test url: %s", raw)
	}
	return u
}

// extractJSEndpoints: bir JS metninden path ve URL'leri dogru cikariyor mu?
func TestExtractJSEndpoints(t *testing.T) {
	js := `
		const api = "/api/v1/users";
		fetch('/admin/login', {method:'POST'});
		let base = "https://internal.target.com/secret";
		var x = "/"; // tek slash -> alinmamali
		axios.get(` + "`/api/orders/123`" + `);
	`
	got := extractJSEndpoints([]byte(js))

	// Sonucu set'e alip beklenenleri kontrol et.
	set := make(map[string]bool)
	for _, g := range got {
		set[g] = true
	}

	beklenen := []string{
		"/api/v1/users",
		"/admin/login",
		"/api/orders/123",
		"https://internal.target.com/secret",
	}
	for _, b := range beklenen {
		if !set[b] {
			t.Errorf("beklenen endpoint bulunamadi: %q (cikan: %v)", b, got)
		}
	}
	// Tek "/" alinmamaliydi.
	if set["/"] {
		t.Errorf("tek slash '/' alinmamaliydi ama alindi")
	}
}

// ilgincMi: hassas yollari dogru isaretliyor mu?
func TestIlgincMi(t *testing.T) {
	ilginc := []string{
		"https://x.com/backup.zip",
		"https://x.com/.git/config",
		"https://x.com/config.bak",
		"https://x.com/.env",
		"https://x.com/robots.txt",
	}
	for _, u := range ilginc {
		if _, ok := ilgincMi(u); !ok {
			t.Errorf("ilginc olmaliydi ama degil: %s", u)
		}
	}

	normal := []string{
		"https://x.com/index.html",
		"https://x.com/about",
		"https://x.com/images/logo.png",
	}
	for _, u := range normal {
		if sebep, ok := ilgincMi(u); ok {
			t.Errorf("normal olmaliydi ama ilginc isaretlendi: %s (sebep: %s)", u, sebep)
		}
	}
}

// normalize: temel dogrulama (relative->absolute, fragment atma).
func TestNormalize(t *testing.T) {
	base := mustURL(t, "https://target.com/dir/page")

	testler := []struct {
		ham      string
		beklenen string
		gecerli  bool
	}{
		{"/admin", "https://target.com/admin", true},
		{"../x", "https://target.com/x", true},
		{"#bolum", "", false},
		{"mailto:a@b.com", "", false},
		{"https://target.com:443/y", "https://target.com/y", true},
	}
	for _, tc := range testler {
		got, ok := normalize(base, tc.ham)
		if ok != tc.gecerli {
			t.Errorf("normalize(%q) gecerli=%v, beklenen=%v", tc.ham, ok, tc.gecerli)
			continue
		}
		if ok && got != tc.beklenen {
			t.Errorf("normalize(%q) = %q, beklenen %q", tc.ham, got, tc.beklenen)
		}
	}
}
