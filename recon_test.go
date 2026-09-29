package main

import (
	"net/url"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("invalid test url: %s", raw)
	}
	return u
}

func TestExtractJSEndpoints(t *testing.T) {
	js := `
		const api = "/api/v1/users";
		fetch('/admin/login', {method:'POST'});
		let base = "https://internal.target.com/secret";
		var x = "/";
		axios.get(` + "`/api/orders/123`" + `);
	`
	got := extractJSEndpoints([]byte(js))

	set := make(map[string]bool)
	for _, g := range got {
		set[g] = true
	}

	expected := []string{
		"/api/v1/users",
		"/admin/login",
		"/api/orders/123",
		"https://internal.target.com/secret",
	}
	for _, b := range expected {
		if !set[b] {
			t.Errorf("expected endpoint not found: %q (got: %v)", b, got)
		}
	}

	if set["/"] {
		t.Errorf("a lone slash '/' should not have been extracted but was")
	}
}

func TestIsInteresting(t *testing.T) {
	interesting := []string{
		"https://x.com/backup.zip",
		"https://x.com/.git/config",
		"https://x.com/config.bak",
		"https://x.com/.env",
		"https://x.com/robots.txt",
	}
	for _, u := range interesting {
		if _, ok := isInteresting(u); !ok {
			t.Errorf("should have been interesting but was not: %s", u)
		}
	}

	normal := []string{
		"https://x.com/index.html",
		"https://x.com/about",
		"https://x.com/images/logo.png",
	}
	for _, u := range normal {
		if reason, ok := isInteresting(u); ok {
			t.Errorf("should have been normal but was flagged interesting: %s (reason: %s)", u, reason)
		}
	}
}

func TestNormalize(t *testing.T) {
	base := mustURL(t, "https://target.com/dir/page")

	cases := []struct {
		raw      string
		expected string
		valid    bool
	}{
		{"/admin", "https://target.com/admin", true},
		{"../x", "https://target.com/x", true},
		{"#section", "", false},
		{"mailto:a@b.com", "", false},
		{"https://target.com:443/y", "https://target.com/y", true},
	}
	for _, tc := range cases {
		got, ok := normalize(base, tc.raw)
		if ok != tc.valid {
			t.Errorf("normalize(%q) valid=%v, expected=%v", tc.raw, ok, tc.valid)
			continue
		}
		if ok && got != tc.expected {
			t.Errorf("normalize(%q) = %q, expected %q", tc.raw, got, tc.expected)
		}
	}
}
