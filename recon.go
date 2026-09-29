package main

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

type FormInput struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Form struct {
	Action      string
	Method      string
	Inputs      []FormInput
	HasCSRF     bool
	HasPassword bool
}

type PageData struct {
	Links    []Link
	Comments []string
	Forms    []Form
}

func analyzeHTML(body []byte) (*PageData, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	pd := &PageData{}

	var visit func(*html.Node)
	visit = func(n *html.Node) {
		switch n.Type {
		case html.CommentNode:

			c := strings.TrimSpace(n.Data)
			if c != "" {
				pd.Comments = append(pd.Comments, c)
			}

		case html.ElementNode:

			if attr := linkAttr(n.Data); attr != "" {
				for _, a := range n.Attr {
					if a.Key == attr && a.Val != "" {
						pd.Links = append(pd.Links, Link{Tag: n.Data, Attr: attr, Value: a.Val})
					}
				}
			}

			if n.Data == "form" {
				pd.Forms = append(pd.Forms, parseForm(n))
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(doc)

	return pd, nil
}

func parseForm(n *html.Node) Form {
	f := Form{Method: "GET"}
	for _, a := range n.Attr {
		switch a.Key {
		case "action":
			f.Action = a.Val
		case "method":
			if a.Val != "" {
				f.Method = strings.ToUpper(a.Val)
			}
		}
	}

	var walk func(*html.Node)
	walk = func(m *html.Node) {
		if m.Type == html.ElementNode &&
			(m.Data == "input" || m.Data == "textarea" || m.Data == "select") {
			in := FormInput{Type: m.Data}
			for _, a := range m.Attr {
				switch a.Key {
				case "name":
					in.Name = a.Val
				case "type":
					in.Type = a.Val
				}
			}
			f.Inputs = append(f.Inputs, in)

			name := strings.ToLower(in.Name)
			if strings.Contains(name, "csrf") || strings.Contains(name, "token") ||
				strings.Contains(name, "authenticity") || strings.Contains(name, "nonce") ||
				strings.Contains(name, "_xsrf") {
				f.HasCSRF = true
			}
			if strings.ToLower(in.Type) == "password" || strings.Contains(name, "password") || strings.Contains(name, "passwd") {
				f.HasPassword = true
			}
		}
		for c := m.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)

	return f
}

var (
	jsPathRe = regexp.MustCompile("[\"'`](/[a-zA-Z0-9_\\-./]{1,120})[\"'`]")

	jsURLRe = regexp.MustCompile(`https?://[a-zA-Z0-9_\-./:?=&%]+`)
)

func extractJSEndpoints(body []byte) []string {
	s := string(body)
	set := make(map[string]struct{})

	for _, m := range jsPathRe.FindAllStringSubmatch(s, -1) {
		p := m[1]
		if len(p) > 1 {
			set[p] = struct{}{}
		}
	}
	for _, m := range jsURLRe.FindAllString(s, -1) {
		set[m] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func isJS(contentType, rawURL string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return true
	}
	if u, err := url.Parse(rawURL); err == nil {
		return strings.HasSuffix(strings.ToLower(u.Path), ".js")
	}
	return false
}

func looksLikeHTML(body []byte) bool {
	n := len(body)
	if n > 1024 {
		n = 1024
	}
	s := strings.ToLower(string(body[:n]))
	for _, sig := range []string{"<!doctype html", "<html", "<head", "<body", "<a ", "<div", "<script", "<title"} {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

func isTextual(contentType, rawURL string, body []byte) bool {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "text/"),
		strings.Contains(ct, "json"),
		strings.Contains(ct, "xml"),
		strings.Contains(ct, "javascript"),
		strings.Contains(ct, "ecmascript"):
		return true
	}
	if isJS(contentType, rawURL) {
		return true
	}

	if ct == "" || strings.Contains(ct, "octet-stream") {
		return looksLikeHTML(body)
	}
	return false
}

type Secret struct {
	URL   string `json:"url"`
	Type  string `json:"type"`
	Match string `json:"match"`
}

var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}`)},
	{"aws-access-key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"aws-secret", regexp.MustCompile(`(?i)aws_secret_access_key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})`)},
	{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"slack-token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`)},
	{"github-token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`)},
	{"private-key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{"s3-bucket", regexp.MustCompile(`(?i)[a-z0-9.\-]+\.s3[.\-][a-z0-9\-]*\.amazonaws\.com`)},
	{"generic-secret", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|password|passwd|bearer)["']?\s*[:=]\s*["']([^"'\s]{6,64})["']`)},
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func flagRegex(format string) *regexp.Regexp {
	format = strings.TrimSpace(format)
	if format == "" {
		format = "HTB"
	}

	return regexp.MustCompile(regexp.QuoteMeta(format) + `\{[^}\r\n]{1,256}\}`)
}

func extractFlags(body []byte, re *regexp.Regexp) []string {
	if re == nil {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, m := range re.FindAllString(string(body), -1) {
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}

func extractSecrets(body []byte) []Secret {
	s := string(body)
	var out []Secret
	seen := make(map[string]struct{})
	for _, d := range secretPatterns {
		for _, m := range d.re.FindAllString(s, -1) {
			m = truncate(m, 100)
			key := d.name + "|" + m
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Secret{Type: d.name, Match: m})
		}
	}
	return out
}

var interestingPatterns = []string{
	".bak", ".old", ".swp", ".save", ".orig", "~",
	".git", ".svn", ".env", ".htaccess", ".htpasswd",
	".sql", ".sqlite", ".db", ".zip", ".tar", ".gz", ".rar",
	".config", ".conf", ".ini", ".log", ".pem", ".key", ".crt",
	".ds_store", ".dockerfile", "dockerfile", ".yml", ".yaml",
	"backup", "phpinfo", "adminer", "/admin", "/.git/", "/api/",
	"robots.txt", "sitemap.xml", ".xml",
}

func isInteresting(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	urlPath := strings.ToLower(u.Path)
	for _, d := range interestingPatterns {
		if strings.Contains(urlPath, d) {
			return d, true
		}
	}
	return "", false
}
