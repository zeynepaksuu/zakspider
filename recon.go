package main

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Bu dosya, cekilen icerikten pentest icin degerli bilgileri cikarir:
//   - HTML yorumlari (gelistirici notlari, credential, gizli endpoint sizar)
//   - Form ve input alanlari (injection / CSRF yuzeyi)
//   - JS dosyalarindaki endpoint'ler (fetch("/api/..."))
//   - Ilginc/hassas dosya isaretleri (.env, .git, .bak ...)
//   - Sizmis secret/token'lar (JWT, AWS key, S3 bucket, generic api_key ...)

// FormInput: bir form icindeki tek bir alan.
type FormInput struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Form: bir HTML formu (saldiri yuzeyi analizi icin).
type Form struct {
	Action      string
	Method      string
	Inputs      []FormInput
	HasCSRF     bool // csrf/token/nonce alani var mi? (yoksa CSRF'ye acik olabilir)
	HasPassword bool // password alani var mi? (login/kayit formu -> ilginc)
}

// PageData: bir HTML sayfasindan tek gezinmede cikarilan her sey.
type PageData struct {
	Links    []Link
	Comments []string
	Forms    []Form
}

// analyzeHTML: HTML govdesini TEK gezinmede parse eder;
// link + yorum + form'u ayni anda toplar (iki kez parse etmemek icin).
func analyzeHTML(body []byte) (*PageData, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	pd := &PageData{}

	var gez func(*html.Node)
	gez = func(n *html.Node) {
		switch n.Type {
		case html.CommentNode:
			// <!-- ... --> icerigi. HTB'de burada sifre/endpoint bulunabilir.
			c := strings.TrimSpace(n.Data)
			if c != "" {
				pd.Comments = append(pd.Comments, c)
			}

		case html.ElementNode:
			// 1) Link tasiyan attribute'lar (a/link/script/img/iframe/form).
			if attr := hedefAttr(n.Data); attr != "" {
				for _, a := range n.Attr {
					if a.Key == attr && a.Val != "" {
						pd.Links = append(pd.Links, Link{Tag: n.Data, Attr: attr, Value: a.Val})
					}
				}
			}
			// 2) Form ise: action/method + tum input'lari cikar.
			if n.Data == "form" {
				pd.Forms = append(pd.Forms, parseForm(n))
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			gez(c)
		}
	}
	gez(doc)

	return pd, nil
}

// parseForm: bir <form> node'undan action, method ve input alanlarini cikarir.
func parseForm(n *html.Node) Form {
	f := Form{Method: "GET"} // method belirtilmezse varsayilan GET
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

	// Form icindeki input/textarea/select alanlarini gez.
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
					in.Type = a.Val // "input" ise gercek type ile ustune yaz
				}
			}
			f.Inputs = append(f.Inputs, in)

			// CSRF / password alan tespiti (saldiri yuzeyi ipuclari).
			ad := strings.ToLower(in.Name)
			if strings.Contains(ad, "csrf") || strings.Contains(ad, "token") ||
				strings.Contains(ad, "authenticity") || strings.Contains(ad, "nonce") ||
				strings.Contains(ad, "_xsrf") {
				f.HasCSRF = true
			}
			if strings.ToLower(in.Type) == "password" || strings.Contains(ad, "password") || strings.Contains(ad, "passwd") {
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

// --- JS endpoint cikarma ---
// DIKKAT: HTML icin regex YASAK'ti; ama JS/dust metin icinde path aramak icin
// regex TAM DOGRU arac. Burada bir DOM yok, sadece string iciyoruz.

var (
	// Tirnak icinde "/..." ile baslayan path'ler: "/api/users", '/admin/login'
	jsPathRe = regexp.MustCompile("[\"'`](/[a-zA-Z0-9_\\-./]{1,120})[\"'`]")
	// Tam URL'ler: https://... http://...
	jsURLRe = regexp.MustCompile(`https?://[a-zA-Z0-9_\-./:?=&%]+`)
)

// extractJSEndpoints: bir JS dosyasi (veya metin) icindeki olasi endpoint'leri cikarir.
func extractJSEndpoints(body []byte) []string {
	s := string(body)
	set := make(map[string]struct{})

	for _, m := range jsPathRe.FindAllStringSubmatch(s, -1) {
		p := m[1]
		if len(p) > 1 { // sadece "/" olan degersizleri ele
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

// isJS: icerik JavaScript mi? (content-type veya .js uzantisi)
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

// looksLikeHTML: Content-Type verilmemis/yaniltici sayfalar icin govdeye bakarak
// HTML olup olmadigini tahmin eder. Bazi HTB box'lari / yanlis yapilandirilmis
// sunucular HTML'i Content-Type header'i olmadan (veya octet-stream ile) doner;
// bu durumda linkleri kaybetmemek icin sniffing yapariz.
func looksLikeHTML(body []byte) bool {
	n := len(body)
	if n > 1024 {
		n = 1024 // ilk 1KB yeterli
	}
	s := strings.ToLower(string(body[:n]))
	for _, sig := range []string{"<!doctype html", "<html", "<head", "<body", "<a ", "<div", "<script", "<title"} {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

// isTextual: govde metin tabanli mi? (secret taramasi sadece metinde anlamli)
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
	// Content-Type yok/belirsiz -> govdeye bak.
	if ct == "" || strings.Contains(ct, "octet-stream") {
		return looksLikeHTML(body)
	}
	return false
}

// --- Secret / token sizinti tespiti ---

// Secret: bir sayfada/JS'te bulunan olasi hassas deger.
type Secret struct {
	URL   string `json:"url"`
	Type  string `json:"type"`
	Match string `json:"match"`
}

// secretDesenler: yaygin secret formatlari. Yanlis pozitifi dusuk tutmak icin
// mumkun oldugunca spesifik desenler secildi.
var secretDesenler = []struct {
	ad string
	re *regexp.Regexp
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

// kisalt: cok uzun eslesmeleri raporda okunur tutmak icin kirpar.
func kisalt(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// --- CTF / HTB flag avi ---

// flagRegex: verilen prefix'ten bir flag deseni uretir. "HTB" -> HTB{...}.
// Bos prefix "HTB" olarak varsayilir. Baska CTF'ler icin --flag-format ile degistirilebilir.
func flagRegex(format string) *regexp.Regexp {
	format = strings.TrimSpace(format)
	if format == "" {
		format = "HTB"
	}
	// PREFIX{ ... } : suslu parantez icinde, yeni satir olmadan, 1-256 karakter.
	return regexp.MustCompile(regexp.QuoteMeta(format) + `\{[^}\r\n]{1,256}\}`)
}

// extractFlags: govdede flag desenine (HTB{...} gibi) uyanlari bulur (tekillestirilmis).
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

// extractSecrets: govde metninden olasi secret/token'lari cikarir (URL cagiran tarafca doldurulur).
func extractSecrets(body []byte) []Secret {
	s := string(body)
	var out []Secret
	seen := make(map[string]struct{})
	for _, d := range secretDesenler {
		for _, m := range d.re.FindAllString(s, -1) {
			m = kisalt(m, 100)
			anahtar := d.ad + "|" + m
			if _, ok := seen[anahtar]; ok {
				continue
			}
			seen[anahtar] = struct{}{}
			out = append(out, Secret{Type: d.ad, Match: m})
		}
	}
	return out
}

// --- Ilginc / hassas dosya tespiti ---

// ilgincDesenler: HTB/pentest'te dikkat ceken uzanti ve yol parcalari.
var ilgincDesenler = []string{
	".bak", ".old", ".swp", ".save", ".orig", "~",
	".git", ".svn", ".env", ".htaccess", ".htpasswd",
	".sql", ".sqlite", ".db", ".zip", ".tar", ".gz", ".rar",
	".config", ".conf", ".ini", ".log", ".pem", ".key", ".crt",
	".ds_store", ".dockerfile", "dockerfile", ".yml", ".yaml",
	"backup", "phpinfo", "adminer", "/admin", "/.git/", "/api/",
	"robots.txt", "sitemap.xml", ".xml",
}

// ilgincMi: bir URL hassas/ilginc bir sey isaret ediyor mu?
// Eslesen deseni (sebep) ve true doner.
func ilgincMi(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	yol := strings.ToLower(u.Path)
	for _, d := range ilgincDesenler {
		if strings.Contains(yol, d) {
			return d, true
		}
	}
	return "", false
}
