package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/fatih/color"
)

// Cikti & raporlama:
// - JSON cikti (baska araclara pipe icin)
// - JSONL streaming (bulgular olustukca satir satir)
// - Renkli konsol (status'a gore renk)

// --- JSON rapor tipleri ---

// PageInfo: gezilen tek bir sayfa.
type PageInfo struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`                  // okunan govde boyutu (byte)
	Depth       int    `json:"depth"`                 // seed'den kac hop uzakta
	RedirectTo  string `json:"redirect_to,omitempty"` // yonlendirme hedefi (varsa)
}

// FormReport: JSON icin form kaydi.
type FormReport struct {
	URL         string      `json:"url"`
	Action      string      `json:"action"`
	Method      string      `json:"method"`
	Inputs      []FormInput `json:"inputs"`
	HasCSRF     bool        `json:"has_csrf"`
	HasPassword bool        `json:"has_password"`
}

// CommentReport: JSON icin yorum kaydi.
type CommentReport struct {
	URL     string `json:"url"`
	Comment string `json:"comment"`
}

// BruteResult: brute-force ile bulunan (404 olmayan) bir yol.
type BruteResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}

// FlagFinding: bulunan bir CTF/HTB flag'i ve kaynagi.
type FlagFinding struct {
	Flag string `json:"flag"`
	URL  string `json:"url"`
}

// RobotsPath: robots.txt'te ilan edilen bir yol ve onu HEDEF olarak cektigimizde
// aldigimiz status. HTB icin: robots'u dinlemek yerine bypass edip hepsini geziyoruz.
type RobotsPath struct {
	Path   string `json:"path"`   // absolute/normalize URL
	Source string `json:"source"` // "disallow" | "allow"
	Status int    `json:"status"` // fetch sonucu (0 = gezilemedi)
}

// RobotsInfo: robots.txt'in okunan icerigi ve cikarilan hedefler.
type RobotsInfo struct {
	URL      string       `json:"url"`           // robots.txt adresi
	Found    bool         `json:"found"`         // 200 dondu mu?
	Raw      string       `json:"raw,omitempty"` // ham icerik (kirpilmis)
	Paths    []RobotsPath `json:"paths"`         // Disallow/Allow yollari + status
	Sitemaps []string     `json:"sitemaps"`      // ilan edilen sitemap URL'leri
}

// Report: tarama sonucunun tamami. JSON'a bu serialize edilir.
type Report struct {
	Target         string            `json:"target"`
	Scope          string            `json:"scope"`
	Workers        int               `json:"workers"`
	DurationMs     int64             `json:"duration_ms"`
	PagesCrawled   int               `json:"pages_crawled"`
	URLsDiscovered int               `json:"urls_discovered"`
	StatusCounts   map[int]int       `json:"status_counts"`
	Pages          []PageInfo        `json:"pages"`
	NotableStatus  map[string][]int  `json:"notable_status"`
	Interesting    map[string]string `json:"interesting"`
	JSEndpoints    []string          `json:"js_endpoints"`
	Forms          []FormReport      `json:"forms"`
	Comments       []CommentReport   `json:"comments"`
	Secrets        []Secret          `json:"secrets"`
	Flags          []FlagFinding     `json:"flags"` // HTB{...} gibi bulunan flag'ler
	BruteFound     []BruteResult     `json:"brute_found"`
	Robots         *RobotsInfo       `json:"robots,omitempty"` // robots.txt icerigi + hedefler
	Redirects      map[string]string `json:"redirects"`        // istenen url -> nihai/hedef url
	Duplicates     map[string]string `json:"duplicates"`       // url -> ayni govdeye sahip ilk url
}

// writeJSON: raporu duzgun girintilenmis JSON olarak verilen writer'a yazar.
// w genelde stdout'tur; --output-file verilirse bir dosya olur.
func writeJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // URL'lerdeki & vb. kacislanmasin
	return enc.Encode(r)
}

// --- JSONL streaming ---
// Buyuk taramalarda bulgulari sonuna kadar bellekte tutmak yerine, olustukca
// satir satir (her satir bir JSON nesnesi) yazariz. Otomasyon/pipe icin idealdir:
//   zakspider --output jsonl target | jq -c 'select(.type=="secret")'

// streamEvent: JSONL akisinda tek bir olay.
type streamEvent struct {
	Type string `json:"type"` // "page" | "finding" | "secret" | "form" | "brute" | "summary"
	Data any    `json:"data"`
}

// newJSONLEmitter: verilen writer'a JSONL olaylari yazan, thread-safe bir emit fonksiyonu dondurur.
// Emit YALNIZCA koordinator goroutine'inden cagrilir; mutex yine de guvenlik icin.
func newJSONLEmitter(w io.Writer) func(string, any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	var mu sync.Mutex
	return func(t string, data any) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(streamEvent{Type: t, Data: data})
	}
}

// --- Renkli konsol ---

var (
	renkYesil   = color.New(color.FgGreen).SprintfFunc()
	renkCyan    = color.New(color.FgCyan).SprintfFunc()
	renkSari    = color.New(color.FgYellow).SprintfFunc()
	renkMor     = color.New(color.FgMagenta).SprintfFunc()
	renkKirmizi = color.New(color.FgRed).SprintfFunc()
	renkGri     = color.New(color.FgHiBlack).SprintfFunc()
)

// statusRenkli: status kodunu anlamina gore renklendirir.
//
//	2xx yesil, 3xx cyan, 401/403 sari (dikkat!), diger 4xx mor, 5xx kirmizi.
func statusRenkli(code int) string {
	s := fmt.Sprintf("%d", code)
	switch {
	case code >= 200 && code < 300:
		return renkYesil("%s", s)
	case code >= 300 && code < 400:
		return renkCyan("%s", s)
	case code == 401 || code == 403:
		return renkSari("%s", s)
	case code >= 400 && code < 500:
		return renkMor("%s", s)
	case code >= 500:
		return renkKirmizi("%s", s)
	default:
		return s
	}
}

// setColorEnabled: rengi acar/kapar. JSON modunda veya --no-color'da kapatilir.
func setColorEnabled(enabled bool) {
	color.NoColor = !enabled
}

// printTextReport: insan-okunur, renkli ozet raporu verilen writer'a basar.
// w genelde stdout'tur; --output-file verilirse dosyadir (renk kapatilir).
func printTextReport(w io.Writer, r *Report) {
	fmt.Fprintf(w, "\n==================== SUMMARY ====================\n")
	fmt.Fprintf(w, "  Duration        : %d ms\n", r.DurationMs)
	fmt.Fprintf(w, "  Workers         : %d\n", r.Workers)
	fmt.Fprintf(w, "  Pages crawled   : %d\n", r.PagesCrawled)
	fmt.Fprintf(w, "  URLs discovered : %d\n", r.URLsDiscovered)
	fmt.Fprintf(w, "  Status breakdown:\n")
	kodlar := make([]int, 0, len(r.StatusCounts))
	for k := range r.StatusCounts {
		kodlar = append(kodlar, k)
	}
	sort.Ints(kodlar)
	for _, k := range kodlar {
		fmt.Fprintf(w, "    %s : %d\n", statusRenkli(k), r.StatusCounts[k])
	}

	fmt.Fprintf(w, "\n==================== RECON FINDINGS ====================\n")

	// FLAG'ler: HTB'de aradigimiz asil sey -> en tepede, dikkat cekici.
	if len(r.Flags) > 0 {
		fmt.Fprintf(w, "\n%s CTF flags found: %d\n", renkYesil("[FLAG]"), len(r.Flags))
		for _, f := range r.Flags {
			fmt.Fprintf(w, "    %s\n      %s\n", renkYesil("%s", f.Flag), renkGri("source: %s", f.URL))
		}
	}

	// robots.txt: HTB icin en degerli bolum. Icerigi okunur, ilan edilen yollar
	// (Disallow dahil) HEDEF olarak gezilir; her birinin status'u burada.
	if r.Robots != nil && r.Robots.Found {
		fmt.Fprintf(w, "\n%s robots.txt found -> crawling its paths as targets (bypassed): %s\n",
			renkKirmizi("[!]"), renkGri("%s", r.Robots.URL))
		for _, p := range r.Robots.Paths {
			durum := "not reached"
			if p.Status > 0 {
				durum = statusRenkli(p.Status)
			}
			fmt.Fprintf(w, "    [%s] %-9s %s\n", durum, "("+p.Source+")", p.Path)
		}
		if len(r.Robots.Sitemaps) > 0 {
			fmt.Fprintf(w, "    %s\n", renkGri("sitemaps: %v", r.Robots.Sitemaps))
		}
	}

	if len(r.NotableStatus) > 0 {
		fmt.Fprintf(w, "\n%s Notable status (401/403/5xx): %d\n", renkSari("[!]"), len(r.NotableStatus))
		for _, u := range sortedKeys(r.NotableStatus) {
			fmt.Fprintf(w, "    %v  %s\n", r.NotableStatus[u], u)
		}
	}

	if len(r.Interesting) > 0 {
		fmt.Fprintf(w, "\n%s Interesting/sensitive paths: %d\n", renkKirmizi("[!]"), len(r.Interesting))
		for _, u := range sortedKeysStr(r.Interesting) {
			fmt.Fprintf(w, "    %s  %s\n", renkGri("(%s)", r.Interesting[u]), u)
		}
	}

	if len(r.Secrets) > 0 {
		fmt.Fprintf(w, "\n%s Secrets / tokens leaked: %d\n", renkKirmizi("[!!]"), len(r.Secrets))
		for _, s := range r.Secrets {
			fmt.Fprintf(w, "    %s %s\n      %s\n", renkKirmizi("[%s]", s.Type), s.Match, renkGri("source: %s", s.URL))
		}
	}

	if len(r.JSEndpoints) > 0 {
		fmt.Fprintf(w, "\n%s Endpoints extracted from JS: %d\n", renkCyan("[!]"), len(r.JSEndpoints))
		for _, e := range r.JSEndpoints {
			fmt.Fprintf(w, "    %s\n", e)
		}
	}

	if len(r.Forms) > 0 {
		fmt.Fprintf(w, "\n%s Forms found: %d\n", renkSari("[!]"), len(r.Forms))
		for _, f := range r.Forms {
			alanlar := make([]string, 0, len(f.Inputs))
			for _, in := range f.Inputs {
				alanlar = append(alanlar, fmt.Sprintf("%s(%s)", in.Name, in.Type))
			}
			etiketler := ""
			if f.HasPassword {
				etiketler += renkSari(" [login]")
			}
			if !f.HasCSRF && (f.Method == "POST" || f.HasPassword) {
				etiketler += renkKirmizi(" [no-csrf]")
			}
			fmt.Fprintf(w, "    [%s %s]%s fields: %v\n      %s\n",
				f.Method, f.Action, etiketler, alanlar, renkGri("source: %s", f.URL))
		}
	}

	if len(r.Comments) > 0 {
		fmt.Fprintf(w, "\n%s HTML comments: %d\n", renkCyan("[!]"), len(r.Comments))
		for _, c := range r.Comments {
			y := c.Comment
			if len(y) > 120 {
				y = y[:120] + "..."
			}
			fmt.Fprintf(w, "    <!-- %s -->\n      %s\n", y, renkGri("source: %s", c.URL))
		}
	}

	if len(r.BruteFound) > 0 {
		fmt.Fprintf(w, "\n%s Paths found via brute-force: %d\n", renkKirmizi("[!]"), len(r.BruteFound))
		for _, b := range r.BruteFound {
			fmt.Fprintf(w, "    [%s] %s\n", statusRenkli(b.Status), b.URL)
		}
	}

	if len(r.Redirects) > 0 {
		fmt.Fprintf(w, "\n%s Redirects observed: %d\n", renkCyan("[!]"), len(r.Redirects))
		for _, u := range sortedKeysStr(r.Redirects) {
			fmt.Fprintf(w, "    %s -> %s\n", u, r.Redirects[u])
		}
	}

	if len(r.Duplicates) > 0 {
		fmt.Fprintf(w, "\n%s Duplicate content (same body, different URL): %d\n", renkGri("[i]"), len(r.Duplicates))
		for _, u := range sortedKeysStr(r.Duplicates) {
			fmt.Fprintf(w, "    %s == %s\n", u, r.Duplicates[u])
		}
	}

	if len(r.NotableStatus) == 0 && len(r.Interesting) == 0 && len(r.Secrets) == 0 &&
		len(r.JSEndpoints) == 0 && len(r.Forms) == 0 && len(r.Comments) == 0 &&
		len(r.BruteFound) == 0 {
		fmt.Fprintln(w, "  (no findings)")
	}
}

// sortedKeys: map[string][]int anahtarlarini sirali dondurur.
func sortedKeys(m map[string][]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// sortedKeysStr: map[string]string anahtarlarini sirali dondurur.
func sortedKeysStr(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
