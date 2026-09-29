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

// robots.txt / sitemap.xml kesfi.
// Crawl baslamadan once bu iki dosyayi cekip icindeki LINKLENMEMIS yollari
// frontier'a besleriz. robots.txt'deki Disallow girdileri, admin'in gizlemek
// istedigi yollarin listesidir -> pentest'te altin degerinde.

// kesif: robots/sitemap'ten bulunan bir aday URL ve kaynagi.
type kesif struct {
	url    string
	kaynak string // "robots-disallow" | "robots-allow" | "sitemap"
}

// sitemapLocRe: sitemap.xml icindeki <loc>...</loc> URL'lerini yakalar.
var sitemapLocRe = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)

// robotsSitemapTara: seed origin'inden robots.txt ve sitemap.xml'i cekip
// icindeki aday URL'leri (kaynagiyla birlikte) dondurur.
func robotsSitemapTara(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, seedURL *url.URL) ([]kesif, *RobotsInfo) {
	origin := seedURL.Scheme + "://" + seedURL.Host
	var sonuc []kesif
	info := &RobotsInfo{URL: origin + "/robots.txt"}

	// --- robots.txt ---
	if res, err := fetch(ctx, client, rm, cfg, origin+"/robots.txt"); err == nil && res.StatusCode == 200 {
		info.Found = true
		// Ham icerigi sakla (kirparak) -> kullanici manuel acmak zorunda kalmasin.
		raw := string(res.Body)
		if len(raw) > 8192 {
			raw = raw[:8192] + "\n...(kirpildi)"
		}
		info.Raw = raw

		disallow, allow, sitemaps := parseRobots(string(res.Body))
		for _, p := range disallow {
			if abs, ok := yolAbsolute(origin, p); ok {
				sonuc = append(sonuc, kesif{url: abs, kaynak: "robots-disallow"})
			}
		}
		// Allow girdileri de birer ipucudur ama "yasak" degildir -> ayri etiket.
		for _, p := range allow {
			if abs, ok := yolAbsolute(origin, p); ok {
				sonuc = append(sonuc, kesif{url: abs, kaynak: "robots-allow"})
			}
		}
		info.Sitemaps = sitemaps
		// robots icinde ilan edilen sitemap'leri de tara.
		for _, sm := range sitemaps {
			sonuc = append(sonuc, sitemapTara(ctx, client, rm, cfg, sm)...)
		}
	}

	// --- varsayilan sitemap.xml ---
	sonuc = append(sonuc, sitemapTara(ctx, client, rm, cfg, origin+"/sitemap.xml")...)

	return sonuc, info
}

// sitemapTara: bir sitemap URL'ini cekip <loc> girdilerini aday olarak dondurur.
func sitemapTara(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, sitemapURL string) []kesif {
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

// parseRobots: robots.txt govdesinden Disallow / Allow yollarini ve Sitemap
// URL'lerini AYRI AYRI cikarir (Allow bir "yasak" degildir, ayri raporlanmali).
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
			// Wildcard'li desende '*' oncesi prefix'i cikar: "/admin/*" -> "/admin/".
			// (HTB'de gizli dizinler cogu zaman boyle ilan edilir; atlamiyoruz.)
			if p := robotsYolTemizle(deger); p != "" {
				disallow = append(disallow, p)
			}
		case "allow":
			if p := robotsYolTemizle(deger); p != "" {
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

// robotsYolTemizle: bir robots.txt deger'ini crawl edilebilir bir yola cevirir.
// Wildcard (*) varsa oncesindeki somut prefix'i alir; '$' ankrajini atar.
// Cok genis / degersiz sonuclari ("" veya "/") eler.
func robotsYolTemizle(deger string) string {
	deger = strings.TrimSpace(deger)
	if i := strings.IndexByte(deger, '*'); i >= 0 {
		deger = deger[:i] // "/admin/*" -> "/admin/", "/a/*/b" -> "/a/"
	}
	deger = strings.TrimSuffix(deger, "$") // "/x.php$" -> "/x.php"
	deger = strings.TrimSpace(deger)
	if deger == "" || deger == "/" {
		return "" // kok veya bos -> hedef olarak anlamsiz
	}
	return deger
}

// Brute-force modu (gobuster mantigi).
// Bir wordlist'teki her kelimeyi hedefte dener; 404 disindaki yanitlari
// "bulundu" olarak isaretler. Linklenmemis gizli yollari tahminle bulur.
//   - Uzanti destegi (-x php,bak,txt): her kelimeyi uzantilarla da dener.
//   - Recursive: bulunan dizinlerin ICINDE tekrar tarar (--brute-recursive).

// wordlistYukle: bir wordlist dosyasini satir satir okur.
func wordlistYukle(dosya string) ([]string, error) {
	f, err := os.Open(dosya)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var kelimeler []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // uzun satirlara tolerans
	for sc.Scan() {
		k := strings.TrimSpace(sc.Text())
		if k == "" || strings.HasPrefix(k, "#") {
			continue
		}
		kelimeler = append(kelimeler, k)
	}
	return kelimeler, sc.Err()
}

// bruteForce: wordlist'teki kelimeleri (ve uzantilari) paralel dener,
// 404 olmayanlari dondurur. --brute-recursive ile bulunan dizinlerin
// icine cfg.BruteDepth seviyesine kadar iner.
func bruteForce(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, seedURL *url.URL, kelimeler []string) []BruteResult {
	origin := seedURL.Scheme + "://" + seedURL.Host

	// Soft-404 parmak izini ogren (origin seviyesinde bir kez).
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
	bases := []string{""} // "" = kok; recursive'de "/app" gibi genisler
	var bulunan []BruteResult

	for depth := 0; depth <= maxDepth && len(bases) > 0; depth++ {
		cands := bruteCandidates(origin, bases, kelimeler, cfg.Extensions)
		found := bruteFetch(ctx, client, rm, cfg, cands, softStatus, softLen, softVar, seenURL)
		var nextBases []string
		for _, br := range found {
			bulunan = append(bulunan, br)
			if cfg.BruteRecursive && depth < maxDepth && dizinGibi(br) {
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

// bruteCandidates: verilen base dizinleri x kelimeler x uzantilar carpimini uretir.
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

// bruteFetch: aday URL'leri paralel dener; 404 ve soft-404'leri eler, yenileri dondurur.
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
				if softVar && res.StatusCode == softStatus && boyutYakin(len(res.Body), softLen) {
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

// dizinGibi: bir brute bulgusu dizin gibi mi gorunuyor? (recursive'de icine inmek icin)
func dizinGibi(br BruteResult) bool {
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
	return seg != "" && seg != "/" && !strings.Contains(seg, ".") // uzanti yoksa dizin varsay
}

// soft404Baseline: var olmayan iki rastgele yol cekip "sayfa yok" cevabinin
// parmak izini (status + govde boyutu) dondurur. Iki deneme ayni status'u ve
// birbirine yakin boyutu verirse gecerli (ok=true) kabul edilir.
// Sunucu zaten duzgun 404 donuyorsa ozel filtreye gerek yok -> ok=false.
func soft404Baseline(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, origin string) (status, length int, ok bool) {
	r1 := probe404(ctx, client, rm, cfg, origin)
	r2 := probe404(ctx, client, rm, cfg, origin)
	if r1 == nil || r2 == nil {
		return 0, 0, false
	}
	// Saglikli sunucu (gercek 404) -> soft-404 filtresine gerek yok.
	if r1.StatusCode == 404 || r2.StatusCode == 404 {
		return 0, 0, false
	}
	// Iki deneme tutarsizsa guvenli bir filtre kuramayiz.
	if r1.StatusCode != r2.StatusCode || !boyutYakin(len(r1.Body), len(r2.Body)) {
		return 0, 0, false
	}
	return r1.StatusCode, (len(r1.Body) + len(r2.Body)) / 2, true
}

// probe404: kesinlikle var olmayacak rastgele bir yolu ceker.
func probe404(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, origin string) *FetchResult {
	yol := fmt.Sprintf("/zakspider-yok-%d-%d", time.Now().UnixNano(), rand.Intn(1_000_000))
	res, err := fetch(ctx, client, rm, cfg, origin+yol)
	if err != nil {
		return nil
	}
	return res
}

// boyutYakin: iki govde boyutu birbirine yeterince yakin mi?
// Dinamik sayfalar biraz oynar; %5 veya en az 32 byte tolerans taniriz.
func boyutYakin(a, b int) bool {
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

// yolAbsolute: "/admin/" gibi bir path'i origin ile birlestirip absolute yapar.
func yolAbsolute(origin, path string) (string, bool) {
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
