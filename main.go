package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Link: bulunan bir baglantiyi ve nereden geldigini tutar.
type Link struct {
	Tag   string // hangi HTML etiketi: a, script, link, img, iframe, form
	Attr  string // hangi attribute'tan geldi: href, src, action
	Value string // ham deger
}

// FetchResult: bir sayfa cekiminin sonucu.
type FetchResult struct {
	StatusCode  int
	ContentType string
	Body        []byte
	FinalURL    string // yonlendirmeler izlendikten sonra ulasilan nihai URL
	RedirectTo  string // scope disi/izlenmeyen yonlendirme hedefi (Location)
}

// Config: tum tarama ayarlari tek yerde. Fonksiyon imzalarini sadelestirir.
type Config struct {
	ScopeMode  string
	MaxPages   int
	Workers    int
	RatePerSec float64
	Retries    int
	Output     string
	OutputFile string // rapor bu dosyaya yazilir (bos = stdout)
	CrawlJS    bool   // JS icinden cikan in-scope endpoint'leri de gez
	UserAgent  string
	Cookie     string   // authenticated crawl icin "session=..." vb.
	Headers    []string // ek header'lar, "Key: Value" formatinda
	Include    string   // sadece bu path parcasini iceren URL'ler
	Exclude    string   // bu path parcasini iceren URL'ler haric
	Proxy      string   // ornek: http://127.0.0.1:8080 (Burp)
	Insecure   bool     // TLS sertifika dogrulamasini atla (Burp/self-signed)
	Quiet      bool     // canli ilerleme satirlarini bastir, sadece raporu ver
	SkipRobots bool     // robots.txt / sitemap.xml kesfini atla
	Wordlist   string   // brute-force wordlist dosya yolu (bos = kapali)
	Words      []string // yuklenen kelimeler (main'de doldurulur)

	MaxDepth       int      // BFS derinlik limiti (-1 = sinirsiz); seed = 0
	PerHostRate    bool     // rate limit'i global yerine host basina uygula
	Extensions     []string // brute-force uzantilari (ornek: php,bak,txt)
	BruteRecursive bool     // bulunan dizinlerin icinde de brute yap
	BruteDepth     int      // recursive brute derinligi
	ExitCode       bool     // bulgu varsa cikis kodu != 0 (otomasyon/CI icin)
	FlagFormat     string   // CTF flag prefix'i (HTB -> HTB{...}); bos = kapali

	baseHost string         // seed'in host'u; redirect scope kontrolu icin (main'de doldurulur)
	flagRe   *regexp.Regexp // FlagFormat'tan derlenen desen (crawl'da doldurulur)
}

// rateManager: hiz sinirlamasini yonetir. Varsayilan modda tek global limiter;
// PerHostRate aciksa her host icin ayri bir token bucket. subdomain scope'ta
// tek global limitle tum alt alanlari bogmamak icin faydali.
type rateManager struct {
	mu          sync.Mutex
	perHost     map[string]*rate.Limiter
	rps         rate.Limit
	perHostMode bool
	global      *rate.Limiter
}

// newRateManager: rps<=0 -> sinirsiz. perHost=true -> host basina ayri limiter.
func newRateManager(rps float64, perHost bool) *rateManager {
	lim := rate.Inf
	if rps > 0 {
		lim = rate.Limit(rps)
	}
	return &rateManager{
		perHost:     make(map[string]*rate.Limiter),
		rps:         lim,
		perHostMode: perHost,
		global:      rate.NewLimiter(lim, 1),
	}
}

// forHost: ilgili host icin limiter'i dondurur (gerekirse olusturur).
func (rm *rateManager) forHost(host string) *rate.Limiter {
	if !rm.perHostMode {
		return rm.global
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	l, ok := rm.perHost[host]
	if !ok {
		l = rate.NewLimiter(rm.rps, 1)
		rm.perHost[host] = l
	}
	return l
}

// wait: verilen URL'in host'una uygun limiter'da token bekler.
func (rm *rateManager) wait(ctx context.Context, rawURL string) error {
	host := ""
	if rm.perHostMode {
		if u, err := url.Parse(rawURL); err == nil {
			host = u.Hostname()
		}
	}
	return rm.forHost(host).Wait(ctx)
}

// stringSlice: ayni flag'in birden cok kez verilebilmesi icin (ornek: -H).
// flag paketi bunu dogal desteklemez; flag.Value arayuzunu uyguluyoruz.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// maxBodyBytes: bir yanittan okunacak azami govde boyutu.
// Dev dosyalara (500MB ZIP vb.) karsi koruma; io.LimitReader ile uygulanir.
const maxBodyBytes = 5 << 20 // 5 MB

// newClient: timeout'lu, tuning'li, opsiyonel proxy/insecure destekli HTTP client.
func newClient(cfg *Config) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Proxy (ornek Burp Suite: http://127.0.0.1:8080).
	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("gecersiz proxy: %w", err)
		}
		transport.Proxy = http.ProxyURL(pu)
	}

	// TLS dogrulamasini atla (Burp'un MITM sertifikasi / HTB self-signed cert'leri).
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - pentest icin bilincli
	}

	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		// Redirect kontrolu: en fazla 10 yonlendirme izle (redirect loop korumasi).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("cok fazla redirect (>10)")
			}
			// Scope disi host'a yonlendirme -> TAKIP ETME. Son yaniti (3xx) oldugu
			// gibi dondur; boylece dis host'un govdesi cekilip parse edilmez.
			if cfg.baseHost != "" && !inScope(cfg.baseHost, req.URL.String(), cfg.ScopeMode) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, nil
}

// parseRetryAfter: "Retry-After" header'ini suреye cevirir.
// Header ya saniye (ornek "5") ya da HTTP tarih formatinda olabilir.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	// Saniye cinsinden mi?
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	// HTTP tarih formatinda mi? (ornek "Wed, 21 Oct 2025 07:28:00 GMT")
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// backoffBekle: yeniden denemeden once bekler.
// retryAfter verilmisse ona saygi gosterir; yoksa exponential backoff + jitter uygular.
// ctx iptal edilirse beklemeyi keser (graceful shutdown'a hazir).
func backoffBekle(ctx context.Context, attempt int, retryAfter time.Duration) {
	var d time.Duration
	if retryAfter > 0 {
		d = retryAfter // sunucunun dedigine uy
	} else {
		// 500ms, 1s, 2s, 4s... (2^attempt)
		d = 500 * time.Millisecond * time.Duration(1<<attempt)
	}
	// Jitter: 0-250ms rastgele ekle. Duzenli pattern tespit edilir; jitter kirar.
	d += time.Duration(rand.Intn(250)) * time.Millisecond

	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// applyHeaders: istege UA, cookie ve ek header'lari uygular.
func applyHeaders(req *http.Request, cfg *Config) {
	ua := cfg.UserAgent
	if ua == "" {
		ua = "zakspider/0.1 (+recon)"
	}
	req.Header.Set("User-Agent", ua)

	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}
	// Ek header'lar: "Key: Value" formatinda.
	for _, h := range cfg.Headers {
		if k, v, ok := strings.Cut(h, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
}

// fetch: bir URL'i ceker. Rate limit uygular, hata/429/503 durumunda retry yapar.
func fetch(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, rawURL string) (*FetchResult, error) {
	retries := cfg.Retries
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		// Her denemede TAZE bir request olustur. (Bir *http.Request'i birden cok
		// kez client.Do'ya vermek Go'da onerilmez; retry'de temiz olsun.)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("istek olusturulamadi: %w", err)
		}
		applyHeaders(req, cfg)

		// Rate limit kapisi: token alana kadar bekle (host basina veya global).
		if err := rm.wait(ctx, rawURL); err != nil {
			return nil, err // ctx iptal edildi
		}

		resp, err := client.Do(req)
		if err != nil {
			// Ag hatasi -> retry (varsa).
			lastErr = err
			if attempt < retries {
				backoffBekle(ctx, attempt, 0)
				continue
			}
			return nil, fmt.Errorf("istek basarisiz: %w", err)
		}

		// LimitReader: en fazla maxBodyBytes oku. Dev/ikili dosyalar RAM'i doldurmasin.
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close() // her denemede kapat (connection reuse)
		if readErr != nil {
			lastErr = readErr
			if attempt < retries {
				backoffBekle(ctx, attempt, 0)
				continue
			}
			return nil, fmt.Errorf("govde okunamadi: %w", readErr)
		}

		// 429/503 -> sunucu "yavasla" diyor. Retry-After'a saygi goster.
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if attempt < retries {
				ra := parseRetryAfter(resp.Header.Get("Retry-After"))
				backoffBekle(ctx, attempt, ra)
				continue
			}
			// Deneme hakki bitti -> yine de sonucu dondur (loglanir).
		}

		// Nihai URL: (in-scope) yonlendirmeler izlendikten sonra ulasilan adres.
		finalURL := rawURL
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}
		// Izlenmeyen (scope disi) yonlendirme -> hedefi Location'dan cikar.
		redirectTo := ""
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			if loc := resp.Header.Get("Location"); loc != "" {
				redirectTo = loc
				if resp.Request != nil && resp.Request.URL != nil {
					if ref, perr := url.Parse(loc); perr == nil {
						redirectTo = resp.Request.URL.ResolveReference(ref).String()
					}
				}
			}
		}

		return &FetchResult{
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Body:        body,
			FinalURL:    finalURL,
			RedirectTo:  redirectTo,
		}, nil
	}
	return nil, lastErr
}

// isHTML: content-type HTML mi? Sadece HTML sayfalardan link cikarmak icin.
// (Bir resmi/JS dosyasini HTML gibi parse etmenin anlami yok.)
func isHTML(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/html")
}

// hedefAttr: bir HTML etiketinde hangi attribute'un link tasidigini belirtir.
func hedefAttr(tag string) string {
	switch tag {
	case "a", "link":
		return "href"
	case "script", "img", "iframe":
		return "src"
	case "form":
		return "action"
	default:
		return ""
	}
}

// atilacakScheme: crawl edilemeyecek/anlamsiz scheme'leri isaretler.
// Bu linkler bir sayfaya gitmez (mail acar, JS calistirir vb.) -> ele.
func atilacakScheme(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	for _, p := range []string{"mailto:", "javascript:", "tel:", "data:", "sms:", "ftp:"} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// normalize: ham bir href'i, ait oldugu sayfanin base URL'ine gore
// temiz + absolute bir URL string'ine cevirir.
// (string, true) doner -> gecerli, crawl edilebilir link.
// ("", false) doner    -> atilmali (bos, fragment, mailto, parse hatasi vb.).
func normalize(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)

	// 1) Bos veya sadece fragment (#, #bolum) -> ayni sayfa, at.
	if raw == "" || strings.HasPrefix(raw, "#") {
		return "", false
	}

	// 2) mailto:, javascript:, tel:, data: gibi anlamsiz scheme'leri at.
	if atilacakScheme(raw) {
		return "", false
	}

	// 3) Ham deger bir URL olarak parse edilebiliyor mu?
	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	// 4) Relative -> absolute. ResolveReference tum isi yapar:
	//    "/admin", "../x", "//cdn.site.com/a.js" (protokol-relative) hepsini
	//    base'e gore dogru cozer.
	abs := base.ResolveReference(ref)

	// 5) Sadece http/https crawl ediyoruz (parse sonrasi tekrar kontrol).
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return "", false
	}

	// 6) Fragment'i at (#section) -> ayni sayfadir, tekrar cekmeyelim.
	abs.Fragment = ""

	// 7) Scheme ve host'u kucuk harfe cevir (dedup icin; host case-insensitive).
	abs.Scheme = strings.ToLower(abs.Scheme)
	abs.Host = strings.ToLower(abs.Host)

	// 8) Default port'u at: http+:80 ve https+:443 gereksiz -> kaldir.
	if (abs.Scheme == "http" && abs.Port() == "80") ||
		(abs.Scheme == "https" && abs.Port() == "443") {
		abs.Host = abs.Hostname() // port'suz host
	}

	// 9) Query parametrelerini alfabetik sirala (Encode sirali uretir).
	//    "?b=2&a=1" ve "?a=1&b=2" ayni sayfa -> ayni string olsun.
	if abs.RawQuery != "" {
		abs.RawQuery = abs.Query().Encode()
	}

	return abs.String(), true
}

// inScope: verilen absolute URL, hedef kapsam icinde mi?
// mode:
//
//	"strict"    -> sadece TAM ayni host (ornek: seed go.dev ise sadece go.dev)
//	"subdomain" -> host'un kendisi veya alt alan adlari (go.dev, api.go.dev, x.go.dev)
//
// Not: rawURL burada zaten normalize edilmis (kucuk harf host) kabul edilir.
func inScope(baseHost, rawURL, mode string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname() // port'suz host

	switch mode {
	case "subdomain":
		// Tam esitlik VEYA ".hedef" ile bitmeli.
		// "evilgo.dev" yanlislikla "go.dev" kapsamina girmesin diye
		// nokta ile kontrol ediyoruz: ".go.dev" ile bitiyor mu?
		return host == baseHost || strings.HasSuffix(host, "."+baseHost)
	default: // "strict"
		return host == baseHost
	}
}

// allowedPath: URL'in path'i include/exclude filtrelerine uyuyor mu?
//
//	include bos degilse: path bunu ICERMELI.
//	exclude bos degilse: path bunu ICERMEMELI.
func allowedPath(cfg *Config, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := u.Path
	if cfg.Include != "" && !strings.Contains(p, cfg.Include) {
		return false
	}
	if cfg.Exclude != "" && strings.Contains(p, cfg.Exclude) {
		return false
	}
	return true
}

// isResult: bir worker'in bir URL'i isledikten sonra koordinatore dondurdugu sonuc.
type isResult struct {
	url         string
	res         *FetchResult
	page        *PageData // HTML ise: link + yorum + form
	jsEndpoints []string  // JS ise: cikarilan endpoint'ler
	secrets     []Secret  // icerikte bulunan olasi secret/token'lar
	flags       []string  // bulunan CTF/HTB flag'leri (HTB{...})
	err         error
}

// worker: jobs kanalindan URL alir, fetch + link cikarma yapar, sonucu results'a yollar.
// DIKKAT: worker HICBIR paylasilan state'e (visited/frontier) dokunmaz.
// Tum ortak state koordinatorde tutulur -> mutex'e gerek yok, race yok.
func worker(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, jobs <-chan string, results chan<- isResult) {
	for u := range jobs {
		// Her is icin sonucu panic-korumali uret; boylece bir sayfadaki
		// beklenmedik panic tum programi cokertmez, sadece o is hata olur.
		results <- guvenliIsle(ctx, client, rm, cfg, u)
	}
}

// guvenliIsle: tek bir URL'i isler; icindeki panic'i yakalayip hata sonucuna cevirir.
// Named return (r) sayesinde recover, dondurulecek degeri degistirebilir.
func guvenliIsle(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, u string) (r isResult) {
	defer func() {
		if rec := recover(); rec != nil {
			r = isResult{url: u, err: fmt.Errorf("panic: %v", rec)}
		}
	}()

	res, err := fetch(ctx, client, rm, cfg, u)
	var page *PageData
	var jsEnd []string
	var secrets []Secret
	var flags []string
	if err == nil {
		ct := strings.ToLower(res.ContentType)
		htmlSniff := (res.ContentType == "" || strings.Contains(ct, "octet-stream")) && looksLikeHTML(res.Body)
		switch {
		case isHTML(res.ContentType) || htmlSniff:
			// Content-Type yoksa/octet-stream ise govdeye bakip yine de parse et.
			page, _ = analyzeHTML(res.Body) // link + yorum + form
		case isJS(res.ContentType, u):
			jsEnd = extractJSEndpoints(res.Body) // endpoint'ler
		}
		// Secret/token taramasi: metin tabanli her icerikte calisir.
		if isTextual(res.ContentType, u, res.Body) {
			secrets = extractSecrets(res.Body)
		}
		// Flag avi: TUM govdelerde (icerik tipinden bagimsiz) HTB{...} ara.
		flags = extractFlags(res.Body, cfg.flagRe)
	}
	return isResult{url: u, res: res, page: page, jsEndpoints: jsEnd, secrets: secrets, flags: flags, err: err}
}

// crawl: concurrent BFS crawler (coordinator + worker pool deseni).
// Ortak state'i (visited, frontier) YALNIZCA bu goroutine yonetir; boylece
// mutex'e gerek kalmaz, worker'lar saf (stateless) kalir. Toplanan Report'u
// dondurur; raporun nasil yazilacagina (json/text) cagiran karar verir.
func crawl(ctx context.Context, client *http.Client, rm *rateManager, seed string, cfg *Config, emit func(string, any)) *Report {
	seedURL, _ := url.Parse(seed)
	baseHost := strings.ToLower(seedURL.Hostname())
	cfg.baseHost = baseHost // redirect scope kontrolu (client'in CheckRedirect'i okur)

	// Flag avi desenini bir kez derle (HTB{...} gibi). Worker'lar cfg.flagRe'yi okur.
	if cfg.FlagFormat != "" {
		cfg.flagRe = flagRegex(cfg.FlagFormat)
	}

	scopeMode := cfg.ScopeMode
	maxPages := cfg.MaxPages
	numWorkers := cfg.Workers
	maxDepth := cfg.MaxDepth // <=0 = sinirsiz; seed = derinlik 0
	jsonMode := cfg.Output == "json"
	// progress: canli ilerleme satiri. --quiet ile tamamen susturulur.
	// JSON/JSONL modunda stdout'u temiz tutmak icin stderr'e; text modunda renkli stdout'a.
	progress := func(format string, a ...any) {
		if cfg.Quiet {
			return
		}
		if jsonMode || cfg.Output == "jsonl" {
			fmt.Fprintf(os.Stderr, format, a...)
		} else {
			fmt.Printf(format, a...)
		}
	}
	if emit == nil {
		emit = func(string, any) {} // streaming kapali -> no-op
	}

	jobs := make(chan string)      // koordinator -> worker'lar
	results := make(chan isResult) // worker'lar -> koordinator

	// Worker havuzunu baslat.
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, client, rm, cfg, jobs, results)
		}()
	}

	// --- Koordinatorun tek basina sahip oldugu state ---
	enqueued := map[string]struct{}{seed: {}} // kuyruga alindi mi? (dedup)
	frontier := []string{seed}                // gezilecekler (BFS)
	derinlik := map[string]int{seed: 0}       // url -> BFS derinligi
	statusSayaci := make(map[int]int)
	active := 0 // gonderilmis ama sonucu donmemis is sayisi
	pages := 0  // gonderilen toplam is (max-pages sayaci)
	baslangic := time.Now()

	// enqueue: bir aday URL'i (derinlik limiti + dedup ile) frontier'a ekler.
	// parentDepth < 0 -> kesif kaynagi (robots/sitemap/brute), derinlik = 1 sayilir.
	enqueue := func(norm string, parentDepth int) bool {
		d := 1
		if parentDepth >= 0 {
			d = parentDepth + 1
		}
		// maxDepth <= 0 -> sinirsiz. Bu, Config'i elle kuran kod icin de guvenli
		// (zero-value = 0 = sinirsiz; kazara "sadece seed" olmaz).
		if maxDepth > 0 && d > maxDepth {
			return false // derinlik limiti asildi
		}
		if _, varmi := enqueued[norm]; varmi {
			return false
		}
		enqueued[norm] = struct{}{}
		derinlik[norm] = d
		frontier = append(frontier, norm)
		return true
	}

	// --- Recon bulgulari (koordinatorde toplanir -> race yok) ---
	type yorumKaydi struct{ url, yorum string }
	type formKaydi struct {
		url  string
		form Form
	}
	var tumYorumlar []yorumKaydi
	var tumFormlar []formKaydi
	var pageList []PageInfo                    // gezilen sayfalar (rapor icin)
	jsEndpointSet := make(map[string]struct{}) // dedup
	ilgincSet := make(map[string]string)       // url -> sebep
	notableStatus := make(map[string][]int)    // url -> [status] (401/403/5xx)
	var tumSecrets []Secret                    // bulunan secret/token'lar
	secretSeen := make(map[string]struct{})    // secret dedup (type|match)
	var flagList []FlagFinding                 // bulunan CTF/HTB flag'leri
	flagSeen := make(map[string]struct{})      // flag dedup
	redirects := make(map[string]string)       // istenen url -> hedef/nihai url
	duplicates := make(map[string]string)      // url -> ayni govdeye sahip ilk url
	bodyHashes := make(map[[32]byte]string)    // govde hash -> ilk gorulen url
	statusByURL := make(map[string]int)        // url -> status (robots yollarinin sonucu icin)

	// robots.txt / sitemap.xml ile frontier'i onceden besle.
	var robotsInfo *RobotsInfo
	if !cfg.SkipRobots {
		adaylar, ri := robotsSitemapTara(ctx, client, rm, cfg, seedURL)
		robotsInfo = ri
		robotsPathSeen := make(map[string]struct{})
		eklenen := 0
		for _, k := range adaylar {
			norm, ok := normalize(seedURL, k.url)
			if !ok || !inScope(baseHost, norm, scopeMode) || !allowedPath(cfg, norm) {
				continue
			}
			// robots girdileri gizli yol ipucu -> kaynagiyla ilginc olarak isaretle
			// (Allow ve Disallow ayri etiketlenir: "robots-allow" / "robots-disallow".)
			if strings.HasPrefix(k.kaynak, "robots") {
				if _, zaten := ilgincSet[norm]; !zaten {
					ilgincSet[norm] = k.kaynak
				}
				// robots yolunu rapora ekle; status crawl sonunda doldurulacak.
				// HTB: Disallow'u dinlemiyoruz, tam tersine HEDEF olarak geziyoruz.
				if _, gorildi := robotsPathSeen[norm]; !gorildi {
					robotsPathSeen[norm] = struct{}{}
					robotsInfo.Paths = append(robotsInfo.Paths, RobotsPath{
						Path: norm, Source: strings.TrimPrefix(k.kaynak, "robots-"),
					})
				}
			}
			if enqueue(norm, -1) {
				eklenen++
			}
		}
		if robotsInfo.Found {
			progress("[*] robots.txt found -> %d path(s) queued as TARGETS (Disallow bypassed)\n\n", len(robotsInfo.Paths))
		} else if eklenen > 0 {
			progress("[*] added %d paths from sitemap to the frontier\n\n", eklenen)
		}
	}

	// brute-force: wordlist ile gizli yol tahmini.
	var bruteFound []BruteResult
	if len(cfg.Words) > 0 {
		progress("[*] brute-force: trying %d words...\n", len(cfg.Words))
		bruteFound = bruteForce(ctx, client, rm, cfg, seedURL, cfg.Words)
		// Bulunan (404 olmayan) yollari frontier'a ekle -> linklerini de gez.
		for _, br := range bruteFound {
			emit("brute", br)
			norm, ok := normalize(seedURL, br.URL)
			if !ok || !inScope(baseHost, norm, scopeMode) || !allowedPath(cfg, norm) {
				continue
			}
			enqueue(norm, -1)
		}
		progress("[*] brute-force: %d paths found (non-404)\n\n", len(bruteFound))
	}

	// Koordinator dongusu:
	//   Her turda ya bir is GONDER ya da bir sonuc AL (select ile).
	//   Cikis kosulu: ne isleyecek is kaldi (active) ne de gonderecek (frontier+limit).
	iptal := false        // Ctrl+C alindi mi?
	ctxDone := ctx.Done() // iptal sinyal kanali
	for active > 0 || (!iptal && len(frontier) > 0 && pages < maxPages) {
		// Gonderilecek bir sonraki is var mi? (limit dolmadiysa ve iptal yoksa)
		var sendCh chan<- string
		var next string
		if !iptal && len(frontier) > 0 && pages < maxPages {
			next = frontier[0]
			sendCh = jobs // gondermeye hazir
		}
		// sendCh nil ise (gonderecek is yok), select yalnizca results/iptal'i dinler.

		select {
		case <-ctxDone:
			// Ctrl+C: yeni is gonderme, mevcut isleri bitir, raporu yine de yaz.
			iptal = true
			ctxDone = nil // bir daha secilmesin (busy-loop olmasin)
			progress("\n[!] cancel signal received, finishing in-flight jobs (report will still be written)...\n")

		case sendCh <- next:
			// Is bir worker'a verildi.
			frontier = frontier[1:]
			active++
			pages++

		case r := <-results:
			// Bir worker is bitirdi.
			active--

			if r.err != nil {
				progress("[%s] %s -> %v\n", renkKirmizi("ERROR"), r.url, r.err)
				continue
			}
			curDepth := derinlik[r.url]

			// FLAG bulundu -> ANINDA bildir. quiet/json fark etmez: stderr'e basiyoruz,
			// boylece rapor stdout'a giderken bile flag'i hemen ekranda gorursun.
			for _, fl := range r.flags {
				if _, ok := flagSeen[fl]; ok {
					continue
				}
				flagSeen[fl] = struct{}{}
				flagList = append(flagList, FlagFinding{Flag: fl, URL: r.url})
				emit("flag", FlagFinding{Flag: fl, URL: r.url})
				fmt.Fprintf(os.Stderr, "\n%s %s\n    %s\n\n",
					renkYesil("[FLAG FOUND]"), renkYesil("%s", fl), renkGri("source: %s", r.url))
			}

			// Linkleri sayfanin KENDI (nihai) URL'ine gore coz, seed'e degil.
			// Alt dizinlerdeki goreli linkler ("chapter2.html") boylece dogru cozulur.
			pageBase := seedURL
			if r.res.FinalURL != "" {
				if pb, perr := url.Parse(r.res.FinalURL); perr == nil {
					pageBase = pb
				}
			}

			// Yonlendirme kaydi (rapor dogrulugu).
			if r.res.RedirectTo != "" {
				redirects[r.url] = r.res.RedirectTo
			} else if r.res.FinalURL != "" && r.res.FinalURL != r.url {
				redirects[r.url] = r.res.FinalURL
			}

			statusSayaci[r.res.StatusCode]++
			statusByURL[r.url] = r.res.StatusCode
			pi := PageInfo{
				URL: r.url, Status: r.res.StatusCode, ContentType: r.res.ContentType,
				Size: len(r.res.Body), Depth: curDepth, RedirectTo: r.res.RedirectTo,
			}
			pageList = append(pageList, pi)
			emit("page", pi)

			// Dikkat cekici status: 401/403 (gizli), 5xx (sunucu hatasi).
			if r.res.StatusCode == 401 || r.res.StatusCode == 403 || r.res.StatusCode >= 500 {
				notableStatus[r.url] = append(notableStatus[r.url], r.res.StatusCode)
				emit("notable", map[string]any{"url": r.url, "status": r.res.StatusCode})
			}
			// Fetch edilen URL'in kendisi ilginc mi?
			if sebep, ok := ilgincMi(r.url); ok {
				if _, zaten := ilgincSet[r.url]; !zaten {
					ilgincSet[r.url] = sebep
					emit("interesting", map[string]any{"url": r.url, "reason": sebep})
				}
			}

			// Govde dedup: ayni icerik farkli URL'de -> tekrar analiz etme,
			// sadece duplicate olarak kaydet (gurultuyu azaltir).
			var isDup bool
			if len(r.res.Body) > 0 {
				h := sha256.Sum256(r.res.Body)
				if first, ok := bodyHashes[h]; ok {
					duplicates[r.url] = first
					isDup = true
				} else {
					bodyHashes[h] = r.url
				}
			}

			// Secret/token bulgularini topla (duplicate degilse; ilk kopyada zaten var).
			if !isDup {
				for _, s := range r.secrets {
					s.URL = r.url
					anahtar := s.Type + "|" + s.Match
					if _, ok := secretSeen[anahtar]; ok {
						continue
					}
					if len(tumSecrets) >= 500 {
						break // asiri gurultuye karsi ust sinir
					}
					secretSeen[anahtar] = struct{}{}
					tumSecrets = append(tumSecrets, s)
					emit("secret", s)
				}
			}

			if isDup {
				progress("[%s] %-7s %s  (dup of %s)\n", statusRenkli(r.res.StatusCode), "dup", r.url, duplicates[r.url])
				continue
			}

			// JS ise endpoint'leri topla.
			if len(r.jsEndpoints) > 0 {
				for _, e := range r.jsEndpoints {
					jsEndpointSet[e] = struct{}{}

					// In-scope JS endpoint'lerini de kuyruga al (--no-js-crawl ile
					// kapatilabilir). JS icindeki "/api/..." gibi linklenmemis
					// yollar boylece gercekten gezilir.
					if !cfg.CrawlJS {
						continue
					}
					norm, ok := normalize(pageBase, e)
					if !ok || !inScope(baseHost, norm, scopeMode) || !allowedPath(cfg, norm) {
						continue
					}
					enqueue(norm, curDepth)
				}
			}

			// HTML degilse link cikarma yok -> asset olarak logla.
			if r.page == nil {
				etiket := "(asset)"
				if len(r.jsEndpoints) > 0 {
					etiket = "(js)"
				}
				progress("[%s] %-7s %s\n", statusRenkli(r.res.StatusCode), etiket, r.url)
				continue
			}

			// Yorumlari topla.
			for _, c := range r.page.Comments {
				tumYorumlar = append(tumYorumlar, yorumKaydi{url: r.url, yorum: c})
			}
			// Formlari topla.
			for _, f := range r.page.Forms {
				tumFormlar = append(tumFormlar, formKaydi{url: r.url, form: f})
				emit("form", FormReport{
					URL: r.url, Action: f.Action, Method: f.Method,
					Inputs: f.Inputs, HasCSRF: f.HasCSRF, HasPassword: f.HasPassword,
				})
			}

			// Yeni in-scope linkleri kuyruga ekle.
			yeni := 0
			for _, l := range r.page.Links {
				norm, ok := normalize(pageBase, l.Value)
				if !ok {
					continue
				}
				// Kesfedilen her link icin ilginclik kontrolu (scope disi olsa bile).
				if sebep, ilg := ilgincMi(norm); ilg {
					if _, zaten := ilgincSet[norm]; !zaten {
						ilgincSet[norm] = sebep
						emit("interesting", map[string]any{"url": norm, "reason": sebep})
					}
				}
				if !inScope(baseHost, norm, scopeMode) {
					continue
				}
				if !allowedPath(cfg, norm) {
					continue // include/exclude filtresi
				}
				if enqueue(norm, curDepth) {
					yeni++
				}
			}
			progress("[%s] %-7s %s  (%d new, queue: %d, active: %d)\n",
				statusRenkli(r.res.StatusCode), "html", r.url, yeni, len(frontier), active)
		}
	}

	// Is bitti: jobs'u kapat -> worker'lar range dongusunden cikar -> wg biter.
	close(jobs)
	wg.Wait()

	if pages >= maxPages && len(frontier) > 0 {
		progress("\n[!] max-pages limit (%d) reached (%d URLs left in queue).\n", maxPages, len(frontier))
	}

	// --- Toplanan verileri Report'a donustur ---
	jsEndpoints := make([]string, 0, len(jsEndpointSet))
	for e := range jsEndpointSet {
		jsEndpoints = append(jsEndpoints, e)
	}
	sort.Strings(jsEndpoints)

	forms := make([]FormReport, 0, len(tumFormlar))
	for _, fk := range tumFormlar {
		forms = append(forms, FormReport{
			URL: fk.url, Action: fk.form.Action, Method: fk.form.Method,
			Inputs: fk.form.Inputs, HasCSRF: fk.form.HasCSRF, HasPassword: fk.form.HasPassword,
		})
	}

	comments := make([]CommentReport, 0, len(tumYorumlar))
	for _, yk := range tumYorumlar {
		comments = append(comments, CommentReport{URL: yk.url, Comment: yk.yorum})
	}

	// robots.txt yollarinin gercek status'unu (crawl sonucu) doldur.
	if robotsInfo != nil {
		for i := range robotsInfo.Paths {
			robotsInfo.Paths[i].Status = statusByURL[robotsInfo.Paths[i].Path]
		}
		emit("robots", robotsInfo)
	}

	report := &Report{
		Target:         seed,
		Scope:          scopeMode,
		Workers:        numWorkers,
		DurationMs:     time.Since(baslangic).Milliseconds(),
		PagesCrawled:   pages,
		URLsDiscovered: len(enqueued),
		StatusCounts:   statusSayaci,
		Pages:          pageList,
		NotableStatus:  notableStatus,
		Interesting:    ilgincSet,
		JSEndpoints:    jsEndpoints,
		Forms:          forms,
		Comments:       comments,
		Secrets:        tumSecrets,
		Flags:          flagList,
		BruteFound:     bruteFound,
		Robots:         robotsInfo,
		Redirects:      redirects,
		Duplicates:     duplicates,
	}

	emit("summary", map[string]any{
		"pages_crawled": pages, "urls_discovered": len(enqueued),
		"duration_ms": report.DurationMs, "status_counts": statusSayaci,
	})

	return report
}

func main() {
	// --- Flag tanimlari ---
	scopeMode := flag.String("scope", "strict", "scope mode: strict | subdomain")
	maxPages := flag.Int("max-pages", 200, "maximum number of pages to crawl")
	workers := flag.Int("workers", 10, "number of concurrent workers (goroutines)")
	ratePerSec := flag.Float64("rate", 0, "maximum requests per second (0 = unlimited)")
	retries := flag.Int("retries", 2, "number of retries on error/429/503")
	output := flag.String("output", "text", "output format: text | json")
	outputFile := flag.String("output-file", "", "write the report to this file (empty = stdout)")
	noJSCrawl := flag.Bool("no-js-crawl", false, "do not crawl in-scope endpoints extracted from JS (default: crawl them)")
	noColor := flag.Bool("no-color", false, "disable colored output")
	userAgent := flag.String("user-agent", "", "custom User-Agent (empty = default)")
	cookie := flag.String("cookie", "", "Cookie header (authenticated crawl, e.g. 'session=abc')")
	include := flag.String("include", "", "only crawl URLs whose path contains this substring")
	exclude := flag.String("exclude", "", "skip URLs whose path contains this substring")
	proxy := flag.String("proxy", "", "HTTP proxy (e.g. http://127.0.0.1:8080 - Burp)")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification (Burp/self-signed)")
	quiet := flag.Bool("quiet", false, "suppress live progress, print report only")
	noRobots := flag.Bool("no-robots", false, "skip robots.txt/sitemap.xml discovery")
	wordlist := flag.String("wordlist", "", "brute-force wordlist file (guess hidden paths)")
	depth := flag.Int("depth", 0, "max BFS depth from seed (0 = unlimited; 1 = seed + its direct links)")
	ratePerHost := flag.Bool("rate-per-host", false, "apply --rate per host instead of globally (useful in subdomain scope)")
	extensions := flag.String("x", "", "brute-force extensions, comma-separated (e.g. php,bak,txt)")
	bruteRecursive := flag.Bool("brute-recursive", false, "recurse into directories found by brute-force")
	bruteDepth := flag.Int("brute-depth", 1, "recursion depth for --brute-recursive")
	exitCode := flag.Bool("exit-code", false, "exit non-zero (2) if any findings (for CI/automation)")
	flagFormat := flag.String("flag-format", "HTB", "CTF flag prefix to hunt for, e.g. HTB -> HTB{...} (empty disables)")
	var headers stringSlice
	flag.Var(&headers, "H", "extra header 'Key: Value' (repeatable)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: zakspider [flags] <url>")
		fmt.Fprintln(os.Stderr, "example: zakspider --scope subdomain --proxy http://127.0.0.1:8080 --insecure https://target.htb")
		flag.PrintDefaults()
	}
	flag.Parse()

	// URL, flag'lerden sonraki ilk pozisyonel argumandir.
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	target := flag.Arg(0)

	if *scopeMode != "strict" && *scopeMode != "subdomain" {
		fmt.Fprintf(os.Stderr, "invalid scope mode: %s (strict|subdomain)\n", *scopeMode)
		os.Exit(1)
	}
	if *output != "text" && *output != "json" && *output != "jsonl" {
		fmt.Fprintf(os.Stderr, "invalid output: %s (text|json|jsonl)\n", *output)
		os.Exit(1)
	}

	// Renk: JSON modunda veya --no-color'da kapali.
	setColorEnabled(*output == "text" && !*noColor)

	// Seed URL kontrolu.
	base, err := url.Parse(target)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") {
		fmt.Fprintf(os.Stderr, "invalid url (must be http/https): %s\n", target)
		os.Exit(1)
	}

	if *workers < 1 {
		*workers = 1
	}

	// Uzanti listesini parse et (-x php,bak,txt).
	var exts []string
	for _, e := range strings.Split(*extensions, ",") {
		if e = strings.TrimSpace(e); e != "" {
			exts = append(exts, e)
		}
	}

	// Tum ayarlari Config'te topla.
	cfg := &Config{
		ScopeMode:      *scopeMode,
		MaxPages:       *maxPages,
		Workers:        *workers,
		RatePerSec:     *ratePerSec,
		Retries:        *retries,
		Output:         *output,
		OutputFile:     *outputFile,
		CrawlJS:        !*noJSCrawl,
		UserAgent:      *userAgent,
		Cookie:         *cookie,
		Headers:        headers,
		Include:        *include,
		Exclude:        *exclude,
		Proxy:          *proxy,
		Insecure:       *insecure,
		Quiet:          *quiet,
		SkipRobots:     *noRobots,
		Wordlist:       *wordlist,
		MaxDepth:       *depth,
		PerHostRate:    *ratePerHost,
		Extensions:     exts,
		BruteRecursive: *bruteRecursive,
		BruteDepth:     *bruteDepth,
		ExitCode:       *exitCode,
		FlagFormat:     *flagFormat,
		baseHost:       strings.ToLower(base.Hostname()),
	}

	// Wordlist verildiyse yukle.
	if cfg.Wordlist != "" {
		words, werr := wordlistYukle(cfg.Wordlist)
		if werr != nil {
			fmt.Fprintf(os.Stderr, "could not read wordlist: %v\n", werr)
			os.Exit(1)
		}
		cfg.Words = words
	}

	client, err := newClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create client: %v\n", err)
		os.Exit(1)
	}

	rateStr := "unlimited"
	if cfg.RatePerSec > 0 {
		rateStr = fmt.Sprintf("%.1f req/s", cfg.RatePerSec)
	}
	proxyStr := "none"
	if cfg.Proxy != "" {
		proxyStr = cfg.Proxy
	}
	// Banner: JSON/JSONL modunda stdout'u kirletmemek icin stderr'e.
	banner := os.Stdout
	if cfg.Output == "json" || cfg.Output == "jsonl" {
		banner = os.Stderr
	}
	fmt.Fprintf(banner, "[*] Target  : %s\n", target)
	fmt.Fprintf(banner, "[*] Scope   : %s\n", cfg.ScopeMode)
	fmt.Fprintf(banner, "[*] MaxPages: %d\n", cfg.MaxPages)
	fmt.Fprintf(banner, "[*] Workers : %d\n", cfg.Workers)
	fmt.Fprintf(banner, "[*] Rate    : %s\n", rateStr)
	fmt.Fprintf(banner, "[*] Proxy   : %s\n", proxyStr)
	if cfg.Cookie != "" {
		fmt.Fprintf(banner, "[*] Cookie  : (set)\n")
	}
	fmt.Fprintf(banner, "\n")

	// Hiz yoneticisi: global veya host basina token bucket.
	rm := newRateManager(cfg.RatePerSec, cfg.PerHostRate)

	// Cikti hedefi: --output-file verildiyse dosya, yoksa stdout.
	// (JSONL streaming icin writer'i taramadan ONCE hazirlamaliyiz.)
	var out io.Writer = os.Stdout
	var closeFn func()
	if cfg.OutputFile != "" {
		f, ferr := os.Create(cfg.OutputFile)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "could not create output file: %v\n", ferr)
			os.Exit(1)
		}
		closeFn = func() { _ = f.Close() }
		out = f
		setColorEnabled(false) // dosyaya ANSI renk kodu yazma
	}

	// JSONL modunda bulgular OLUSTUKCA satir satir yazilir (streaming).
	var emit func(string, any)
	if cfg.Output == "jsonl" {
		emit = newJSONLEmitter(out)
	}

	// Graceful shutdown: Ctrl+C (SIGINT) gelince ctx iptal edilir.
	// crawl bunu gorup yeni is gondermeyi durdurur ama raporu yine de yazar.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	report := crawl(ctx, client, rm, target, cfg, emit)

	// Cikti moduna gore raporu yaz.
	switch cfg.Output {
	case "json":
		if err := writeJSON(out, report); err != nil {
			fmt.Fprintf(os.Stderr, "could not write json: %v\n", err)
		}
	case "jsonl":
		// Bulgular zaten stream edildi; ozet "summary" olayinda yazildi.
	default:
		printTextReport(out, report)
	}

	// os.Exit defer'lari atlar -> dosyayi elle kapat.
	if closeFn != nil {
		closeFn()
	}
	if cfg.OutputFile != "" {
		fmt.Fprintf(os.Stderr, "[*] Report written: %s\n", cfg.OutputFile)
	}

	// --exit-code -> bulgu varsa 2 don (otomasyon/CI pipeline'lari icin).
	if cfg.ExitCode && bulguVarMi(report) {
		os.Exit(2)
	}
}

// bulguVarMi: raporda dikkate deger bir bulgu var mi? (--exit-code icin).
func bulguVarMi(r *Report) bool {
	return len(r.Flags) > 0 || len(r.NotableStatus) > 0 || len(r.Interesting) > 0 ||
		len(r.Secrets) > 0 || len(r.Forms) > 0 || len(r.BruteFound) > 0 || len(r.JSEndpoints) > 0
}
