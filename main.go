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

type Link struct {
	Tag   string
	Attr  string
	Value string
}

type FetchResult struct {
	StatusCode  int
	ContentType string
	Body        []byte
	FinalURL    string
	RedirectTo  string
}

type Config struct {
	ScopeMode  string
	MaxPages   int
	Workers    int
	RatePerSec float64
	Retries    int
	Output     string
	OutputFile string
	CrawlJS    bool
	UserAgent  string
	Cookie     string
	Headers    []string
	Include    string
	Exclude    string
	Proxy      string
	Insecure   bool
	Quiet      bool
	SkipRobots bool
	Wordlist   string
	Words      []string

	MaxDepth       int
	PerHostRate    bool
	Extensions     []string
	BruteRecursive bool
	BruteDepth     int
	ExitCode       bool
	FlagFormat     string

	baseHost string
	flagRe   *regexp.Regexp
}

type rateManager struct {
	mu          sync.Mutex
	perHost     map[string]*rate.Limiter
	rps         rate.Limit
	perHostMode bool
	global      *rate.Limiter
}

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

func (rm *rateManager) wait(ctx context.Context, rawURL string) error {
	host := ""
	if rm.perHostMode {
		if u, err := url.Parse(rawURL); err == nil {
			host = u.Hostname()
		}
	}
	return rm.forHost(host).Wait(ctx)
}

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

const maxBodyBytes = 5 << 20

func newClient(cfg *Config) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("gecersiz proxy: %w", err)
		}
		transport.Proxy = http.ProxyURL(pu)
	}

	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,

		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("cok fazla redirect (>10)")
			}

			if cfg.baseHost != "" && !inScope(cfg.baseHost, req.URL.String(), cfg.ScopeMode) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, nil
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}

	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}

	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func backoffWait(ctx context.Context, attempt int, retryAfter time.Duration) {
	var d time.Duration
	if retryAfter > 0 {
		d = retryAfter
	} else {

		d = 500 * time.Millisecond * time.Duration(1<<attempt)
	}

	d += time.Duration(rand.Intn(250)) * time.Millisecond

	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func applyHeaders(req *http.Request, cfg *Config) {
	ua := cfg.UserAgent
	if ua == "" {
		ua = "zakspider/0.1 (+recon)"
	}
	req.Header.Set("User-Agent", ua)

	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}

	for _, h := range cfg.Headers {
		if k, v, ok := strings.Cut(h, ":"); ok {
			req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
}

func fetch(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, rawURL string) (*FetchResult, error) {
	retries := cfg.Retries
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("istek olusturulamadi: %w", err)
		}
		applyHeaders(req, cfg)

		if err := rm.wait(ctx, rawURL); err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {

			lastErr = err
			if attempt < retries {
				backoffWait(ctx, attempt, 0)
				continue
			}
			return nil, fmt.Errorf("istek basarisiz: %w", err)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if attempt < retries {
				backoffWait(ctx, attempt, 0)
				continue
			}
			return nil, fmt.Errorf("govde okunamadi: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			if attempt < retries {
				ra := parseRetryAfter(resp.Header.Get("Retry-After"))
				backoffWait(ctx, attempt, ra)
				continue
			}

		}

		finalURL := rawURL
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}

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

func isHTML(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/html")
}

func linkAttr(tag string) string {
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

func skipScheme(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	for _, p := range []string{"mailto:", "javascript:", "tel:", "data:", "sms:", "ftp:"} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func normalize(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)

	if raw == "" || strings.HasPrefix(raw, "#") {
		return "", false
	}

	if skipScheme(raw) {
		return "", false
	}

	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	abs := base.ResolveReference(ref)

	if abs.Scheme != "http" && abs.Scheme != "https" {
		return "", false
	}

	abs.Fragment = ""

	abs.Scheme = strings.ToLower(abs.Scheme)
	abs.Host = strings.ToLower(abs.Host)

	if (abs.Scheme == "http" && abs.Port() == "80") ||
		(abs.Scheme == "https" && abs.Port() == "443") {
		abs.Host = abs.Hostname()
	}

	if abs.RawQuery != "" {
		abs.RawQuery = abs.Query().Encode()
	}

	return abs.String(), true
}

func inScope(baseHost, rawURL, mode string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()

	switch mode {
	case "subdomain":

		return host == baseHost || strings.HasSuffix(host, "."+baseHost)
	default:
		return host == baseHost
	}
}

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

type isResult struct {
	url         string
	res         *FetchResult
	page        *PageData
	jsEndpoints []string
	secrets     []Secret
	flags       []string
	err         error
}

func worker(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, jobs <-chan string, results chan<- isResult) {
	for u := range jobs {

		results <- processSafely(ctx, client, rm, cfg, u)
	}
}

func processSafely(ctx context.Context, client *http.Client, rm *rateManager, cfg *Config, u string) (r isResult) {
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

			page, _ = analyzeHTML(res.Body)
		case isJS(res.ContentType, u):
			jsEnd = extractJSEndpoints(res.Body)
		}

		if isTextual(res.ContentType, u, res.Body) {
			secrets = extractSecrets(res.Body)
		}

		flags = extractFlags(res.Body, cfg.flagRe)
	}
	return isResult{url: u, res: res, page: page, jsEndpoints: jsEnd, secrets: secrets, flags: flags, err: err}
}

func crawl(ctx context.Context, client *http.Client, rm *rateManager, seed string, cfg *Config, emit func(string, any)) *Report {
	seedURL, _ := url.Parse(seed)
	baseHost := strings.ToLower(seedURL.Hostname())
	cfg.baseHost = baseHost

	if cfg.FlagFormat != "" {
		cfg.flagRe = flagRegex(cfg.FlagFormat)
	}

	scopeMode := cfg.ScopeMode
	maxPages := cfg.MaxPages
	numWorkers := cfg.Workers
	maxDepth := cfg.MaxDepth
	jsonMode := cfg.Output == "json"

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
		emit = func(string, any) {}
	}

	jobs := make(chan string)
	results := make(chan isResult)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, client, rm, cfg, jobs, results)
		}()
	}

	enqueued := map[string]struct{}{seed: {}}
	frontier := []string{seed}
	derinlik := map[string]int{seed: 0}
	statusSayaci := make(map[int]int)
	active := 0
	pages := 0
	baslangic := time.Now()

	enqueue := func(norm string, parentDepth int) bool {
		d := 1
		if parentDepth >= 0 {
			d = parentDepth + 1
		}

		if maxDepth > 0 && d > maxDepth {
			return false
		}
		if _, varmi := enqueued[norm]; varmi {
			return false
		}
		enqueued[norm] = struct{}{}
		derinlik[norm] = d
		frontier = append(frontier, norm)
		return true
	}

	type yorumKaydi struct{ url, yorum string }
	type formKaydi struct {
		url  string
		form Form
	}
	var tumYorumlar []yorumKaydi
	var tumFormlar []formKaydi
	var pageList []PageInfo
	jsEndpointSet := make(map[string]struct{})
	ilgincSet := make(map[string]string)
	notableStatus := make(map[string][]int)
	var tumSecrets []Secret
	secretSeen := make(map[string]struct{})
	var flagList []FlagFinding
	flagSeen := make(map[string]struct{})
	redirects := make(map[string]string)
	duplicates := make(map[string]string)
	bodyHashes := make(map[[32]byte]string)
	statusByURL := make(map[string]int)

	var robotsInfo *RobotsInfo
	if !cfg.SkipRobots {
		adaylar, ri := scanRobotsSitemap(ctx, client, rm, cfg, seedURL)
		robotsInfo = ri
		robotsPathSeen := make(map[string]struct{})
		eklenen := 0
		for _, k := range adaylar {
			norm, ok := normalize(seedURL, k.url)
			if !ok || !inScope(baseHost, norm, scopeMode) || !allowedPath(cfg, norm) {
				continue
			}

			if strings.HasPrefix(k.kaynak, "robots") {
				if _, zaten := ilgincSet[norm]; !zaten {
					ilgincSet[norm] = k.kaynak
				}

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

	var bruteFound []BruteResult
	if len(cfg.Words) > 0 {
		progress("[*] brute-force: trying %d words...\n", len(cfg.Words))
		bruteFound = bruteForce(ctx, client, rm, cfg, seedURL, cfg.Words)

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

	iptal := false
	ctxDone := ctx.Done()
	for active > 0 || (!iptal && len(frontier) > 0 && pages < maxPages) {

		var sendCh chan<- string
		var next string
		if !iptal && len(frontier) > 0 && pages < maxPages {
			next = frontier[0]
			sendCh = jobs
		}

		select {
		case <-ctxDone:

			iptal = true
			ctxDone = nil
			progress("\n[!] cancel signal received, finishing in-flight jobs (report will still be written)...\n")

		case sendCh <- next:

			frontier = frontier[1:]
			active++
			pages++

		case r := <-results:

			active--

			if r.err != nil {
				progress("[%s] %s -> %v\n", colorRed("ERROR"), r.url, r.err)
				continue
			}
			curDepth := derinlik[r.url]

			for _, fl := range r.flags {
				if _, ok := flagSeen[fl]; ok {
					continue
				}
				flagSeen[fl] = struct{}{}
				flagList = append(flagList, FlagFinding{Flag: fl, URL: r.url})
				emit("flag", FlagFinding{Flag: fl, URL: r.url})
				fmt.Fprintf(os.Stderr, "\n%s %s\n    %s\n\n",
					colorGreen("[FLAG FOUND]"), colorGreen("%s", fl), colorGray("source: %s", r.url))
			}

			pageBase := seedURL
			if r.res.FinalURL != "" {
				if pb, perr := url.Parse(r.res.FinalURL); perr == nil {
					pageBase = pb
				}
			}

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

			if r.res.StatusCode == 401 || r.res.StatusCode == 403 || r.res.StatusCode >= 500 {
				notableStatus[r.url] = append(notableStatus[r.url], r.res.StatusCode)
				emit("notable", map[string]any{"url": r.url, "status": r.res.StatusCode})
			}

			if sebep, ok := isInteresting(r.url); ok {
				if _, zaten := ilgincSet[r.url]; !zaten {
					ilgincSet[r.url] = sebep
					emit("interesting", map[string]any{"url": r.url, "reason": sebep})
				}
			}

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

			if !isDup {
				for _, s := range r.secrets {
					s.URL = r.url
					anahtar := s.Type + "|" + s.Match
					if _, ok := secretSeen[anahtar]; ok {
						continue
					}
					if len(tumSecrets) >= 500 {
						break
					}
					secretSeen[anahtar] = struct{}{}
					tumSecrets = append(tumSecrets, s)
					emit("secret", s)
				}
			}

			if isDup {
				progress("[%s] %-7s %s  (dup of %s)\n", colorStatus(r.res.StatusCode), "dup", r.url, duplicates[r.url])
				continue
			}

			if len(r.jsEndpoints) > 0 {
				for _, e := range r.jsEndpoints {
					jsEndpointSet[e] = struct{}{}

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

			if r.page == nil {
				etiket := "(asset)"
				if len(r.jsEndpoints) > 0 {
					etiket = "(js)"
				}
				progress("[%s] %-7s %s\n", colorStatus(r.res.StatusCode), etiket, r.url)
				continue
			}

			for _, c := range r.page.Comments {
				tumYorumlar = append(tumYorumlar, yorumKaydi{url: r.url, yorum: c})
			}

			for _, f := range r.page.Forms {
				tumFormlar = append(tumFormlar, formKaydi{url: r.url, form: f})
				emit("form", FormReport{
					URL: r.url, Action: f.Action, Method: f.Method,
					Inputs: f.Inputs, HasCSRF: f.HasCSRF, HasPassword: f.HasPassword,
				})
			}

			yeni := 0
			for _, l := range r.page.Links {
				norm, ok := normalize(pageBase, l.Value)
				if !ok {
					continue
				}

				if sebep, ilg := isInteresting(norm); ilg {
					if _, zaten := ilgincSet[norm]; !zaten {
						ilgincSet[norm] = sebep
						emit("interesting", map[string]any{"url": norm, "reason": sebep})
					}
				}
				if !inScope(baseHost, norm, scopeMode) {
					continue
				}
				if !allowedPath(cfg, norm) {
					continue
				}
				if enqueue(norm, curDepth) {
					yeni++
				}
			}
			progress("[%s] %-7s %s  (%d new, queue: %d, active: %d)\n",
				colorStatus(r.res.StatusCode), "html", r.url, yeni, len(frontier), active)
		}
	}

	close(jobs)
	wg.Wait()

	if pages >= maxPages && len(frontier) > 0 {
		progress("\n[!] max-pages limit (%d) reached (%d URLs left in queue).\n", maxPages, len(frontier))
	}

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

	setColorEnabled(*output == "text" && !*noColor)

	base, err := url.Parse(target)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") {
		fmt.Fprintf(os.Stderr, "invalid url (must be http/https): %s\n", target)
		os.Exit(1)
	}

	if *workers < 1 {
		*workers = 1
	}

	var exts []string
	for _, e := range strings.Split(*extensions, ",") {
		if e = strings.TrimSpace(e); e != "" {
			exts = append(exts, e)
		}
	}

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

	if cfg.Wordlist != "" {
		words, werr := loadWordlist(cfg.Wordlist)
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

	rm := newRateManager(cfg.RatePerSec, cfg.PerHostRate)

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
		setColorEnabled(false)
	}

	var emit func(string, any)
	if cfg.Output == "jsonl" {
		emit = newJSONLEmitter(out)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	report := crawl(ctx, client, rm, target, cfg, emit)

	switch cfg.Output {
	case "json":
		if err := writeJSON(out, report); err != nil {
			fmt.Fprintf(os.Stderr, "could not write json: %v\n", err)
		}
	case "jsonl":

	default:
		printTextReport(out, report)
	}

	if closeFn != nil {
		closeFn()
	}
	if cfg.OutputFile != "" {
		fmt.Fprintf(os.Stderr, "[*] Report written: %s\n", cfg.OutputFile)
	}

	if cfg.ExitCode && hasFindings(report) {
		os.Exit(2)
	}
}

func hasFindings(r *Report) bool {
	return len(r.Flags) > 0 || len(r.NotableStatus) > 0 || len(r.Interesting) > 0 ||
		len(r.Secrets) > 0 || len(r.Forms) > 0 || len(r.BruteFound) > 0 || len(r.JSEndpoints) > 0
}
