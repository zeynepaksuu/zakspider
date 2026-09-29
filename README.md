# zakspider

A concurrent, recon-focused web crawler written in Go, built for HackTheBox and
authorized pentest labs.

It crawls a target and, while crawling, extracts the attack surface: forms, JS
endpoints, HTML comments, hidden files and leaked secrets. Next to passive
crawling it also does active discovery — robots.txt/sitemap parsing and wordlist
brute-force — to reach paths that are not linked anywhere.

## Features

- Concurrent BFS crawl on a coordinator/worker-pool design (lock-free, race-free)
- Scope control: `strict` (single host) or `subdomain`, with bypass protection; off-scope redirects are not followed
- Rate limiting (global or per-host token bucket) with retry, exponential backoff and jitter
- Recon: HTML comments, forms with CSRF/password flags, JS endpoints, sensitive files (`.git`, `.env`, `.bak`)
- Secret scanning: JWT, AWS/Google/Slack/GitHub tokens, private keys, S3 buckets, generic `api_key`/`password`
- Flag hunting: scans every response body for `HTB{...}` (configurable via `--flag-format`) and prints the flag as soon as it appears
- robots.txt as a target list: reads it and crawls the `Disallow` paths as targets instead of obeying them, reporting each with the status it returned
- Active discovery: robots/sitemap parsing (Allow/Disallow labelled separately) + wordlist brute-force with extensions and recursion, filtered by a learned soft-404 baseline
- JS endpoint crawling, content-type sniffing, duplicate detection (body hash), depth limit
- Pentest integration: Burp proxy (`--proxy`), authenticated crawl (`--cookie`, `-H`)
- Output: colored text, JSON, or JSONL streaming; `--exit-code` for CI
- Graceful shutdown, panic recovery, response size limit, redirect-loop control

## How it works

A crawler is a graph traversal problem: each page is a node, each link an edge.
zakspider walks this graph breadth-first (BFS).

A single coordinator goroutine owns the frontier (queue) and the visited set; a
pool of stateless workers fetch and parse. Because only the coordinator touches
shared state, no mutex is needed and there are no data races — verified with
`go test -race`.

```
frontier ──► fetch ──► parse ──► normalize ──► scope + dedup ──┐
   ▲                                                           │
   └───────────────────── new in-scope links ──────────────────┘
```

## Installation

Requires Go 1.26+.

```bash
go install github.com/zeynepaksuu/zakspider@latest
```

Or build from source:

```bash
git clone https://github.com/zeynepaksuu/zakspider
cd zakspider
go build -o zakspider .
```

Prebuilt binaries for Windows, Linux and macOS (amd64/arm64) are attached to each
release.

## Usage

```bash
# Simple scan
zakspider https://target.com

# HTB workflow: subdomain scope, through Burp, authenticated, JSON output
zakspider --scope subdomain --proxy http://127.0.0.1:8080 --insecure \
  --cookie "PHPSESSID=abc123" --output json https://target.htb

# Brute-force hidden paths with extensions and recursion
zakspider --wordlist common.txt -x php,bak,txt --brute-recursive https://target.htb

# Save the JSON report to a file
zakspider --output json --output-file report.json https://target.htb

# Stream findings as JSONL and filter with jq
zakspider --output jsonl https://target.htb | jq -c 'select(.type=="secret" or .type=="flag")'
```

## Flags

| Flag | Description | Default |
|---|---|---|
| `--scope` | `strict` \| `subdomain` | `strict` |
| `--max-pages` | Maximum number of pages to crawl | `200` |
| `--depth` | Max BFS depth from seed (`0` = unlimited) | `0` |
| `--workers` | Number of concurrent workers | `10` |
| `--rate` | Maximum requests per second (`0` = unlimited) | `0` |
| `--rate-per-host` | Apply `--rate` per host instead of globally | `false` |
| `--retries` | Retries on error / 429 / 503 | `2` |
| `--output` | `text` \| `json` \| `jsonl` | `text` |
| `--output-file` | Write the report to this file (empty = stdout) | — |
| `--exit-code` | Exit non-zero (2) if any findings | `false` |
| `--flag-format` | Flag prefix to hunt for (`HTB` → `HTB{...}`; empty disables) | `HTB` |
| `--proxy` | HTTP proxy (Burp: `http://127.0.0.1:8080`) | — |
| `--insecure` | Skip TLS verification (Burp / self-signed) | `false` |
| `--cookie` | Cookie header (authenticated crawl) | — |
| `--user-agent` | Custom User-Agent | — |
| `-H` | Extra header `"Key: Value"` (repeatable) | — |
| `--include` / `--exclude` | Path-based scope filter | — |
| `--wordlist` | Brute-force wordlist file | — |
| `-x` | Brute-force extensions, comma-separated (`php,bak,txt`) | — |
| `--brute-recursive` | Recurse into directories found by brute-force | `false` |
| `--brute-depth` | Recursion depth for `--brute-recursive` | `1` |
| `--no-js-crawl` | Do not crawl in-scope endpoints extracted from JS | `false` |
| `--no-robots` | Skip robots.txt / sitemap.xml discovery | `false` |
| `--quiet` | Suppress live progress | `false` |
| `--no-color` | Disable colored output | `false` |

## Architecture

Four files, one `package main`:

| File | Responsibility |
|---|---|
| `main.go` | HTTP client, `fetch`, URL normalize/scope, worker pool, coordinator (`crawl`), CLI |
| `recon.go` | HTML comments/forms/JS endpoints/sensitive files, secret and flag extraction |
| `discover.go` | Active discovery: robots/sitemap parsing + brute-force + soft-404 |
| `output.go` | Reporting: JSON, JSONL streaming, colored console |

## Development

```bash
go test ./...          # tests
go test -race ./...    # race detector
go test -cover ./...   # coverage
go vet ./...           # static checks
```

## Ethics

Use this only against systems you are authorized to test: HTB labs, your own
DVWA/bWAPP instances, engagements with a written pentest scope. `--rate` and
`--exclude` are both a technical and an ethical requirement. Unauthorized
scanning — especially brute-force — is an attack.
