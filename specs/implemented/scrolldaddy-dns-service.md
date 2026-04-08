# ScrollDaddy DNS Service -- Go Application Specification

**Status:** Draft
**Language:** Go
**Author:** Claude (the project owner has no Go experience)
**Purpose:** Self-hosted DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) filtering proxy that reads configuration from the Joinery PostgreSQL database

---

## 1. Overview

ScrollDaddy DNS is a standalone Go binary that provides per-device DNS filtering. Each device gets a unique resolver URL. When a DNS query arrives, the service identifies the device, looks up its active filtering profile, and either blocks the query (returns NXDOMAIN) or forwards it to upstream DNS.

The service is **read-only** with respect to the database. The Joinery PHP application handles all management (creating devices, toggling filters, etc.) by writing to the database. This service reads from the same database and caches everything in memory, reloading periodically.

### How It Fits Into the Stack

```
User's device (iPhone, Android, etc.)
    |
    | DNS query via HTTPS or TLS
    v
Apache reverse proxy (host, TLS termination for DoH)
    |
    v
ScrollDaddy DNS Service (Go binary, inside Docker container)
    |
    | Reads device/profile/blocklist data (cached, reloads every 60s)
    v
PostgreSQL (same database as Joinery PHP app)
```

The PHP app writes to the DB. This service reads from the DB. They never communicate directly.

---

## 2. Project Structure

```
scrolldaddy-dns/
├── go.mod                    # Module definition and dependencies
├── go.sum                    # Dependency checksums (auto-generated)
├── cmd/
│   └── dns/
│       └── main.go           # Entry point: parse config, start servers, signal handling
├── internal/
│   ├── config/
│   │   └── config.go         # Configuration struct and loading (env vars)
│   ├── cache/
│   │   └── cache.go          # In-memory blocklist/profile/resolver cache and reload logic
│   ├── db/
│   │   └── db.go             # PostgreSQL connection and all queries for loading cache data
│   ├── doh/
│   │   └── handler.go        # HTTP handler for DoH endpoints (/resolve/{uid}, /health, /stats, /reload)
│   ├── dot/
│   │   └── server.go         # DNS-over-TLS server (port 853)
│   ├── resolver/
│   │   └── resolver.go       # Core DNS resolution logic (block/allow/forward/rewrite)
│   └── upstream/
│       └── upstream.go       # Forward queries to upstream DNS servers (1.1.1.1, 8.8.8.8)
└── README.md                 # Build and deployment instructions
```

**Location in the Joinery repo:** `public_html/scrolldaddy-dns/` (copied into the Docker container during build).

---

## 3. Dependencies

```
module scrolldaddy-dns

go 1.22

require (
    github.com/miekg/dns v1.1.58    // DNS wire format parsing, DoT server
    github.com/lib/pq v1.10.9       // PostgreSQL driver for database/sql
)
```

No web framework -- Go's `net/http` standard library handles the DoH HTTP endpoints. No ORM -- raw `database/sql` with the `lib/pq` driver.

---

## 4. Configuration

All configuration via environment variables. No config file.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SCD_DB_HOST` | No | `localhost` | PostgreSQL host |
| `SCD_DB_PORT` | No | `5432` | PostgreSQL port |
| `SCD_DB_NAME` | Yes | -- | Database name (e.g., `empoweredhealthtn`) |
| `SCD_DB_USER` | No | `postgres` | Database user |
| `SCD_DB_PASSWORD` | Yes | -- | Database password |
| `SCD_DOH_PORT` | No | `8053` | HTTP port for DoH endpoint |
| `SCD_DOT_PORT` | No | `853` | TLS port for DoT endpoint |
| `SCD_DOT_CERT_FILE` | No | -- | TLS certificate file path (required for DoT) |
| `SCD_DOT_KEY_FILE` | No | -- | TLS private key file path (required for DoT) |
| `SCD_DOT_BASE_DOMAIN` | No | -- | Base domain for DoT SNI extraction (e.g., `dns.scrolldaddy.app`). Required if DoT is enabled. |
| `SCD_UPSTREAM_PRIMARY` | No | `1.1.1.1:53` | Primary upstream DNS server |
| `SCD_UPSTREAM_SECONDARY` | No | `8.8.8.8:53` | Secondary upstream DNS (fallback) |
| `SCD_RELOAD_INTERVAL` | No | `60` | Seconds between lightweight cache reloads |
| `SCD_BLOCKLIST_RELOAD_INTERVAL` | No | `3600` | Seconds between full blocklist domain reloads |
| `SCD_LOG_LEVEL` | No | `info` | Logging level: `debug`, `info`, `warn`, `error` |
| `SCD_LOG_FILE` | No | `stdout` | Log file path, or `stdout` for standard output |

**Validation at startup:** If `SCD_DB_NAME` or `SCD_DB_PASSWORD` are not set, exit immediately with a clear error message.

**Version flag:** `scrolldaddy-dns --version` prints the version string and exits. The version is set at build time via Go linker flag:
```bash
go build -ldflags "-X main.version=1.0.0" -o scrolldaddy-dns ./cmd/dns
```

---

## 5. Entry Point (cmd/dns/main.go)

```
1. Parse configuration from environment variables
2. Validate required config (SCD_DB_NAME, SCD_DB_PASSWORD)
3. Connect to PostgreSQL, verify connection with a ping
   - If connection fails: retry every 5 seconds, log error each attempt
   - Do NOT start serving until DB is reachable
4. Create cache instance
5. Perform initial full cache load (both lightweight + blocklist data)
   - Blocks until complete
   - If this fails: exit with error (supervisord will restart)
6. Start background reload goroutines:
   a. Lightweight reload every SCD_RELOAD_INTERVAL seconds
   b. Full blocklist domain reload every SCD_BLOCKLIST_RELOAD_INTERVAL seconds
7. Start DoH HTTP server on SCD_DOH_PORT (always)
8. Start DoT TLS server on SCD_DOT_PORT (only if SCD_DOT_CERT_FILE and SCD_DOT_KEY_FILE are set)
   - If cert/key files don't exist: log warning, skip DoT, continue with DoH only
9. Listen for OS signals:
   - SIGHUP: Force immediate full reload (both lightweight + blocklist)
   - SIGTERM/SIGINT: Graceful shutdown
     a. Stop accepting new connections
     b. Wait up to 5 seconds for in-flight queries to complete
     c. Close database connection
     d. Exit 0
10. Block on signal channel until shutdown
```

---

## 6. Core DNS Resolution Logic (internal/resolver/resolver.go)

For every DNS query (received via DoH or DoT):

```
function resolve(resolver_uid string, dns_query *dns.Msg) → *dns.Msg:

    1. DEVICE LOOKUP
       Look up resolver_uid in cache → get DeviceInfo
       - If not found: return DNS REFUSED response
       - If device.IsActive == false: return DNS REFUSED response

    2. DETERMINE ACTIVE PROFILE
       - If device has no secondary profile (SecondaryProfileID == 0):
           active_profile_id = device.PrimaryProfileID
       - If device has secondary profile: evaluate schedule
         a. Get current time in device's schedule timezone (ScheduleTimezone)
         b. Get current day abbreviation lowercase: "mon", "tue", "wed", "thu", "fri", "sat", "sun"
         c. Check if current day is in device.ScheduleDays list
         d. If not a scheduled day: active_profile_id = device.PrimaryProfileID
         e. If scheduled day: check if current time is between ScheduleStart and ScheduleEnd
            - Handle overnight ranges (e.g., "22:00" to "06:00"):
              if end < start, then active if time >= start OR time < end
            - Normal range: active if time >= start AND time < end
         f. If within scheduled range: active_profile_id = device.SecondaryProfileID
         g. If outside range: active_profile_id = device.PrimaryProfileID
       - Look up active_profile_id in cache → get ProfileInfo
       - If profile not found: return DNS SERVFAIL (data inconsistency)

    3. EXTRACT QUERY DOMAIN
       Get queried domain name from DNS question section (dns_query.Question[0].Name)
       - Normalize: lowercase, strip trailing dot
       - If no question section: return DNS FORMERR
       - The query type (A, AAAA, HTTPS, MX, TXT, etc.) does not affect blocking.
         All query types for a blocked domain return NXDOMAIN.
         All query types for a non-blocked domain are forwarded to upstream.

    4. CHECK CUSTOM ALLOW RULES (bypass all blocking)
       Check domain against profile.CustomAllowed (map[string]bool):
       - Check exact match: "tracker.ads.example.com"
       - Parent domain walk: "ads.example.com" → "example.com"
       - Stop before TLD-only to avoid matching entire TLDs
       - If any match: skip to step 7 (forward to upstream)

    5. CHECK SAFESEARCH / SAFEYOUTUBE REWRITES
       - If profile.SafeSearch == true:
         Check domain against safeSearchRewrites map (see Section 8)
         If match: return CNAME response → safe domain (also resolve CNAME target via upstream)
       - If profile.SafeYouTube == true:
         Check domain against safeYouTubeRewrites map (see Section 8)
         If match: return CNAME response → restrict.youtube.com

    6. CHECK IF DOMAIN IS BLOCKED
       Check in this order (first match wins):

       a. Custom BLOCK rules (profile.CustomBlocked):
          - Exact match on domain
          - Parent domain walk (same as step 4)

       b. Filter category blocklists:
          - For each category_key in profile.EnabledCategories:
            - Look up category_key in cache.blocklistDomains → get domain set
            - Check exact match
            - Parent domain walk
          - If any match: return NXDOMAIN

    7. FORWARD TO UPSTREAM DNS
       Forward the original dns_query unmodified (preserving any EDNS0 options).
       a. Send to SCD_UPSTREAM_PRIMARY via UDP
          - Timeout: 5 seconds
       b. If timeout or network error: send to SCD_UPSTREAM_SECONDARY
          - Timeout: 5 seconds
       c. If both fail: return DNS SERVFAIL response
       d. Return upstream's response to caller unmodified
```

### Constructing DNS Responses

When the service constructs its own responses (NXDOMAIN, REFUSED, SERVFAIL, FORMERR), set these header flags:
- **ID**: Copy from the query (clients match responses by ID)
- **QR**: 1 (this is a response)
- **RD**: Copy from the query (Recursion Desired)
- **RA**: 1 (Recursion Available — we provide recursion via upstream)
- **RCODE**: Set appropriately — NXDOMAIN=3, REFUSED=5, SERVFAIL=2, FORMERR=1
- **Question section**: Copy from the query

Using `miekg/dns`, the simplest pattern:
```go
resp := new(dns.Msg)
resp.SetRcode(query, dns.RcodeNameError) // sets ID, QR, RD, copies Question, sets RCODE
resp.RecursionAvailable = true
```

### Parent Domain Walk Algorithm

```
function isDomainInSet(domain string, domainSet map[string]bool) → bool:
    // Check exact match first
    if domainSet[domain]: return true

    // Walk up parent domains
    parts = split domain by "."
    // e.g., "tracker.ads.example.com" → ["tracker", "ads", "example", "com"]

    // Start from index 1 (skip first label) up to len-1 (skip TLD-only)
    for i = 1; i < len(parts) - 1; i++:
        parent = join(parts[i:], ".")
        // i=1: "ads.example.com"
        // i=2: "example.com"
        // Stop: don't check "com"
        if domainSet[parent]: return true

    return false
```

---

## 7. DoH Protocol Implementation (internal/doh/handler.go)

Implements DNS-over-HTTPS per RFC 8484.

### HTTP Routes

Register these handlers on the HTTP server:

```
GET  /resolve/{uid}    → DoH GET handler
POST /resolve/{uid}    → DoH POST handler
GET  /health           → Health check handler
GET  /stats            → Statistics handler (localhost only)
POST /reload           → Force reload handler (localhost only)
GET  /test             → Diagnostic handler (localhost only)
```

### DoH GET Handler

```
1. Extract resolver_uid from URL path (everything after "/resolve/")
2. Get "dns" query parameter from URL
3. Base64url-decode the "dns" parameter (RFC 4648 §5, NO padding)
4. Parse decoded bytes as DNS wire format using dns.Unpack()
5. If parse fails: return HTTP 400 Bad Request
6. Call resolver.resolve(resolver_uid, dns_query)
7. Pack response to wire format using dns.Pack()
8. Return HTTP 200 with:
   - Content-Type: application/dns-message
   - Cache-Control: no-cache, no-store
   - Body: wire format response bytes
```

### DoH POST Handler

```
1. Extract resolver_uid from URL path
2. Check Content-Type header == "application/dns-message"
   - If wrong: return HTTP 415 Unsupported Media Type
3. Read request body (limit to 65535 bytes — max DNS message size)
4. Parse body as DNS wire format using dns.Unpack()
5. If parse fails: return HTTP 400 Bad Request
6. Call resolver.resolve(resolver_uid, dns_query)
7. Pack and return same as GET handler
```

### Resolver UID Format and Validation

Resolver UIDs are **32-character lowercase hex strings** (128 bits of randomness), generated in PHP via `bin2hex(random_bytes(16))`. Example: `a1b2c3d4e5f67890abcdef1234567890`.

Validate the UID before doing a cache lookup — reject obviously invalid UIDs without hitting the map:

```go
uid := strings.TrimPrefix(r.URL.Path, "/resolve/")
if len(uid) != 32 || !isHex(uid) {
    http.Error(w, "Not found", 404)
    return
}

func isHex(s string) bool {
    for _, c := range s {
        if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
            return false
        }
    }
    return true
}
```

### Health Check Handler (`/health`)

```json
{
  "status": "ok",
  "db_connected": true,
  "uptime_seconds": 86400,
  "last_reload": "2026-03-14T10:30:00Z"
}
```

Check DB connectivity by calling `db.Ping()`. If unreachable:
- Return HTTP 503
- `"status": "degraded"`
- `"db_connected": false`

### Stats Handler (`/stats`)

```json
{
  "devices": 150,
  "profiles": 280,
  "blocklist_categories": 26,
  "blocklist_domains_total": 523000,
  "last_light_reload": "2026-03-14T10:30:00Z",
  "last_full_reload": "2026-03-14T06:00:00Z",
  "uptime_seconds": 86400
}
```

### Reload Handler (`POST /reload`)

Triggers an immediate full cache reload (both lightweight and blocklist). Returns:
```json
{"status": "reload_triggered"}
```

The reload happens asynchronously. The handler returns immediately.

### Diagnostic Handler (`GET /test`)

Localhost-only. Tests what would happen if a device queried a domain, without sending an actual DNS query. Useful for debugging "why is this site blocked?"

```
GET /test?uid=a1b2c3d4...&domain=doubleclick.net
```

Returns:
```json
{
  "uid": "a1b2c3d4...",
  "domain": "doubleclick.net",
  "result": "BLOCKED",
  "reason": "category_blocklist",
  "category": "ads",
  "active_profile_id": 43,
  "profile_type": "secondary",
  "schedule_active": true
}
```

For an allowed domain:
```json
{
  "uid": "a1b2c3d4...",
  "domain": "google.com",
  "result": "FORWARDED",
  "reason": "not_blocked",
  "active_profile_id": 42,
  "profile_type": "primary",
  "schedule_active": false
}
```

For a custom allow rule bypass:
```json
{
  "uid": "a1b2c3d4...",
  "domain": "allowed-ads.example.com",
  "result": "FORWARDED",
  "reason": "custom_allow_rule",
  "matched_rule": "example.com",
  "active_profile_id": 43,
  "profile_type": "secondary",
  "schedule_active": true
}
```

Possible `reason` values: `not_blocked`, `custom_block_rule`, `custom_allow_rule`, `category_blocklist`, `safesearch_rewrite`, `safeyoutube_rewrite`.

**Implementation note:** The resolver's `resolve()` function needs to return a `ResolveResult` struct with the reason/category/matched_rule alongside the DNS response. The DoH and DoT handlers use only the DNS response; the `/test` handler uses the full struct.

### Access Control

`/stats`, `/reload`, and `/test` are restricted to localhost connections only. If the request's remote IP is not `127.0.0.1` or `::1`, return HTTP 403 Forbidden. This provides defense in depth in case the Apache proxy config changes.

`/health` is open to all — it reveals nothing sensitive and is useful for external monitoring. `/resolve/{uid}` is the public endpoint.

---

## 8. DoT Protocol Implementation (internal/dot/server.go)

DNS-over-TLS for Android Private DNS support. Device identification via subdomain in TLS SNI.

### How Android Private DNS Works

1. User enters `a1b2c3d4.dns.scrolldaddy.app` in Android Private DNS settings
2. Android connects to that hostname on port 853 via TLS
3. The TLS ClientHello contains the SNI (Server Name Indication): `a1b2c3d4.dns.scrolldaddy.app`
4. Our server extracts the resolver UID from the SNI

### Server Setup

```
1. Load TLS certificate and key from SCD_DOT_CERT_FILE and SCD_DOT_KEY_FILE
   - Must be a wildcard cert for *.dns.scrolldaddy.app
2. Create TLS config with the cert
3. Listen on SCD_DOT_PORT (default 853) with TLS
4. For each accepted connection:
   a. Extract SNI from TLS handshake (tls.Conn.ConnectionState().ServerName)
   b. Extract resolver UID: strip "." + SCD_DOT_BASE_DOMAIN suffix from SNI
      Example: "a1b2c3d4.dns.scrolldaddy.app" → "a1b2c3d4"
   c. If extraction fails (SNI doesn't end with base domain): close connection
   d. Handle DNS queries on this connection in a loop:
      - Read 2-byte length prefix (big-endian uint16)
      - Read that many bytes (the DNS message)
      - Parse as DNS wire format
      - Call resolver.resolve(resolver_uid, dns_query)
      - Pack response
      - Write 2-byte length prefix + response bytes
      - Continue reading next query (TCP connections can be reused)
   e. On read error or connection close: clean up
```

### DNS-over-TLS Wire Format

DoT uses TCP with a 2-byte length prefix before each DNS message:

```
[2 bytes: message length (big-endian)] [N bytes: DNS wire format message]
```

This is the standard DNS TCP format. The `miekg/dns` library handles this if you use `dns.Server` with `Net: "tcp-tls"`.

### SNI Extraction via GetConfigForClient

Use Go's `tls.Config.GetConfigForClient` callback to capture the SNI (Server Name Indication) during the TLS handshake. The SNI is the hostname the client connected to (e.g., `a1b2c3d4.dns.scrolldaddy.app`). We strip the base domain to get the resolver UID.

```go
// Store SNI per-connection using a sync.Map keyed by remote address
var sniMap sync.Map

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
        // hello.ServerName contains the SNI, e.g. "a1b2c3d4.dns.scrolldaddy.app"
        // Store it keyed by connection remote address for later retrieval
        sniMap.Store(hello.Conn.RemoteAddr().String(), hello.ServerName)
        return nil, nil // return nil to use the default TLS config
    },
}
```

Then in the DNS handler, look up the SNI by the connection's remote address and extract the resolver UID:

```go
func handleDoTQuery(w dns.ResponseWriter, r *dns.Msg) {
    remoteAddr := w.RemoteAddr().String()
    sniValue, ok := sniMap.Load(remoteAddr)
    if !ok {
        // No SNI captured — refuse
        // ...
        return
    }
    sni := sniValue.(string)
    uid := strings.TrimSuffix(sni, "."+baseDomain)
    // Resolve using uid...
}
```

Clean up the `sniMap` entry when the connection closes.

---

## 9. SafeSearch & SafeYouTube Rewrites

Implemented as CNAME DNS responses per-profile.

### Rewrite Maps

```go
var safeSearchRewrites = map[string]string{
    "www.google.com":      "forcesafesearch.google.com",
    "www.google.co.uk":    "forcesafesearch.google.com",
    "www.google.ca":       "forcesafesearch.google.com",
    "www.google.com.au":   "forcesafesearch.google.com",
    "www.google.de":       "forcesafesearch.google.com",
    "www.google.fr":       "forcesafesearch.google.com",
    "www.google.es":       "forcesafesearch.google.com",
    "www.google.it":       "forcesafesearch.google.com",
    "www.google.nl":       "forcesafesearch.google.com",
    "www.google.co.in":    "forcesafesearch.google.com",
    "www.google.co.jp":    "forcesafesearch.google.com",
    "www.google.com.br":   "forcesafesearch.google.com",
    "www.bing.com":        "strict.bing.com",
    "duckduckgo.com":      "safe.duckduckgo.com",
    "www.duckduckgo.com":  "safe.duckduckgo.com",
}

var safeYouTubeRewrites = map[string]string{
    "www.youtube.com":           "restrict.youtube.com",
    "youtube.com":               "restrict.youtube.com",
    "m.youtube.com":             "restrict.youtube.com",
    "youtubei.googleapis.com":   "restrict.youtube.com",
}
```

### CNAME Response Construction

When a rewrite matches:

```
1. Create a DNS response message
2. Add a CNAME record to the Answer section:
   - Name: original query domain (e.g., "www.google.com")
   - Type: CNAME
   - Value: safe domain (e.g., "forcesafesearch.google.com")
   - TTL: 300 seconds
3. Resolve the CNAME target via upstream DNS to get its A/AAAA records
4. Add those A/AAAA records to the Answer section (after the CNAME)
5. Return the complete response
```

This ensures the client gets both the CNAME and the resolved IP in a single response.

---

## 10. Category Filter Blocklist Sources

Category filters (ads, malware, porn, gambling, etc.) are populated from open-source community-maintained blocklists. These lists are downloaded, parsed, and loaded into the `bld_blocklist_domains` table by a PHP maintenance script. The Go DNS service reads from this table.

### Blocklist Format

All lists use **plain domain format** — one domain per line. Lines starting with `#` are comments. The PHP loader strips whitespace, skips comments and blank lines, lowercases all domains, and inserts into the database keyed by `category_key`.

### Category-to-Source Mapping

Each filter category (matching the keys in `ControlDHelper::$filters`) maps to one or more open-source blocklist URLs:

| Category Key | Display Name | Source(s) |
|---|---|---|
| `ads_small` | Ads & Trackers (Relaxed) | hagezi light |
| `ads_medium` | Ads & Trackers (Balanced) | hagezi normal |
| `ads` | Ads & Trackers (Strict) | hagezi pro.plus |
| `porn` | Adult content | OISD NSFW |
| `porn_strict` | Adult content (Strict) | OISD NSFW + Bon-Appetit porn-domains |
| `noai` | Artificial intelligence | hagezi native.ai |
| `fakenews` | Hoaxes and disinformation | blocklistproject fraud |
| `cryptominers` | Cryptocurrency | blocklistproject crypto |
| `dating` | Dating sites | ShadowWhisperer Dating |
| `drugs` | Illegal drugs | blocklistproject drugs |
| `ddns` | Dynamic DNS hosts | hagezi dyndns |
| `filehost` | File hosting | ShadowWhisperer Free (free hosting) |
| `gambling` | Gambling sites | hagezi gambling + ShadowWhisperer Gambling |
| `games` | Games | (no reliable open-source list — defer to custom rules) |
| `gov` | Government sites | (no reliable open-source list — defer to custom rules) |
| `iot` | Internet of things | hagezi native.* vendor trackers |
| `malware` | Known malware sites (Relaxed) | hagezi tif (Threat Intelligence Feeds) |
| `ip_malware` | Known malware sites (Balanced) | hagezi tif + blocklistproject malware |
| `ai_malware` | Known malware sites (Strict) | hagezi tif + blocklistproject malware + ransomware |
| `nrd_small` | New domains (Last week) | hagezi nrd7 |
| `nrd` | New domains (Last month) | hagezi nrd7 + nrd14-8 + nrd21-15 + nrd28-22 |
| `typo` | Phishing domains | blocklistproject phishing + hagezi fake |
| `social` | Social media | ShadowWhisperer Social (when available) + blocklistproject facebook |
| `torrents` | Torrent sites | blocklistproject torrent |
| `urlshort` | URL shorteners | hagezi urlshortener |
| `dnsvpn` | VPN and DNS providers | hagezi doh-vpn-proxy-bypass |

### Source URLs

**Hagezi** (cdn.jsdelivr.net — CDN-cached, updated daily):
```
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/light.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/multi.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.plus.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/tif.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/nrd7.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/nrd14-8.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/nrd21-15.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/nrd28-22.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/doh.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/dyndns.txt
https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.ai.txt
```

**OISD** (oisd.nl — updated continuously):
```
https://nsfw.oisd.nl/domainswild2
```

**Block List Project** (blocklistproject.github.io — domain-only format):
```
https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt
https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt
https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt
https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt
https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt
https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt
https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt
https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt
https://blocklistproject.github.io/Lists/alt-version/facebook-nl.txt
```

**ShadowWhisperer** (raw.githubusercontent.com — plain domain format):
```
https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Dating
https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Gambling
https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Free
```

**Bon-Appetit** (raw.githubusercontent.com — for strict adult content):
```
https://raw.githubusercontent.com/Bon-Appetit/porn-domains/master/domains.txt
```

### PHP Blocklist Loader

A PHP maintenance script (`utils/load_blocklists.php`) handles downloading and loading:

```
1. For each category_key in the mapping:
   a. Download each source URL (curl, 30-second timeout)
   b. Parse: skip comments (#), blank lines; lowercase; trim whitespace
   c. Merge domains from all sources for that category (deduplicate)
   d. Begin transaction
   e. DELETE FROM bld_blocklist_domains WHERE bld_category_key = $category_key
   f. Batch INSERT new domains (1000 rows per INSERT for performance)
   g. Commit transaction
   h. Log: "Loaded X domains for category_key"
2. Log total: "Blocklist load complete: X total domains across Y categories"
```

This script runs via cron (e.g., daily at 3 AM) or manually via the admin utilities page. The Go service picks up changes on its next full reload cycle (hourly by default, or triggered via `POST /reload`).

### Notes

- Categories `games` and `gov` have no reliable open-source blocklists. They remain available as filter options but will be empty until manually populated or a suitable source is found.
- The mapping table above is the initial configuration. Sources can be added, replaced, or combined as better lists become available — the PHP loader is configured by a data structure, not hardcoded per-category.
- When a category maps to multiple sources, domains are merged and deduplicated before insertion.

---

## 11. In-Memory Cache (internal/cache/cache.go)

### Data Structures

```go
type Cache struct {
    mu sync.RWMutex  // Protects all fields during reload

    // Device lookup: resolver_uid → DeviceInfo
    devices map[string]*DeviceInfo

    // Profile data: profile_id → ProfileInfo
    profiles map[int64]*ProfileInfo

    // Blocklist domains: category_key → set of domains
    // Shared across all profiles (memory efficient)
    blocklistDomains map[string]map[string]bool

    // Metadata
    lastLightReload     time.Time
    lastFullReload      time.Time
    totalDevices        int
    totalBlockedDomains int
}

type DeviceInfo struct {
    DeviceID            int64
    ResolverUID         string
    PrimaryProfileID    int64
    SecondaryProfileID  int64  // 0 if no secondary
    IsActive            bool
    Timezone            *time.Location

    // Schedule fields (from secondary profile's schedule)
    ScheduleStart       string         // "HH:MM" format, e.g. "22:00"
    ScheduleEnd         string         // "HH:MM" format, e.g. "06:00"
    ScheduleDays        []string       // e.g. ["mon", "tue", "wed"]
    ScheduleTimezone    *time.Location // timezone for schedule evaluation
}

type ProfileInfo struct {
    ProfileID       int64
    SafeSearch      bool
    SafeYouTube     bool

    // Enabled filter category keys for this profile
    EnabledCategories []string  // e.g. ["ads", "malware", "porn"]

    // Custom rules for this profile
    CustomBlocked map[string]bool  // domains with rule_action=0
    CustomAllowed map[string]bool  // domains with rule_action=1
}
```

### Memory Efficiency

Category domain sets (`blocklistDomains`) are shared across all profiles. If 100 profiles enable "ads", the domain set exists once in memory. Only per-profile metadata (which categories are enabled, custom rules) is duplicated.

**Memory estimation:** 500,000 domains ≈ 50MB as a Go `map[string]bool`. Typical deployment with all categories loaded: ~100-200MB total.

### Concurrency Model

- DNS query handlers acquire a **read lock** (`mu.RLock()`) to access cache data
- Reload goroutines build new data structures without holding any lock, then acquire a **write lock** (`mu.Lock()`) only for the brief moment of swapping pointers
- This means DNS queries are never blocked during the database query phase of a reload — only during the microsecond-level pointer swap

### Public Methods

```go
// GetDevice returns the DeviceInfo for a resolver UID, or nil if not found.
func (c *Cache) GetDevice(resolverUID string) *DeviceInfo

// GetProfile returns the ProfileInfo for a profile ID, or nil if not found.
func (c *Cache) GetProfile(profileID int64) *ProfileInfo

// IsDomainBlockedByCategory checks if a domain (or parent) is in the given category's blocklist.
func (c *Cache) IsDomainBlockedByCategory(domain string, categoryKey string) bool

// LightReload reloads devices, profiles, filters, and rules from DB.
func (c *Cache) LightReload(db *DB) error

// FullReload reloads blocklist domains from DB.
func (c *Cache) FullReload(db *DB) error

// Stats returns current cache statistics.
func (c *Cache) Stats() CacheStats
```

---

## 12. Database Queries (internal/db/db.go)

All queries are **read-only SELECT statements**. The Go service never writes to the database.

### Connection

```go
connStr := fmt.Sprintf(
    "host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
    config.DBHost, config.DBPort, config.DBName, config.DBUser, config.DBPassword,
)
db, err := sql.Open("postgres", connStr)
```

Set connection pool limits:
```go
db.SetMaxOpenConns(5)       // Don't need many — queries are infrequent
db.SetMaxIdleConns(2)
db.SetConnMaxLifetime(5 * time.Minute)
```

### Schema Validation on Startup

Before loading any data, verify that all expected tables and columns exist. This catches PHP-side schema changes immediately instead of failing with cryptic database errors.

All table and column names are defined as constants at the top of `db.go` — this is the single place to update if the PHP schema changes.

```go
var expectedSchema = map[string][]string{
    "cdd_ctlddevices": {
        "cdd_ctlddevice_id", "cdd_device_id", "cdd_cdp_ctldprofile_id_primary",
        "cdd_cdp_ctldprofile_id_secondary", "cdd_is_active", "cdd_timezone",
        "cdd_delete_time",
    },
    "cdp_ctldprofiles": {
        "cdp_ctldprofile_id", "cdp_schedule_start", "cdp_schedule_end",
        "cdp_schedule_days", "cdp_schedule_timezone", "cdp_safesearch", "cdp_safeyoutube",
    },
    "cdf_ctldfilters": {
        "cdf_cdp_ctldprofile_id", "cdf_filter_pk", "cdf_is_active",
    },
    "cdr_ctldrules": {
        "cdr_cdp_ctldprofile_id", "cdr_rule_hostname", "cdr_rule_action", "cdr_is_active",
    },
    "bld_blocklist_domains": {
        "bld_category_key", "bld_domain",
    },
}
```

Validation query (run once per table at startup):
```sql
SELECT column_name FROM information_schema.columns
WHERE table_name = $1;
```

Compare returned columns against expected list. If any are missing:
```
FATAL: Schema validation failed:
  - Table cdd_ctlddevices: missing column "cdd_device_id" (was it renamed?)
  - Table cdp_ctldprofiles: missing column "cdp_safesearch" (was it added yet?)
```

Refuse to start if validation fails. This makes the interface between PHP and Go explicit and self-checking.

### Lightweight Reload Queries (every 60 seconds)

**Query 1: Load all active devices with profile and schedule data**

```sql
SELECT
    d.cdd_ctlddevice_id,
    d.cdd_device_id AS resolver_uid,
    d.cdd_cdp_ctldprofile_id_primary,
    d.cdd_cdp_ctldprofile_id_secondary,
    d.cdd_is_active,
    d.cdd_timezone,
    p2.cdp_schedule_start,
    p2.cdp_schedule_end,
    p2.cdp_schedule_days,
    p2.cdp_schedule_timezone,
    p1.cdp_safesearch AS primary_safesearch,
    p1.cdp_safeyoutube AS primary_safeyoutube,
    p2.cdp_safesearch AS secondary_safesearch,
    p2.cdp_safeyoutube AS secondary_safeyoutube
FROM cdd_ctlddevices d
JOIN cdp_ctldprofiles p1 ON d.cdd_cdp_ctldprofile_id_primary = p1.cdp_ctldprofile_id
LEFT JOIN cdp_ctldprofiles p2 ON d.cdd_cdp_ctldprofile_id_secondary = p2.cdp_ctldprofile_id
WHERE d.cdd_delete_time IS NULL
  AND d.cdd_is_active = TRUE;
```

**Notes on parsing results:**
- `cdd_timezone` is a timezone string like "America/New_York" — parse with `time.LoadLocation()`
- `cdp_schedule_days` is a JSON array like `["mon","tue","wed"]` — parse with `json.Unmarshal`. (The PHP side uses `json_encode`/`json_decode` for this field, not PHP's `serialize`.)
- `cdp_schedule_start` and `cdp_schedule_end` are "HH:MM" strings like "22:00"
- `cdp_safesearch` and `cdp_safeyoutube` are booleans (may be NULL for profiles that predate these fields — treat NULL as false)

**Query 2: Load all active filter assignments**

```sql
SELECT cdf_cdp_ctldprofile_id AS profile_id,
       cdf_filter_pk AS category_key
FROM cdf_ctldfilters
WHERE cdf_is_active = 1;
```

**Query 3: Load all active custom rules**

```sql
SELECT cdr_cdp_ctldprofile_id AS profile_id,
       cdr_rule_hostname AS hostname,
       cdr_rule_action AS action
FROM cdr_ctldrules
WHERE cdr_is_active = 1;
```

`cdr_rule_action`: 0 = block, 1 = allow.

### Full Blocklist Reload Queries (every 1 hour, or on SIGHUP/POST /reload)

**Query 4: Load all blocklist domains**

```sql
SELECT bld_category_key, bld_domain
FROM bld_blocklist_domains;
```

This may return hundreds of thousands of rows. Process with `rows.Next()` in a loop, building the `map[string]map[string]bool` incrementally. Do NOT load all rows into memory as a slice first.

### Reload Process

**Lightweight reload:**
1. Begin a read-only transaction for consistency across queries 1-3
2. Run queries 1-3
3. Build new `devices` and `profiles` maps from results
4. Acquire cache write lock
5. Replace `cache.devices` and `cache.profiles` (keep existing `blocklistDomains`)
6. Update metadata (lastLightReload, totalDevices)
7. Release write lock
8. Log: `"Lightweight reload complete: X devices, Y profiles"`

**Full reload:**
1. Run query 4 (no transaction needed — this is an append-only table)
2. Build new `blocklistDomains` map
3. Acquire cache write lock
4. Replace `cache.blocklistDomains`
5. Update metadata (lastFullReload, totalBlockedDomains)
6. Release write lock
7. Log: `"Full reload complete: X blocklist domains across Y categories"`

### Schedule Days Parsing

The `cdp_schedule_days` field is stored as JSON: `["mon","tue","wed"]`. Parse in Go with the standard library:

```go
var days []string
if err := json.Unmarshal([]byte(rawValue), &days); err != nil {
    // Log warning, treat as empty (no schedule)
    days = nil
}
```

---

## 13. Upstream DNS Forwarding (internal/upstream/upstream.go)

### Forwarding Logic

```go
func Forward(query *dns.Msg, primary string, secondary string) (*dns.Msg, error) {
    // Try primary upstream
    client := &dns.Client{
        Net:     "udp",
        Timeout: 5 * time.Second,
    }

    resp, _, err := client.Exchange(query, primary)
    if err == nil && resp != nil {
        return resp, nil
    }

    // Log warning about primary failure
    log.Printf("WARN Upstream timeout: %s, trying %s", primary, secondary)

    // Try secondary upstream
    resp, _, err = client.Exchange(query, secondary)
    if err == nil && resp != nil {
        return resp, nil
    }

    // Both failed
    return nil, fmt.Errorf("both upstreams failed: %s, %s", primary, secondary)
}
```

When both upstreams fail, the resolver returns a DNS SERVFAIL response.

---

## 14. Logging

All logging goes to stdout (captured by supervisord) or a configurable file path.

### Format

Structured text, one line per entry:

```
2026-03-14T10:30:00Z INFO  Starting ScrollDaddy DNS service on :8053
2026-03-14T10:30:01Z INFO  Connected to PostgreSQL: empoweredhealthtn@localhost:5432
2026-03-14T10:30:02Z INFO  Initial cache load complete: 150 devices, 523000 blocked domains
2026-03-14T10:30:02Z INFO  DoH server listening on :8053
2026-03-14T10:30:02Z INFO  DoT server listening on :853
2026-03-14T10:31:02Z INFO  Lightweight reload: 150 devices, 280 profiles
2026-03-14T10:31:02Z DEBUG uid=a1b2c3d4 q=ads.example.com BLOCKED cat=ads
2026-03-14T10:31:02Z DEBUG uid=a1b2c3d4 q=google.com FORWARDED via=1.1.1.1
2026-03-14T10:31:05Z WARN  Upstream timeout: 1.1.1.1, falling back to 8.8.8.8
2026-03-14T10:32:00Z ERROR DB connection lost, serving from cached data
2026-03-14T10:33:00Z INFO  DB reconnected, resuming normal reloads
```

### Log Levels

| Level | What gets logged | When to use |
|-------|-----------------|-------------|
| `debug` | Individual DNS query results (very verbose) | Troubleshooting specific devices |
| `info` | Startup, shutdown, reload events, configuration | Normal production |
| `warn` | Upstream timeouts, skipped DoT (missing certs), non-fatal issues | Production (default) |
| `error` | DB connection failures, TLS errors, unrecoverable issues | Always logged |

Use Go's standard `log` package. Prefix each line with timestamp and level.

---

## 15. Error Handling and Resilience

| Failure | Behavior |
|---------|----------|
| DB unreachable at startup | Retry every 5 seconds, log error. Do not start serving until initial cache loads. |
| DB unreachable during reload | Log error, keep serving from last successful cache. Retry on next interval. |
| Unknown resolver UID | Return DNS REFUSED |
| Inactive device (is_active=false) | Return DNS REFUSED |
| Malformed DNS query (DoH) | Return HTTP 400 |
| Malformed DNS query (DoT) | Close TLS connection |
| Invalid Content-Type (DoH POST) | Return HTTP 415 |
| Upstream DNS timeout (primary) | Try secondary upstream |
| Both upstreams timeout | Return DNS SERVFAIL |
| SIGHUP received | Trigger immediate full reload |
| SIGTERM/SIGINT received | Graceful shutdown: stop accepting, drain 5s, exit 0 |
| Out of memory | Go crashes, supervisord restarts, cache reloads from DB |
| TLS cert/key missing (DoT) | Log warning, skip DoT startup, DoH continues |
| Invalid timezone string from DB | Log warning, default to UTC for that device |
| Unparseable schedule_days from DB | Log warning, treat as no schedule (primary profile only) |

**IPv6:** The service listens on both IPv4 and IPv6 (Go's default behavior when binding to `:port`). AAAA queries are treated like any other query type — blocked if the domain is blocked, forwarded to upstream otherwise. The default upstream servers (1.1.1.1, 8.8.8.8) handle AAAA queries natively.

**Rate limiting:** Not in v1 (see Section 19).

**DNS response caching:** Not in v1 (see Section 19).

---

## 16. Build and Compilation

Prerequisites: Go 1.22+ installed.

A `Makefile` in the project root provides all build commands:

```makefile
VERSION ?= dev

build:
	go build -ldflags "-X main.version=$(VERSION)" -o scrolldaddy-dns ./cmd/dns

test:
	go test ./...

clean:
	rm -f scrolldaddy-dns
```

Usage:
```bash
cd scrolldaddy-dns

make build                    # Compile binary (version = "dev")
make build VERSION=1.0.0      # Compile with specific version
make test                     # Run all unit tests
make clean                    # Remove compiled binary

# The output is a single binary: ./scrolldaddy-dns
# No runtime dependencies (no .so files, no Go installation needed to run)
# Copy to /usr/local/bin/ for deployment:
cp scrolldaddy-dns /usr/local/bin/
chmod 755 /usr/local/bin/scrolldaddy-dns
```

### Running Locally for Development

```bash
export SCD_DB_NAME=joinerytest
export SCD_DB_PASSWORD=yourpassword
export SCD_LOG_LEVEL=debug

./scrolldaddy-dns
```

This starts the DoH server on port 8053. Test with curl:

```bash
# Health check
curl http://localhost:8053/health

# Stats
curl http://localhost:8053/stats

# Force reload
curl -X POST http://localhost:8053/reload

# DNS query (requires a valid DNS wire format message — use dig or a test script)
```

---

## 17. Supervisord Configuration

Inside the Docker container, supervisord manages the Go service alongside Apache and cron.

**`/etc/supervisor/conf.d/scrolldaddy.conf`:**

```ini
[program:scrolldaddy-dns]
command=/usr/local/bin/scrolldaddy-dns
autostart=true
autorestart=true
startsecs=5
startretries=3
stderr_logfile=/var/log/scrolldaddy-dns.err.log
stdout_logfile=/var/log/scrolldaddy-dns.out.log
stdout_logfile_maxbytes=10MB
stderr_logfile_maxbytes=10MB
```

Environment variables are injected at container startup (see migration spec Section 7.4).

---

## 18. Testing

Go unit tests that test all logic in isolation, without a database connection. Tests create in-memory cache structures directly and verify behavior. Run with `go test ./...`.

### What to Test

**Resolver logic (`internal/resolver/`):**
- Blocked domain returns NXDOMAIN
- Non-blocked domain is forwarded (mock upstream)
- Custom allow rule bypasses block (exact match and parent domain)
- Custom block rule blocks domain (exact match and parent domain)
- Category blocklist blocks domain
- Allow rule takes priority over block rule for same domain
- Unknown resolver UID returns REFUSED
- Inactive device returns REFUSED

**Parent domain walk (`internal/cache/` or `internal/resolver/`):**
- Exact match: `ads.example.com` matches `ads.example.com`
- Parent match: `tracker.ads.example.com` matches `ads.example.com`
- TLD not matched: `com` in blocklist does NOT block `example.com`
- No false positives: `example.com` in blocklist does NOT block `otherexample.com`

**Schedule evaluation:**
- No secondary profile → primary
- Within schedule window → secondary
- Outside schedule window → primary
- Overnight range (e.g., 22:00–06:00) works correctly
- Non-scheduled day → primary
- Missing schedule fields → primary (graceful fallback)

**Schedule days JSON parsing:**
- Standard format: `["mon","tue","wed"]` → `["mon", "tue", "wed"]`
- Empty array: `[]` → `[]`
- NULL or empty string → `[]`
- Malformed JSON → `[]` (log warning)

**SafeSearch/SafeYouTube rewrites:**
- Matching domain returns CNAME response
- Non-matching domain is not rewritten
- SafeSearch disabled → no rewrite even for matching domain

**DNS response construction:**
- Response ID matches query ID
- QR=1, RA=1, RD copied from query
- NXDOMAIN, REFUSED, SERVFAIL set correct RCODE
- Question section copied from query
- All query types (A, AAAA, MX, etc.) return NXDOMAIN for blocked domains

### DB Integration

Not tested in automated tests. Verify manually by running the service against the test database and checking `/health` and `/stats` responses for correct counts.

---

## 19. Future Improvements (Not in v1)

These are deferred to keep v1 simple. Add when scale or need justifies the complexity.

- **DNS response caching** -- Cache upstream responses in memory for the duration of their TTL. Reduces latency and upstream load when many devices query the same domains. Not needed at small scale since Cloudflare/Google respond in ~5-20ms.
- **Rate limiting** -- Per-IP or per-UID query rate limits to prevent abuse. Not needed in v1 since resolver UIDs are 32-char hex strings (unguessable). Can also be handled at the Apache/firewall layer.
