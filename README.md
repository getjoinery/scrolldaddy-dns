# scrolldaddy-dns

DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) server for the ScrollDaddy content filtering platform. Written in Go. Reads device and filter configuration from a shared PostgreSQL database and enforces per-device blocking rules on every DNS query.

---

## How It Works

Each user device is assigned a unique 32-character hex **resolver UID**. The device sends all DNS queries through one of:

- **DoH:** `https://dns.scrolldaddy.app/resolve/{uid}` (standard RFC 8484, GET or POST)
- **DoT:** `{uid}.dns.scrolldaddy.app:853` (SNI-based routing)

On each query the server:
1. Looks up the device in its in-memory cache by UID
2. Determines the active profile (primary, or secondary if a schedule is active)
3. Checks the query domain against custom allow rules → custom block rules → category blocklists → service blocks
4. Returns NXDOMAIN if blocked, or forwards to an upstream resolver (Cloudflare/Google) if not
5. Cache hit: returns a cached DNS response with decremented TTLs (bypasses upstream entirely)

Configuration is stored in the Joinery PostgreSQL database and loaded into memory on startup, then refreshed every 60 seconds (device/filter changes) and every 3600 seconds (blocklist domains). No restart is required for config changes.

Feature toggles (DNS response cache, query logging) are controlled by a JSON config file at `/etc/scrolldaddy/dns.json` and hot-reloaded on SIGHUP or POST /reload.

---

## Package Structure

```
cmd/dns/main.go              Entry point. Wires all components together.
internal/
  config/config.go           Environment variable loading, JSON feature config, and validation.
  db/db.go                   PostgreSQL connection, schema validation, data loading.
  cache/
    cache.go                 In-memory store: devices, profiles, blocklists, last-seen.
    services.go              Hardcoded service→domain mappings (LinkedIn, Facebook, etc.)
  dnscache/dnscache.go       TTL-aware DNS response cache (bypasses upstream on cache hit).
  querylog/querylog.go       Per-device flat file query logger (async, non-blocking).
  resolver/resolver.go       Core DNS resolution logic and filtering decisions.
  doh/handler.go             HTTP handlers: DoH GET/POST, /health, /device/{uid}/seen, /stats, /reload, /test, /device/{uid}/log, /device/{uid}/log/purge.
  dot/server.go              DoT server: SNI-based UID extraction, TLS termination.
  upstream/upstream.go       UDP/TCP forwarding to upstream DNS resolvers.
  logger/logger.go           Leveled logger (debug/info/warn/error).
```

---

## Building

```bash
# Development build (local architecture)
make build

# With version tag
make build VERSION=1.2.3

# Cross-compile for Linux amd64 (for deployment)
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=1.2.3" -o scrolldaddy-dns ./cmd/dns/

# Run tests
make test
```

---

## Configuration

Configuration comes from two sources: **environment variables** (core settings) and a **JSON feature config file** (runtime-toggleable features).

### Environment Variables

Typically loaded from `/etc/scrolldaddy/scrolldaddy.env`.

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SCD_DB_HOST` | `localhost` | — | PostgreSQL host |
| `SCD_DB_PORT` | `5432` | — | PostgreSQL port |
| `SCD_DB_NAME` | — | **yes** | Database name |
| `SCD_DB_USER` | `postgres` | — | Database user |
| `SCD_DB_PASSWORD` | — | **yes** | Database password |
| `SCD_DOH_PORT` | `8053` | — | HTTP port for DoH (Caddy proxies 443 → this) |
| `SCD_DOT_PORT` | `853` | — | TCP port for DoT |
| `SCD_DOT_CERT_FILE` | — | for DoT | Path to TLS certificate (wildcard `*.dns.scrolldaddy.app`) |
| `SCD_DOT_KEY_FILE` | — | for DoT | Path to TLS private key |
| `SCD_DOT_BASE_DOMAIN` | — | for DoT | Base domain for SNI routing (e.g. `dns.scrolldaddy.app`) |
| `SCD_UPSTREAM_PRIMARY` | `1.1.1.1:53` | — | Primary upstream DNS resolver |
| `SCD_UPSTREAM_SECONDARY` | `8.8.8.8:53` | — | Fallback upstream DNS resolver |
| `SCD_RELOAD_INTERVAL` | `60` | — | Seconds between device/filter cache reloads |
| `SCD_BLOCKLIST_RELOAD_INTERVAL` | `3600` | — | Seconds between blocklist domain reloads |
| `SCD_API_KEY` | — | — | API key for protected endpoints. If unset, all API-key-protected endpoints are open. |
| `SCD_LOG_LEVEL` | `info` | — | Log verbosity: `debug`, `info`, `warn`, `error` |
| `SCD_LOG_FILE` | `stdout` | — | Log destination: `stdout` or a file path |
| `SCD_CONFIG_FILE` | `/etc/scrolldaddy/dns.json` | — | Path to JSON feature config file (see below) |
| `SCD_PEER_URL` | — | — | Base URL of a peer DNS server for cross-instance log merging (e.g. `http://10.0.0.2:8053`). Leave blank for single-server mode. See [Multi-Server Deployment](#multi-server-deployment). |

**Feature override env vars** (override values in the JSON config file):

| Variable | Overrides | Description |
|----------|-----------|-------------|
| `SCD_DNS_CACHE_SIZE` | `dns_cache.max_size` | Max cached entries. Set to `0` to disable cache entirely. |
| `SCD_QUERY_LOG_DIR` | `query_log.dir` | Directory for per-device query log files. Set to empty string to disable logging. |
| `SCD_QUERY_LOG_BUFFER` | `query_log.buffer_size` | Channel buffer depth for async log writes. |
| `SCD_QUERY_LOG_MAX_SIZE` | `query_log.max_file_size` | Per-device log file rotation threshold in bytes. |

DoT is only started if `SCD_DOT_CERT_FILE` and `SCD_DOT_KEY_FILE` are both set **and** `SCD_DOT_BASE_DOMAIN` is non-empty.

### JSON Feature Config File

Feature toggles live in `/etc/scrolldaddy/dns.json` (path overridable via `SCD_CONFIG_FILE`). The file is optional — if missing, built-in defaults apply. It is re-read on every SIGHUP or POST /reload, so changes take effect without a restart.

**Environment variables always override JSON file values.**

```json
{
  "dns_cache": {
    "enabled": true,
    "max_size": 10000
  },
  "query_log": {
    "enabled": true,
    "dir": "/var/log/scrolldaddy/queries",
    "buffer_size": 4096,
    "max_file_size": 2097152
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `dns_cache.enabled` | `true` | Enable/disable the DNS response cache |
| `dns_cache.max_size` | `10000` | Maximum number of cached DNS responses. Oldest entries evicted when full. |
| `query_log.enabled` | `true` | Enable/disable per-device query logging globally. Individual devices also need `sdd_log_queries = true` in the database. |
| `query_log.dir` | `/var/log/scrolldaddy/queries` | Directory where per-device `.log` files are written |
| `query_log.buffer_size` | `4096` | Async write channel buffer. Entries are silently dropped if full (DNS resolution is never blocked). |
| `query_log.max_file_size` | `2097152` (2 MB) | Per-device log file size before rotation. Rotated file is saved as `{uid}.log.1` (one backup only). Set to `0` to disable rotation. |
| `fail_mode` | `"open"` | What to do when the database is unavailable at startup. `"open"`: start immediately in passthrough mode — all queries forwarded unfiltered until the cache loads (uptime priority). `"closed"`: refuse all queries until the database is ready (filtering integrity priority). Errors are logged in both modes. |

---

## HTTP Endpoints

### Public (accessible via Caddy on port 443)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/resolve/{uid}?dns=<base64url>` | DoH query (RFC 8484 GET format) |
| `POST` | `/resolve/{uid}` | DoH query (RFC 8484 POST, `Content-Type: application/dns-message`) |
| `GET` | `/health` | Health check. Returns 200 OK or 503 if DB is unreachable. |

### Web server API (port 8053, firewall-restricted to web server IP)

All endpoints below require the `X-API-Key` header (or `?api_key=` query parameter) if `SCD_API_KEY` is configured.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/device/{uid}/seen` | Returns last time this UID made a DNS query. Response: `{"uid":"...","seen":true,"last_seen":"2026-01-01T12:00:00Z"}` or `{"seen":false,"last_seen":null}`. Last-seen is in-memory only — resets on service restart. |
| `GET` | `/device/{uid}/log?lines=N` | Returns the last N lines (default 100) of the device's query log as plain text. Returns 404 if query logging is disabled. When `SCD_PEER_URL` is configured, also fetches from the peer and merges chronologically. Add `?peer=0` to skip peer merging (used internally to prevent recursion). |
| `POST` | `/device/{uid}/log/purge` | Truncates the device's query log file. Returns `{"status":"purged"}`. When `SCD_PEER_URL` is configured, also forwards the purge to the peer. |
| `POST` | `/reload` | Triggers an immediate full cache reload (blocklist + device data) and re-reads the JSON feature config file. |
| `POST` | `/cache/flush` | Flushes the DNS response cache. Subsequent queries go to upstream until the cache warms up again. |

### Localhost only (port 8053, blocked by firewall externally)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/stats` | Cache statistics: device count, profile count, blocklist domain count, DNS cache hit rate, reload times, uptime. |
| `GET` | `/test?uid=<uid>&domain=<domain>` | Simulates resolution for a UID/domain pair without making a real DNS query. Returns result, reason, matched rule, and active profile info. |

---

## DNS Response Cache

When enabled, resolved DNS responses are cached in memory with their original TTLs. On a cache hit, TTLs in the returned response are decremented by elapsed time — the client sees accurate remaining TTL values and the upstream resolver is not contacted at all.

**Cache behavior:**
- Only successful responses (NOERROR, NXDOMAIN) are cached. SERVFAIL and other errors are never cached.
- Responses with TTL = 0 on all records are not cached (the domain signals no caching).
- Cache key is `qname + qtype + qclass` (case-insensitive on the name).
- When the cache reaches `max_size`, the oldest entries are evicted first.
- The cache is flushed atomically by POST /cache/flush (e.g. after a blocklist update).

**Stats** (available at GET /stats):
```json
{
  "dns_cache_size": 1423,
  "dns_cache_max_size": 10000,
  "dns_cache_hits": 98712,
  "dns_cache_misses": 4301,
  "dns_cache_hit_rate": 0.9582
}
```

---

## Per-Device Query Logging

When enabled globally (in `dns.json`) **and** for a specific device (`sdd_log_queries = true` in the database), every DNS query is appended to a flat file: `/var/log/scrolldaddy/queries/{uid}.log`.

**Log format** — tab-separated, one line per query:
```
2026-04-04T19:23:45Z	google.com	A	FORWARDED	not_blocked		no
```

Fields: `timestamp` `domain` `qtype` `result` `reason` `category` `cached`

- `result`: `FORWARDED`, `BLOCKED`, `ALLOWED` (custom allow rule), `REWRITE` (SafeSearch/SafeYouTube)
- `reason`: `not_blocked`, `custom_allow`, `custom_block`, `category`, `safesearch`, `safeyoutube`, `service`
- `category`: blocklist category key if blocked by a category (otherwise empty)
- `cached`: `yes` if the response came from the DNS response cache, `no` otherwise

**File rotation:** Each device file is rotated at `max_file_size` (default 2 MB). The current file is renamed to `{uid}.log.1` and a new file starts. Only one backup is kept. Set `max_file_size = 0` to disable rotation.

**Performance:** Log writes are asynchronous — a background goroutine drains a buffered channel. DNS resolution is never blocked by file I/O. If the buffer fills up, entries are silently dropped rather than slowing queries.

**Retrieving logs** (from the web server):
```bash
# Last 100 lines for a device
curl http://<DNS_SERVER_IP>:8053/device/<uid>/log \
  -H "X-API-Key: <SCD_API_KEY>"

# Specific number of lines
curl "http://<DNS_SERVER_IP>:8053/device/<uid>/log?lines=500" \
  -H "X-API-Key: <SCD_API_KEY>"

# Truncate log
curl -X POST http://<DNS_SERVER_IP>:8053/device/<uid>/log/purge \
  -H "X-API-Key: <SCD_API_KEY>"
```

---

## Filtering Logic

Resolution checks run in this order. First match wins.

1. **Unknown/inactive device** → REFUSED
2. **Custom allow rule** → forward immediately (bypasses all blocks)
3. **SafeSearch rewrite** — if profile has SafeSearch enabled and query is a major search engine, rewrite to safe variant via CNAME
4. **SafeYouTube rewrite** — if profile has SafeYouTube enabled and query is YouTube, rewrite to restricted mode via CNAME
5. **Custom block rule** → NXDOMAIN
6. **Service block** — if a service (LinkedIn, Facebook, etc.) is enabled for the profile, its known domains are treated as custom block rules
7. **Category blocklist** → NXDOMAIN if the domain appears in any of the profile's enabled blocklist categories
8. **Forward** → upstream DNS

### Profile Scheduling

Each device has a primary profile (always active) and an optional secondary profile with a schedule. When the current time falls within the schedule's days/hours (evaluated in the device's configured timezone), the secondary profile is used instead.

### Service Domains

Services (LinkedIn, Facebook, etc.) are defined in `internal/cache/services.go` as a hardcoded map of `service_key → []domains`. When the web app enables a service block for a profile, it saves a row to `sds_services`. The DNS server loads active services on each cache reload and merges their domains into the profile's custom block set.

To add a new service or update domain lists, edit `services.go` and redeploy the binary.

---

## Deployment

### Building the installer

The `build_installer.sh` script cross-compiles the binary for `linux/amd64`, bundles it with the systemd unit and example config files, and generates a single self-extracting shell script.

**Prerequisites (on the build machine):** Go toolchain, `base64`, `tar`

```bash
# Build with an explicit version
make release VERSION=1.2.3

# Or let it infer from git tags
make release

# Output: scrolldaddy-dns-installer.sh (~7 MB)
```

Copy the installer to your server and run it as root:

```bash
scp scrolldaddy-dns-installer.sh root@<SERVER_IP>:/tmp/
ssh root@<SERVER_IP> bash /tmp/scrolldaddy-dns-installer.sh [--verbose]
```

The installer automatically detects whether this is a **fresh install** or an **upgrade** based on whether `/usr/local/bin/scrolldaddy-dns` already exists, and takes the appropriate action.

---

### Fresh install

**Before running the installer:**
- Point a DNS A record at this server's IP (e.g. `dns.example.com`) — Caddy needs this for automatic TLS
- Have your PostgreSQL host, port, database name, user, and password ready
- The database must already have the ScrollDaddy schema installed (via the Joinery ScrollDaddy extension)

The installer runs an interactive setup wizard:

1. Prompts for database credentials, DoH domain, API key (auto-generated if left blank), optional DoT config, and log level
2. Tests TCP connectivity to the database before proceeding
3. Writes `/etc/scrolldaddy/scrolldaddy.env` with all provided values
4. Installs Caddy via apt (Debian/Ubuntu; warns with manual instructions on other systems)
5. Configures `/etc/caddy/Caddyfile` — only `/resolve/*` and `/health` are exposed publicly; all other endpoints remain on port 8053
6. Configures ufw firewall — allows 443/tcp and 853/tcp; port 8053 stays blocked externally
7. Starts the service and displays the health endpoint response

After the wizard completes the server is fully operational. No manual config editing required.

**Non-interactive mode** (for automated/CI installs):

```bash
bash scrolldaddy-dns-installer.sh --non-interactive
```

Installs files and writes the env template, enables the service but does not start it, and skips Caddy and firewall setup. Edit `/etc/scrolldaddy/scrolldaddy.env` before starting the service.

---

### Upgrade

The installer will:
1. Back up the existing binary
2. Update the systemd unit file and example configs (live configs are never touched)
3. Stop the service, swap the binary, restart
4. Wait up to 10 seconds for the service to become active
5. **Automatically roll back** to the previous binary if the service fails to start

No config file changes are needed between upgrades unless the release notes say otherwise.

---

### Verifying operation

```bash
# Service status
systemctl status scrolldaddy-dns

# Health check (returns 200 or 503 if DB unreachable)
curl http://localhost:8053/health

# Cache and blocklist statistics
curl http://localhost:8053/stats

# DNS cache hit rate
curl http://localhost:8053/stats | jq '{hits: .dns_cache_hits, misses: .dns_cache_misses, rate: .dns_cache_hit_rate}'

# Simulate a resolution for a device (no real DNS query)
curl "http://localhost:8053/test?uid=<resolver_uid>&domain=linkedin.com"

# Check whether a device has been seen recently (from web server)
curl http://<SERVER_IP>:8053/device/<resolver_uid>/seen \
  -H "X-API-Key: <SCD_API_KEY>"

# Read last 100 query log lines for a device (from web server)
curl http://<SERVER_IP>:8053/device/<resolver_uid>/log \
  -H "X-API-Key: <SCD_API_KEY>"

# Flush DNS response cache
curl -X POST http://<SERVER_IP>:8053/cache/flush \
  -H "X-API-Key: <SCD_API_KEY>"

# Trigger an immediate reload (also re-reads dns.json)
curl -X POST http://localhost:8053/reload \
  -H "X-API-Key: <SCD_API_KEY>"

# Live service log
tail -f /var/log/scrolldaddy/dns.log

# Live query log for a specific device
tail -f /var/log/scrolldaddy/queries/<resolver_uid>.log
```

---

## Multi-Server Deployment

Two ScrollDaddy DNS instances can run on separate hosts for redundancy. If one server goes down, client DNS resolvers fail over to the other automatically. Both instances share the same PostgreSQL database and operate independently.

### How failover works

ScrollDaddy uses DoH (HTTPS) and DoT (TLS), not plain DNS on port 53. Failover relies on:

- **Multiple A records** for the DoH/DoT hostname (e.g. `dns.scrolldaddy.app` resolves to both server IPs). Modern HTTPS/TLS clients implement Happy Eyeballs (RFC 8305), racing connections to both IPs with ~250ms stagger. This covers iOS, macOS, Chrome, Firefox, and Edge with near-instant failover.
- **Multiple DNS server entries** for platforms that configure DNS by IP (Windows, routers). Users list both server IPs explicitly.
- **Android DoT** resolves the hostname to multiple IPs and tries them sequentially (3-5 second failover).

### Setup

1. **Run the installer on the second server.** Point `SCD_DB_HOST` at the primary server's IP (both instances share one PostgreSQL).

2. **Open PostgreSQL** on the primary for the secondary's IP:
   ```
   # pg_hba.conf
   host    scrolldaddy    scrolldaddy_dns    <SECONDARY_IP>/32    scram-sha-256
   ```

3. **Set `SCD_PEER_URL`** on each server pointing at the other:
   ```bash
   # On primary:  SCD_PEER_URL=http://<SECONDARY_IP>:8053
   # On secondary: SCD_PEER_URL=http://<PRIMARY_IP>:8053
   ```

4. **Open firewall** for peer API access (port 8053) between the two servers.

5. **Publish two A records** for the DoH/DoT hostname, one per server IP.

### What `SCD_PEER_URL` enables

- **Log merging:** GET `/device/{uid}/log` fetches logs from both the local files and the peer, merges them chronologically, and returns the combined result. A `?peer=0` query parameter prevents recursive calls between servers.
- **Purge forwarding:** POST `/device/{uid}/log/purge` also forwards the purge to the peer.

There is zero impact on the query resolution path. Peer communication only happens on the infrequent log and purge API requests.

When `SCD_PEER_URL` is blank (the default), all peer features are disabled and the server behaves exactly as a single-instance deployment.

### What the Joinery plugin handles

The ScrollDaddy plugin in Joinery handles the remaining multi-server concerns:

- **Last seen during install:** Queries both servers for `/device/{uid}/seen` so the setup flow detects the device regardless of which server it resolved through.
- **Blocklist reload:** Triggers `/reload` on both servers after downloading blocklist updates.
- **Apple mobileconfig:** Includes a `ServerAddresses` array with both server IPs for optimal Happy Eyeballs failover.
- **Setup instructions:** Shows platform-appropriate instructions with both server IPs (Windows, routers).

---

## Database Schema

The service reads from these tables (read-only user sufficient):

| Table | Purpose |
|-------|---------|
| `sdd_devices` | Devices: resolver UID, active status, timezone, profile assignments, `sdd_log_queries` flag |
| `sdp_profiles` | Profiles: schedule config, SafeSearch/SafeYouTube flags |
| `sdf_filters` | Enabled blocklist categories per profile |
| `sds_services` | Enabled service blocks per profile (LinkedIn, Facebook, etc.) |
| `sdr_rules` | Custom domain rules per profile (block/allow) |
| `bld_blocklist_domains` | Blocklist domain entries by category key |

Schema validation runs at startup — the service refuses to start if any required table or column is missing.

---

## Signals

| Signal | Effect |
|--------|--------|
| `SIGTERM` / `SIGINT` | Graceful shutdown |
| `SIGHUP` | Triggers an immediate full cache reload and re-reads the JSON feature config file (same as POST /reload) |
