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

Configuration is stored in the Joinery PostgreSQL database and loaded into memory on startup, then refreshed every 60 seconds (device/filter changes) and every 3600 seconds (blocklist domains). No restart is required for config changes.

---

## Package Structure

```
cmd/dns/main.go              Entry point. Wires all components together.
internal/
  config/config.go           Environment variable loading and validation.
  db/db.go                   PostgreSQL connection, schema validation, data loading.
  cache/
    cache.go                 In-memory store: devices, profiles, blocklists, last-seen.
    services.go              Hardcoded service→domain mappings (LinkedIn, Facebook, etc.)
  resolver/resolver.go       Core DNS resolution logic and filtering decisions.
  doh/handler.go             HTTP handlers: DoH GET/POST, /health, /device/{uid}/seen, /stats, /reload, /test.
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

All configuration is via environment variables (typically loaded from `/etc/scrolldaddy/scrolldaddy.env`).

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
| `SCD_API_KEY` | — | — | API key for `/device/{uid}/seen` endpoint. If unset, endpoint is open. |
| `SCD_LOG_LEVEL` | `info` | — | Log verbosity: `debug`, `info`, `warn`, `error` |
| `SCD_LOG_FILE` | `stdout` | — | Log destination: `stdout` or a file path |

DoT is only started if `SCD_DOT_CERT_FILE` and `SCD_DOT_KEY_FILE` are both set **and** `SCD_DOT_BASE_DOMAIN` is non-empty.

---

## HTTP Endpoints

### Public (accessible via Caddy on port 443)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/resolve/{uid}?dns=<base64url>` | DoH query (RFC 8484 GET format) |
| `POST` | `/resolve/{uid}` | DoH query (RFC 8484 POST, `Content-Type: application/dns-message`) |
| `GET` | `/health` | Health check. Returns 200 OK or 503 if DB is unreachable. |

### Web server API (port 8053, firewall-restricted to web server IP)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/device/{uid}/seen` | `X-API-Key` header | Returns last time this UID made a DNS query. Response: `{"uid":"...","seen":true,"last_seen":"2026-01-01T12:00:00Z"}` or `{"seen":false,"last_seen":null}`. Last-seen is in-memory only — resets on service restart. |

### Localhost only (port 8053, blocked by firewall externally)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/stats` | Cache statistics: device count, profile count, blocklist domain count, reload times, uptime. |
| `POST` | `/reload` | Triggers an immediate full cache reload (blocklist + device data). Used by web server after blocklist download. |
| `GET` | `/test?uid=<uid>&domain=<domain>` | Simulates resolution for a UID/domain pair without making a real DNS query. Returns result, reason, matched rule, and active profile info. |

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

Services (LinkedIn, Facebook, etc.) are defined in `internal/cache/services.go` as a hardcoded map of `service_key → []domains`. When the web app enables a service block for a profile, it saves a row to `cds_ctldservices`. The DNS server loads active services on each cache reload and merges their domains into the profile's custom block set.

To add a new service or update domain lists, edit `services.go` and redeploy the binary.

---

## Deployment

### First-time install

```bash
# 1. Create service user and directories
useradd --system --no-create-home --shell /usr/sbin/nologin scrolldaddy
mkdir -p /etc/scrolldaddy /var/log/scrolldaddy
chown scrolldaddy:scrolldaddy /var/log/scrolldaddy

# 2. Copy binary
cp scrolldaddy-dns /usr/local/bin/
chmod 755 /usr/local/bin/scrolldaddy-dns

# 3. Write environment file
cp scrolldaddy.env.example /etc/scrolldaddy/scrolldaddy.env
# Edit /etc/scrolldaddy/scrolldaddy.env with your values
chown root:scrolldaddy /etc/scrolldaddy/scrolldaddy.env
chmod 640 /etc/scrolldaddy/scrolldaddy.env

# 4. Install and start systemd service
cp scrolldaddy-dns.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now scrolldaddy-dns
```

### Updating the binary

```bash
systemctl stop scrolldaddy-dns
cp scrolldaddy-dns-new /usr/local/bin/scrolldaddy-dns
systemctl start scrolldaddy-dns
systemctl is-active scrolldaddy-dns
```

### Verifying operation

```bash
# Service health
systemctl status scrolldaddy-dns

# Health endpoint
curl http://localhost:8053/health

# Cache statistics
curl http://localhost:8053/stats

# Test a specific device+domain (no real DNS query)
curl "http://localhost:8053/test?uid=<resolver_uid>&domain=linkedin.com"

# Check last-seen for a device (from web server)
curl http://<DNS_SERVER_IP>:8053/device/<resolver_uid>/seen \
  -H "X-API-Key: <SCD_API_KEY>"

# Live log
tail -f /var/log/scrolldaddy/dns.log
```

### Triggering a cache reload

```bash
# From the DNS server itself (or web server after blocklist update)
curl -X POST http://localhost:8053/reload

# Via systemd signal (equivalent)
systemctl reload scrolldaddy-dns
```

---

## Database Schema

The service reads from these tables (read-only user sufficient):

| Table | Purpose |
|-------|---------|
| `cdd_ctlddevices` | Devices: resolver UID, active status, timezone, profile assignments |
| `cdp_ctldprofiles` | Profiles: schedule config, SafeSearch/SafeYouTube flags |
| `cdf_ctldfilters` | Enabled blocklist categories per profile |
| `cds_ctldservices` | Enabled service blocks per profile (LinkedIn, Facebook, etc.) |
| `cdr_ctldrules` | Custom domain rules per profile (block/allow) |
| `bld_blocklist_domains` | Blocklist domain entries by category key |

Schema validation runs at startup — the service refuses to start if any required table or column is missing.

---

## Signals

| Signal | Effect |
|--------|--------|
| `SIGTERM` / `SIGINT` | Graceful shutdown |
| `SIGHUP` | Triggers an immediate full cache reload (same as POST /reload) |
