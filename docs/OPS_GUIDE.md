# ScrollDaddy DNS Servers — Operations Guide

Operational guide for the ScrollDaddy DNS infrastructure. Two DNS servers resolve DNS-over-HTTPS (DoH) queries for ScrollDaddy users, with automatic failover via dual A records.

## Architecture Overview

```
User device (DoH request)
    │
    ▼
dns.scrolldaddy.app  (two A records — clients hit either)
    ├── 45.56.103.84   (primary)   ── Caddy :443 → scrolldaddy-dns :8053
    └── 97.107.131.227 (secondary) ── Caddy :443 → scrolldaddy-dns :8053
                                          │
                                          ▼
                                   PostgreSQL (one or more Joinery DBs)
                                   Configured via SCD_JOINERY_DB_URLS
```

Both servers run identical software. They peer with each other over the Linode private network for log merging and purge forwarding. Each server can read from multiple Joinery PostgreSQL databases simultaneously — devices from all configured deployments are unioned in memory; device resolver UIDs are globally unique (128-bit random) so the union is collision-free.

## Servers

| Role | Public IP | Private IP | Provider | OS |
|------|-----------|------------|----------|----|
| Primary | 45.56.103.84 | 192.168.206.198 | Linode | Ubuntu 24.04 |
| Secondary | 97.107.131.227 | 192.168.151.4 | Linode | Ubuntu 24.04 |
| ScrollDaddy DB | 23.239.11.53 (docker-prod) | 192.168.206.198 | Linode | Docker container `scrolldaddy`, port 9087 |

**SSH access:** `ssh -i ~/.ssh/id_ed25519_claude root@<IP>`

## Software Stack

Each DNS server runs two services:

### 1. scrolldaddy-dns (Go binary)

The DNS resolver. Loads device profiles and blocklists from PostgreSQL, resolves DoH queries, logs query activity.

- **Binary:** `/usr/local/bin/scrolldaddy-dns`
- **Service:** `scrolldaddy-dns.service`
- **Runs as:** `scrolldaddy` user
- **Version:** 1.8.0 (as of 2026-05-02)
- **Source code:** `/home/user1/scrolldaddy-dns/` on the dev server

### 2. Caddy (reverse proxy)

Terminates TLS and proxies HTTPS traffic to the DNS resolver on localhost:8053.

- **Binary:** `/usr/bin/caddy` (custom build with `dns.providers.cloudflare` module)
- **Service:** `caddy.service`
- **Version:** 2.11.2 (as of 2026-04-16)

The custom Caddy binary is required because the standard package does not include DNS challenge plugins. If Caddy is ever reinstalled from the package manager, it will lose the Cloudflare module and cert renewal will break.

## Configuration Files

All paths below apply to **both** servers unless noted.

### scrolldaddy-dns

| File | Purpose |
|------|---------|
| `/etc/scrolldaddy/scrolldaddy.env` | Main config: DB credentials, API key, ports, peer URL, log settings |
| `/etc/scrolldaddy/dns.json` | Runtime options: DNS cache size, query log settings, fail mode |
| `/var/log/scrolldaddy/dns.log` | Application log (configured via `SCD_LOG_FILE`) |
| `/var/log/scrolldaddy/queries/` | Per-device query logs |

**Key environment variables in scrolldaddy.env:**

| Variable | Purpose |
|----------|---------|
| `SCD_JOINERY_DB_URLS` | Comma-separated list of PostgreSQL DSNs, one per Joinery deployment. Use this for multi-deployment setups (e.g. ScrollDaddy + NetworkSentry). Example: `host=192.168.206.198 port=9087 dbname=scrolldaddy user=scrolldaddy_reader password=xxx sslmode=disable` |
| `SCD_DB_HOST`, `SCD_DB_PORT`, `SCD_DB_NAME`, `SCD_DB_USER`, `SCD_DB_PASSWORD` | Legacy single-DB connection variables. Used automatically if `SCD_JOINERY_DB_URLS` is not set. Keep these for single-deployment setups; migrate to `SCD_JOINERY_DB_URLS` when adding a second deployment. |
| `SCD_DOH_PORT` | Port the resolver listens on (8053) |
| `SCD_API_KEY` | Protects management endpoints (`/reload`, `/cache/flush`, `/device/{uid}/log`) |
| `SCD_PEER_URL` | URL of the other server for cross-instance log merging. Primary points to secondary's private IP and vice versa |
| `SCD_UPSTREAM_PRIMARY`, `SCD_UPSTREAM_SECONDARY` | Upstream DNS forwarders (1.1.1.1, 8.8.8.8) |
| `SCD_RELOAD_INTERVAL` | How often (seconds) to reload device profiles from DB (60) |
| `SCD_BLOCKLIST_RELOAD_INTERVAL` | How often (seconds) to reload blocklists from DB (3600) |

**To add a second Joinery deployment** (e.g. NetworkSentry), replace the `SCD_DB_*` block in `scrolldaddy.env` with:
```
SCD_JOINERY_DB_URLS=host=<scrolldaddy-db-host> port=<port> dbname=<db> user=<user> password=<pass> sslmode=disable,host=<networksentry-db-host> port=<port> dbname=<db> user=<user> password=<pass> sslmode=disable
```
Then `systemctl restart scrolldaddy-dns` on each server. No binary change needed.

**Peer URLs (private network):**
- Primary's `SCD_PEER_URL` → `http://192.168.151.4:8053` (secondary)
- Secondary's `SCD_PEER_URL` → `http://192.168.206.198:8053` (primary)

### Caddy

| File | Purpose |
|------|---------|
| `/etc/caddy/Caddyfile` | Reverse proxy config and TLS settings |
| `/etc/systemd/system/caddy.service.d/cloudflare.conf` | Cloudflare API token (systemd environment override, mode 600) |
| `/var/lib/caddy/.local/share/caddy/` | Cert storage (managed automatically by Caddy) |

**Caddyfile** (identical on both servers):
```
dns.scrolldaddy.app {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    handle /resolve/* {
        reverse_proxy localhost:8053
    }
    handle /health {
        reverse_proxy localhost:8053
    }
    respond 404
}
```

### TLS Certificate Renewal

Caddy automatically renews the TLS certificate for `dns.scrolldaddy.app` using **DNS-01 challenges via Cloudflare**. This is necessary because the domain has two A records — HTTP-01 challenges would fail when Let's Encrypt's validator hits the other server.

- **Cloudflare API token** is stored in `/etc/systemd/system/caddy.service.d/cloudflare.conf` on each server
- The token has `Zone / DNS / Edit` permission scoped to the `scrolldaddy.app` zone, with IP restrictions to both server IPs (45.56.103.84 and 97.107.131.227)
- Certs are stored in `/var/lib/caddy/.local/share/caddy/certificates/`
- Caddy renews automatically ~30 days before expiry; no cron needed
- If you need to recreate the Cloudflare token: Cloudflare dashboard → My Profile → API Tokens → Create Token → "Edit zone DNS" template, scope to `scrolldaddy.app`, restrict to IPs `45.56.103.84` and `97.107.131.227`

## DNS Records (Cloudflare)

`dns.scrolldaddy.app` has two A records:
- `45.56.103.84` (primary)
- `97.107.131.227` (secondary)

Clients randomly receive one or both IPs. If one server is down, clients retry and hit the other.

## Web App Settings (ScrollDaddy Production)

The dns_filtering plugin reads these settings from `stg_settings` to generate device configs and communicate with the DNS servers:

| Setting | Value | Purpose |
|---------|-------|---------|
| `dns_filtering_dns_host` | `dns.scrolldaddy.app` | Hostname used in DoH URLs |
| `dns_filtering_dns_server_ip` | `45.56.103.84` | Primary IP shown in device configs |
| `dns_filtering_dns_secondary_server_ip` | `97.107.131.227` | Secondary IP shown in device configs |
| `dns_filtering_dns_internal_url` | `http://45.56.103.84:8053` | Web app → primary API |
| `dns_filtering_dns_secondary_internal_url` | `http://97.107.131.227:8053` | Web app → secondary API |
| `dns_filtering_dns_api_key` | *(in database)* | API key for primary server (must match SCD_API_KEY in primary env) |
| `dns_filtering_dns_secondary_api_key` | *(in database)* | API key for secondary server (must match SCD_API_KEY in secondary env) |

These settings are managed from the dns_filtering plugin Settings page in the Joinery admin panel, or directly in the database on docker-prod.

## Firewall (UFW)

Both servers run UFW with identical rules:
- 22/tcp — SSH
- 80/tcp — HTTP (Caddy ACME, redirects to HTTPS)
- 443/tcp — HTTPS (Caddy → DoH)
- 853/tcp — DNS-over-TLS
- 8053 from 23.239.11.53 — API access from docker-prod web server
- 8053 from peer private IP — cross-server peer communication

## Deploying Updates

### Upgrading scrolldaddy-dns

Source code is at `/home/user1/scrolldaddy-dns/` on the dev server.

```bash
cd /home/user1/scrolldaddy-dns
make release VERSION=1.x.x
scp scrolldaddy-dns-installer.sh root@45.56.103.84:/tmp/
ssh root@45.56.103.84 bash /tmp/scrolldaddy-dns-installer.sh --verbose
scp scrolldaddy-dns-installer.sh root@97.107.131.227:/tmp/
ssh root@97.107.131.227 bash /tmp/scrolldaddy-dns-installer.sh --verbose
```

The installer auto-detects install vs upgrade. On upgrade it stops the service, swaps the binary, restarts, and auto-rolls back on failure.

### Upgrading Caddy

If Caddy needs upgrading, you must rebuild the custom binary with the Cloudflare DNS module — do **not** use `apt upgrade caddy`, as that would replace the custom build with the stock binary (no Cloudflare support).

```bash
# On the dev server (requires Go)
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
cd /tmp
xcaddy build --with github.com/caddy-dns/cloudflare

# Deploy to each server
scp /tmp/caddy root@<SERVER_IP>:/tmp/caddy-custom
ssh root@<SERVER_IP> "systemctl stop caddy && cp /usr/bin/caddy /usr/bin/caddy.bak && cp /tmp/caddy-custom /usr/bin/caddy && chmod 755 /usr/bin/caddy && systemctl start caddy"
```

## Troubleshooting

### Quick health check

```bash
# From anywhere
curl https://dns.scrolldaddy.app/health

# Target a specific server
curl https://dns.scrolldaddy.app/health --resolve dns.scrolldaddy.app:443:45.56.103.84
curl https://dns.scrolldaddy.app/health --resolve dns.scrolldaddy.app:443:97.107.131.227
```

A healthy response looks like:
```json
{"db_connected":true,"last_reload":"2026-05-02T17:09:49Z","status":"ok","uptime_seconds":19}
```

### Server is unreachable (no HTTPS response)

1. **SSH in** and check if services are running:
   ```bash
   systemctl status scrolldaddy-dns
   systemctl status caddy
   ```

2. **If scrolldaddy-dns is down:**
   ```bash
   journalctl -u scrolldaddy-dns --no-pager -n 50
   systemctl restart scrolldaddy-dns
   ```
   Common causes: database unreachable (check `SCD_JOINERY_DB_URLS` or `SCD_DB_HOST` in `scrolldaddy.env`), env file syntax error.

3. **If Caddy is down:**
   ```bash
   journalctl -u caddy --no-pager -n 50
   systemctl restart caddy
   ```
   Common causes: port 443 already in use, Caddyfile syntax error, cert renewal failure.

4. **If scrolldaddy-dns is up but Caddy can't reach it:**
   ```bash
   curl http://localhost:8053/health
   ```
   If this works, the issue is in Caddy's proxy config.

### DNS health is "degraded"

The `"status":"degraded"` response means the server is starting up and loading its blocklist cache (takes ~6-8 seconds). During this time `fail_mode: open` means queries are forwarded to upstream DNS unfiltered. Wait a few seconds and check again.

### Database connection errors

Each server reads from the Joinery deployments configured in `SCD_JOINERY_DB_URLS` (or the legacy `SCD_DB_*` vars). Current ScrollDaddy connection:
```
Host: 192.168.206.198   Port: 9087   DB: scrolldaddy   User: scrolldaddy_reader
```

If the database is unreachable:
1. Check if docker-prod is up: `ssh root@23.239.11.53 "docker ps | grep scrolldaddy"`
2. Check if the DB port is exposed: `ssh root@23.239.11.53 "docker port scrolldaddy"`
3. Check private network connectivity from the DNS server: `ping 192.168.206.198`
4. Check the resolver log for specific connection errors: `journalctl -u scrolldaddy-dns --no-pager -n 50 | grep -i "DB\|connect\|error"`

### TLS certificate expired or failing

Caddy auto-renews certs. If it fails:
1. Check Caddy logs: `journalctl -u caddy --no-pager -n 100 | grep -i "tls\|cert\|acme"`
2. Verify the Cloudflare token is still valid — check the systemd override:
   ```bash
   cat /etc/systemd/system/caddy.service.d/cloudflare.conf
   ```
3. Force a cert renewal by deleting the stored cert and restarting:
   ```bash
   rm -rf /var/lib/caddy/.local/share/caddy/certificates/
   systemctl restart caddy
   ```
4. If the Cloudflare token was revoked or expired, create a new one (see TLS Certificate Renewal section above), update the override file on both servers, run `systemctl daemon-reload && systemctl restart caddy`.

### Rolling back scrolldaddy-dns

The installer keeps a backup binary:
```bash
systemctl stop scrolldaddy-dns
cp /usr/local/bin/scrolldaddy-dns.bak /usr/local/bin/scrolldaddy-dns
systemctl start scrolldaddy-dns
```

### Rolling back Caddy

```bash
systemctl stop caddy
cp /usr/bin/caddy.bak /usr/bin/caddy
systemctl start caddy
```

### Checking query resolution end-to-end

To test that a real DNS query works through DoH, use a known device resolver UID:
```bash
# Replace RESOLVER_UID with an actual device UID from the database
# This sends a DNS query for example.com through the DoH endpoint
curl -s -H "accept: application/dns-message" \
  "https://dns.scrolldaddy.app/resolve/RESOLVER_UID?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE" \
  --resolve dns.scrolldaddy.app:443:45.56.103.84 \
  -o /dev/null -w "%{http_code}"
# Should return 200
```

### Restarting everything (nuclear option)

On each server:
```bash
systemctl restart scrolldaddy-dns
systemctl restart caddy
```

Wait ~10 seconds for blocklist cache to load, then verify with the health endpoint.
