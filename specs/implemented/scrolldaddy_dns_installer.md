# ScrollDaddy DNS — Self-Hosted Installer

## Goal

Make it possible for a non-expert to go from a blank Linux VPS to a fully operational ScrollDaddy DNS server by running one command after copying a single file. No manual config editing, no separate Caddy setup, no manual firewall steps.

## Background

scrolldaddy-dns is a Go binary that implements DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) with per-device content filtering backed by a PostgreSQL database. It is distributed as a self-extracting shell script (`scrolldaddy-dns-installer.sh`) built by `build_installer.sh`.

The installer is the primary distribution mechanism for both:
- **ScrollDaddy SaaS operators** running dedicated DNS VPS nodes
- **Self-hosters** running the full Joinery + ScrollDaddy extension stack

## What the Installer Does

### Fresh Install (Interactive Mode)

The installer runs a setup wizard that:

1. **Prompts for required configuration:**
   - Database host, port, name, user, password
   - Public DoH domain (e.g. `dns.example.com`) for Caddy
   - API key (auto-generates a 64-char hex key if the user presses Enter)
   - DoT configuration (optional — most installs skip this)
   - Log level (default: `info`)

2. **Tests TCP connectivity** to the database host:port before proceeding (non-fatal — warns if unreachable, does not abort).

3. **Writes `/etc/scrolldaddy/scrolldaddy.env`** with all provided values. File is owned `root:scrolldaddy`, mode `640`.

4. **Installs Caddy** via the official Cloudsmith apt repository (Debian/Ubuntu). Skipped if Caddy is already installed. No-ops with a warning on non-apt systems.

5. **Configures Caddy** by writing a block to `/etc/caddy/Caddyfile`:
   ```
   dns.example.com {
       handle /resolve/* {
           reverse_proxy localhost:8053
       }
       handle /health {
           reverse_proxy localhost:8053
       }
       respond 404
   }
   ```
   Only `/resolve/*` and `/health` are exposed publicly. All other endpoints (stats, test, reload, device log) remain internal. Caddy handles TLS automatically via Let's Encrypt.

   If the existing Caddyfile contains the default `:80` placeholder, it is replaced entirely. Otherwise the block is appended. The original is backed up to `Caddyfile.bak`. Operation is idempotent — a marker comment prevents double-configuration.

6. **Configures ufw firewall:**
   - If ufw is inactive: ensures `ssh` is allowed, then allows `443/tcp` and `853/tcp`, enables ufw.
   - If ufw is already active: adds `443/tcp` and `853/tcp` rules.
   - Port `8053` remains blocked externally (ufw default deny — only Caddy and the web server call it directly).

7. **Starts the service** and waits up to 15 seconds for it to become active, then shows the health endpoint response.

### Fresh Install (Non-Interactive Mode)

Run with `--non-interactive`. Installs files, writes env from the example template, enables the service but does not start it. No Caddy or firewall setup. Prints next-steps instructions.

### Upgrade

Detected automatically: if `/usr/local/bin/scrolldaddy-dns` exists, upgrade mode runs. No setup wizard, no Caddy or firewall changes.

1. Backs up the existing binary
2. Updates the systemd unit and example configs (never touches live configs)
3. Stops the service (`reset-failed` to clear crash state and reset `NRestarts`)
4. Installs new binary
5. Restarts the service (only if `systemctl is-enabled`)
6. Waits up to 12 seconds, checking `is-active` AND `NRestarts == 0`
7. Rolls back to the previous binary automatically if the service fails to start

## Build Workflow

```bash
cd scrolldaddy-dns
make release VERSION=1.x.x
scp scrolldaddy-dns-installer.sh root@<SERVER_IP>:/tmp/
ssh root@<SERVER_IP> bash /tmp/scrolldaddy-dns-installer.sh [--verbose]
```

`make release` calls `build_installer.sh`, which:
- Cross-compiles the binary for `linux/amd64`
- Bundles it with the systemd unit and example configs into a tar.gz
- Base64-encodes the payload and appends it after a `__PAYLOAD__` marker
- Outputs a single self-extracting shell script

## Files Installed

| Path | Description |
|------|-------------|
| `/usr/local/bin/scrolldaddy-dns` | The binary |
| `/etc/systemd/system/scrolldaddy-dns.service` | systemd unit |
| `/etc/scrolldaddy/scrolldaddy.env` | Live environment config (credentials) |
| `/etc/scrolldaddy/scrolldaddy.env.example` | Template (always updated on upgrade) |
| `/etc/scrolldaddy/dns.json` | Feature config (cache, query logging, fail_mode) |
| `/etc/scrolldaddy/dns.json.example` | Template (always updated on upgrade) |
| `/var/log/scrolldaddy/` | Log directory (owned by `scrolldaddy` user) |
| `/var/log/scrolldaddy/queries/` | Per-device query log files |

## What the User Needs Before Running

1. **A Linux server** (systemd required; Debian/Ubuntu for auto-Caddy)
2. **A domain with an A record** pointing to the server's IP (for Let's Encrypt HTTPS)
3. **A PostgreSQL database** with the ScrollDaddy schema already installed (via the Joinery ScrollDaddy extension)
4. **Network access** from the server to the database host

That's it. The installer handles everything else.

## What the Installer Does NOT Do

- **Database setup** — the DB and schema must already exist. The installer tests connectivity but cannot create the database.
- **Wildcard TLS cert for DoT** — DoT requires a wildcard cert (e.g. `*.dns.example.com`) which requires a DNS challenge. The installer prompts for existing cert paths but will not obtain a new cert. Most installs skip DoT entirely.
- **Non-Debian/Ubuntu Caddy install** — warns and prints manual instructions instead.

## Future Work

- **Schema bootstrapping** — for true standalone installs, provide a SQL migration file that creates all required tables from scratch without the full Joinery stack. This would decouple the DNS server from Joinery for operators who want a simpler deployment.
- **DoT cert automation** — Caddy supports wildcard certs via DNS challenge plugins. Could automate this for supported DNS providers (Cloudflare, etc.).
- **Post-install health loop** — currently prints health once at the end. Could poll for `db_connected: true` and print a clear "filtering active" message once the blocklist finishes loading.
- **nginx/Apache Caddy alternative** — detect existing web server and offer a ready-to-paste config snippet instead of installing Caddy.
