package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"scrolldaddy-dns/internal/cache"
	"scrolldaddy-dns/internal/config"
	"scrolldaddy-dns/internal/db"
	"scrolldaddy-dns/internal/dnscache"
	"scrolldaddy-dns/internal/doh"
	"scrolldaddy-dns/internal/dot"
	"scrolldaddy-dns/internal/logger"
	"scrolldaddy-dns/internal/querylog"
	"scrolldaddy-dns/internal/resolver"
)

// version is set at build time via: go build -ldflags "-X main.version=1.0.0"
var version = "dev"

func main() {
	// Handle --version flag
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("scrolldaddy-dns %s\n", version)
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	// 1. Load and validate configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("ERROR config: %v", err)
	}
	logger.SetLevel(cfg.LogLevel)
	logger.Info("starting ScrollDaddy DNS service v%s", version)
	for i, dsn := range cfg.JoineryDBURLs {
		logger.Info("database[%d]: %s", i, maskDSN(dsn))
	}

	// 2. Load feature config (needed early to know fail_mode before DB connect)
	fc, err := config.LoadFeatureConfig(cfg.ConfigFile)
	if err != nil {
		log.Fatalf("FATAL config file: %v", err)
	}
	config.MergeEnvOverrides(fc)

	// 2a. Create DNS response cache
	var dc *dnscache.Cache
	if fc.DNSCache.Enabled && fc.DNSCache.MaxSize > 0 {
		dc = dnscache.New(fc.DNSCache.MaxSize)
		logger.Info("DNS response cache enabled (max %d entries)", fc.DNSCache.MaxSize)
	} else {
		logger.Info("DNS response cache disabled")
	}

	// 2b. Create query logger
	var ql *querylog.Logger
	if fc.QueryLog.Enabled && fc.QueryLog.Dir != "" {
		ql = querylog.New(fc.QueryLog.Dir, fc.QueryLog.BufferSize, fc.QueryLog.MaxFileSize)
		defer ql.Close()
		logger.Info("query logging enabled (dir=%s, buffer=%d, max_size=%d)",
			fc.QueryLog.Dir, fc.QueryLog.BufferSize, fc.QueryLog.MaxFileSize)
	} else {
		logger.Info("query logging disabled")
	}

	c := cache.New()
	res := resolver.New(c, dc, ql, cfg.UpstreamPrimary, cfg.UpstreamSecondary)
	reloadTrigger := make(chan struct{}, 1)

	// 3. Create DoH handler (database starts nil; SetDatabase called once connected)
	errCh := make(chan error, 2)
	handler := doh.New(res, c, dc, ql, nil, reloadTrigger, cfg.APIKey, cfg.PeerURL)

	// 4. Connect to DB and load cache.
	//    fail_open:  start servers in passthrough mode immediately, load in background.
	//    fail_closed: block until DB is ready, then start servers.
	if fc.FailOpen() {
		logger.Info("fail_mode=open — starting servers in passthrough mode; cache loading in background")
		res.SetPassthrough(true)
		go connectAndLoad(res, handler, cfg, c, dc, reloadTrigger)
	} else {
		logger.Info("fail_mode=closed — waiting for database before accepting queries")
		connectAndLoad(res, handler, cfg, c, dc, reloadTrigger)
	}

	// 5. Start DoH server
	go func() {
		if err := doh.Server(cfg.DoHPort, handler); err != nil {
			errCh <- fmt.Errorf("DoH server: %w", err)
		}
	}()

	// 6. Start DoT server (only if cert and key are configured)
	if cfg.DoTCertFile != "" && cfg.DoTKeyFile != "" {
		if cfg.DoTBaseDomain == "" {
			logger.Warn("SCD_DOT_CERT_FILE set but SCD_DOT_BASE_DOMAIN is empty -- skipping DoT")
		} else {
			go func() {
				if err := dot.Server(cfg.DoTPort, cfg.DoTCertFile, cfg.DoTKeyFile, cfg.DoTBaseDomain, res, c); err != nil {
					// Non-fatal: DoH continues without DoT
					logger.Warn("DoT server error (DoH continues): %v", err)
				}
			}()
		}
	} else {
		logger.Info("DoT not configured (set SCD_DOT_CERT_FILE, SCD_DOT_KEY_FILE, SCD_DOT_BASE_DOMAIN to enable)")
	}

	// 9. Wait for signals or fatal server error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				logger.Info("SIGHUP received -- triggering immediate full reload")
				select {
				case reloadTrigger <- struct{}{}:
				default:
				}
			case syscall.SIGTERM, syscall.SIGINT:
				logger.Info("shutdown signal received -- exiting")
				os.Exit(0)
			}
		case err := <-errCh:
			log.Fatalf("FATAL server error: %v", err)
		}
	}
}

// connectAndLoad connects to all configured databases, validates schemas,
// performs the initial cache load, starts the reload loops, and disables
// passthrough mode. Retries indefinitely on failure. Called synchronously
// (fail_closed) or as a goroutine (fail_open).
func connectAndLoad(res *resolver.Resolver, h *doh.Handler, cfg *config.Config, c *cache.Cache, dc *dnscache.Cache, reloadTrigger chan struct{}) {
	databases := make([]*db.DB, 0, len(cfg.JoineryDBURLs))

	for {
		// Connect to every configured DB; close any already-opened on partial failure.
		var failed bool
		databases = databases[:0]
		for i, dsn := range cfg.JoineryDBURLs {
			d, err := db.ConnectURL(dsn)
			if err != nil {
				logger.Error("DB[%d] connection failed: %v — retrying all in 5s", i, err)
				for _, open := range databases {
					open.Close()
				}
				failed = true
				break
			}
			logger.Info("DB[%d] connected (%s)", i, maskDSN(dsn))
			if err = d.ValidateSchema(); err != nil {
				logger.Error("DB[%d] schema validation failed: %v — retrying all in 5s", i, err)
				d.Close()
				for _, open := range databases {
					open.Close()
				}
				failed = true
				break
			}
			logger.Info("DB[%d] schema validation passed", i)
			databases = append(databases, d)
		}
		if failed {
			time.Sleep(5 * time.Second)
			continue
		}

		if err := c.LightReload(databases); err != nil {
			logger.Error("initial light reload failed: %v — retrying in 5s", err)
			for _, d := range databases {
				d.Close()
			}
			time.Sleep(5 * time.Second)
			continue
		}
		if err := c.FullReload(databases); err != nil {
			logger.Error("initial full reload failed: %v — retrying in 5s", err)
			for _, d := range databases {
				d.Close()
			}
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}

	logger.Info("initial cache load complete (%d database(s))", len(databases))

	// Wire the first database into the DoH handler for /health.
	// A future enhancement could check all DBs; for now one ping is sufficient.
	h.SetDatabase(databases[0])

	// Flush the DNS response cache: any responses cached during passthrough
	// were unfiltered and should not persist now that filtering is active.
	if dc != nil {
		dc.Flush()
	}

	// Disable passthrough — filtering is now active.
	if res.InPassthrough() {
		res.SetPassthrough(false)
	}

	go lightReloadLoop(c, databases, cfg.ReloadInterval)
	go fullReloadLoop(c, databases, cfg.BlocklistReloadInterval, reloadTrigger)
}

// lightReloadLoop reloads devices, profiles, filters, and rules every interval seconds.
func lightReloadLoop(c *cache.Cache, databases []*db.DB, intervalSecs int) {
	ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := c.LightReload(databases); err != nil {
			logger.Error("light reload failed: %v -- serving from cached data", err)
		}
	}
}

// fullReloadLoop reloads blocklist domains every interval seconds,
// and also on demand via the reloadTrigger channel.
func fullReloadLoop(c *cache.Cache, databases []*db.DB, intervalSecs int, trigger <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			doFullReload(c, databases)
		case <-trigger:
			logger.Info("on-demand reload triggered")
			doFullReload(c, databases)
			// Also do a light reload so device/profile changes are picked up immediately
			if err := c.LightReload(databases); err != nil {
				logger.Error("on-demand light reload failed: %v", err)
			}
		}
	}
}

func doFullReload(c *cache.Cache, databases []*db.DB) {
	if err := c.FullReload(databases); err != nil {
		logger.Error("full reload failed: %v -- serving from cached data", err)
	}
}

// maskDSN redacts the password from a DSN or URL for safe logging.
func maskDSN(dsn string) string {
	// Handle URL form: postgresql://user:password@host/db
	if i := strings.Index(dsn, "://"); i >= 0 {
		rest := dsn[i+3:]
		if at := strings.Index(rest, "@"); at >= 0 {
			userinfo := rest[:at]
			if colon := strings.Index(userinfo, ":"); colon >= 0 {
				return dsn[:i+3] + userinfo[:colon+1] + "***" + rest[at:]
			}
		}
		return dsn
	}
	// Handle key=value DSN form: host=... password=xxx ...
	parts := strings.Fields(dsn)
	for i, p := range parts {
		if strings.HasPrefix(p, "password=") {
			parts[i] = "password=***"
		}
	}
	return strings.Join(parts, " ")
}
