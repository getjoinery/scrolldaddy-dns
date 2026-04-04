package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
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
	logger.Info("database: %s@%s:%s/%s", cfg.DBUser, cfg.DBHost, cfg.DBPort, cfg.DBName)

	// 2. Connect to PostgreSQL with retry
	var database *db.DB
	for {
		database, err = db.Connect(cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBUser, cfg.DBPassword)
		if err == nil {
			break
		}
		logger.Error("DB connection failed: %v -- retrying in 5s", err)
		time.Sleep(5 * time.Second)
	}
	defer database.Close()
	logger.Info("connected to PostgreSQL: %s@%s:%s/%s", cfg.DBUser, cfg.DBHost, cfg.DBPort, cfg.DBName)

	// 3. Validate schema -- refuse to start if required columns are missing
	if err := database.ValidateSchema(); err != nil {
		log.Fatalf("FATAL %v", err)
	}
	logger.Info("schema validation passed")

	// 4. Create cache and perform initial full load
	c := cache.New()
	if err := c.LightReload(database); err != nil {
		log.Fatalf("FATAL initial light reload failed: %v", err)
	}
	if err := c.FullReload(database); err != nil {
		log.Fatalf("FATAL initial full reload failed: %v", err)
	}
	logger.Info("initial cache load complete")

	// 5. Load feature config (dns cache, query logging)
	fc, err := config.LoadFeatureConfig(cfg.ConfigFile)
	if err != nil {
		log.Fatalf("FATAL config file: %v", err)
	}
	config.MergeEnvOverrides(fc)

	// 5a. Create DNS response cache
	var dc *dnscache.Cache
	if fc.DNSCache.Enabled && fc.DNSCache.MaxSize > 0 {
		dc = dnscache.New(fc.DNSCache.MaxSize)
		logger.Info("DNS response cache enabled (max %d entries)", fc.DNSCache.MaxSize)
	} else {
		logger.Info("DNS response cache disabled")
	}

	// 5b. Create query logger
	var ql *querylog.Logger
	if fc.QueryLog.Enabled && fc.QueryLog.Dir != "" {
		ql = querylog.New(fc.QueryLog.Dir, fc.QueryLog.BufferSize, fc.QueryLog.MaxFileSize)
		defer ql.Close()
		logger.Info("query logging enabled (dir=%s, buffer=%d, max_size=%d)",
			fc.QueryLog.Dir, fc.QueryLog.BufferSize, fc.QueryLog.MaxFileSize)
	} else {
		logger.Info("query logging disabled")
	}

	res := resolver.New(c, dc, ql, cfg.UpstreamPrimary, cfg.UpstreamSecondary)

	// 6. Start background reload goroutines
	reloadTrigger := make(chan struct{}, 1)
	go lightReloadLoop(c, database, cfg.ReloadInterval)
	go fullReloadLoop(c, database, cfg.BlocklistReloadInterval, reloadTrigger)

	// 7. Start DoH server
	errCh := make(chan error, 2)
	handler := doh.New(res, c, dc, ql, database, reloadTrigger, cfg.APIKey)
	go func() {
		if err := doh.Server(cfg.DoHPort, handler); err != nil {
			errCh <- fmt.Errorf("DoH server: %w", err)
		}
	}()

	// 8. Start DoT server (only if cert and key are configured)
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

// lightReloadLoop reloads devices, profiles, filters, and rules every interval seconds.
func lightReloadLoop(c *cache.Cache, database *db.DB, intervalSecs int) {
	ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := c.LightReload(database); err != nil {
			logger.Error("light reload failed: %v -- serving from cached data", err)
		}
	}
}

// fullReloadLoop reloads blocklist domains every interval seconds,
// and also on demand via the reloadTrigger channel.
func fullReloadLoop(c *cache.Cache, database *db.DB, intervalSecs int, trigger <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(intervalSecs) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			doFullReload(c, database)
		case <-trigger:
			logger.Info("on-demand reload triggered")
			doFullReload(c, database)
			// Also do a light reload so device/profile changes are picked up immediately
			if err := c.LightReload(database); err != nil {
				logger.Error("on-demand light reload failed: %v", err)
			}
		}
	}
}

func doFullReload(c *cache.Cache, database *db.DB) {
	if err := c.FullReload(database); err != nil {
		logger.Error("full reload failed: %v -- serving from cached data", err)
	}
}
