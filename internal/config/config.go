package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	DBHost     string
	DBPort     string
	DBName     string
	DBUser     string
	DBPassword string

	DoHPort       int
	DoTPort       int
	DoTCertFile   string
	DoTKeyFile    string
	DoTBaseDomain string

	UpstreamPrimary   string
	UpstreamSecondary string

	ReloadInterval          int
	BlocklistReloadInterval int

	DNSCacheSize int

	LogLevel string
	LogFile  string

	APIKey string
}

func Load() (*Config, error) {
	cfg := &Config{
		DBHost:                  getEnv("SCD_DB_HOST", "localhost"),
		DBPort:                  getEnv("SCD_DB_PORT", "5432"),
		DBName:                  getEnv("SCD_DB_NAME", ""),
		DBUser:                  getEnv("SCD_DB_USER", "postgres"),
		DBPassword:              getEnv("SCD_DB_PASSWORD", ""),
		DoHPort:                 getEnvInt("SCD_DOH_PORT", 8053),
		DoTPort:                 getEnvInt("SCD_DOT_PORT", 853),
		DoTCertFile:             getEnv("SCD_DOT_CERT_FILE", ""),
		DoTKeyFile:              getEnv("SCD_DOT_KEY_FILE", ""),
		DoTBaseDomain:           getEnv("SCD_DOT_BASE_DOMAIN", ""),
		UpstreamPrimary:         getEnv("SCD_UPSTREAM_PRIMARY", "1.1.1.1:53"),
		UpstreamSecondary:       getEnv("SCD_UPSTREAM_SECONDARY", "8.8.8.8:53"),
		ReloadInterval:          getEnvInt("SCD_RELOAD_INTERVAL", 60),
		BlocklistReloadInterval: getEnvInt("SCD_BLOCKLIST_RELOAD_INTERVAL", 3600),
		DNSCacheSize:            getEnvInt("SCD_DNS_CACHE_SIZE", 10000),
		LogLevel:                getEnv("SCD_LOG_LEVEL", "info"),
		LogFile:                 getEnv("SCD_LOG_FILE", "stdout"),
		APIKey:                  getEnv("SCD_API_KEY", ""),
	}

	if cfg.DBName == "" {
		return nil, fmt.Errorf("SCD_DB_NAME is required")
	}
	if cfg.DBPassword == "" {
		return nil, fmt.Errorf("SCD_DB_PASSWORD is required")
	}

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}
