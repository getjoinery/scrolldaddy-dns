package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	// JoineryDBURLs is the list of PostgreSQL DSNs to read from.
	// Populated from SCD_JOINERY_DB_URLS (comma-separated) or constructed from
	// the legacy SCD_DB_* vars when SCD_JOINERY_DB_URLS is not set.
	JoineryDBURLs []string

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

	ConfigFile string

	LogLevel string
	LogFile  string

	APIKey  string
	PeerURL string
}

// FeatureConfig holds runtime-toggleable feature settings loaded from the
// JSON config file. All fields have sensible defaults.
type FeatureConfig struct {
	DNSCache DNSCacheConfig `json:"dns_cache"`
	QueryLog QueryLogConfig `json:"query_log"`
	FailMode string         `json:"fail_mode"` // "open" or "closed"
}

// FailOpen reports whether the service should start in passthrough mode when
// the database is unavailable, rather than refusing all queries.
func (fc *FeatureConfig) FailOpen() bool {
	return fc.FailMode != "closed"
}

// DNSCacheConfig controls the DNS response cache.
type DNSCacheConfig struct {
	Enabled bool `json:"enabled"`
	MaxSize int  `json:"max_size"`
}

// QueryLogConfig controls per-device query logging.
type QueryLogConfig struct {
	Enabled     bool   `json:"enabled"`
	Dir         string `json:"dir"`
	BufferSize  int    `json:"buffer_size"`
	MaxFileSize int64  `json:"max_file_size"`
}

// DefaultFeatureConfig returns a FeatureConfig with all defaults applied.
func DefaultFeatureConfig() *FeatureConfig {
	return &FeatureConfig{
		DNSCache: DNSCacheConfig{
			Enabled: true,
			MaxSize: 10000,
		},
		QueryLog: QueryLogConfig{
			Enabled:     true,
			Dir:         "/var/log/scrolldaddy/queries",
			BufferSize:  4096,
			MaxFileSize: 2097152, // 2MB
		},
		FailMode: "open",
	}
}

// LoadFeatureConfig reads the JSON config file and returns a FeatureConfig.
// If path is empty or the file doesn't exist, defaults are returned.
// Returns an error only if the file exists but contains invalid JSON.
func LoadFeatureConfig(path string) (*FeatureConfig, error) {
	fc := DefaultFeatureConfig()
	if path == "" {
		return fc, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fc, nil
		}
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	if err := json.Unmarshal(data, fc); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	return fc, nil
}

// MergeEnvOverrides applies environment variable overrides to a FeatureConfig.
// Env vars take precedence over config file values.
func MergeEnvOverrides(fc *FeatureConfig) {
	if v := os.Getenv("SCD_DNS_CACHE_SIZE"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			fc.DNSCache.MaxSize = i
			if i == 0 {
				fc.DNSCache.Enabled = false
			}
		}
	}
	if v := os.Getenv("SCD_QUERY_LOG_DIR"); v != "" {
		fc.QueryLog.Dir = v
	} else if os.Getenv("SCD_QUERY_LOG_DIR") == "" {
		// Check if explicitly set to empty to disable
		if _, set := os.LookupEnv("SCD_QUERY_LOG_DIR"); set {
			fc.QueryLog.Dir = ""
			fc.QueryLog.Enabled = false
		}
	}
	if v := os.Getenv("SCD_QUERY_LOG_BUFFER"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			fc.QueryLog.BufferSize = i
		}
	}
	if v := os.Getenv("SCD_QUERY_LOG_MAX_SIZE"); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			fc.QueryLog.MaxFileSize = i
		}
	}
}

func Load() (*Config, error) {
	var dbURLs []string
	if raw := os.Getenv("SCD_JOINERY_DB_URLS"); raw != "" {
		for _, u := range strings.Split(raw, ",") {
			if u = strings.TrimSpace(u); u != "" {
				dbURLs = append(dbURLs, u)
			}
		}
	}

	// Backward compat: construct a single DSN from legacy SCD_DB_* vars.
	if len(dbURLs) == 0 {
		host := getEnv("SCD_DB_HOST", "localhost")
		port := getEnv("SCD_DB_PORT", "5432")
		name := getEnv("SCD_DB_NAME", "")
		user := getEnv("SCD_DB_USER", "postgres")
		pass := getEnv("SCD_DB_PASSWORD", "")
		if name == "" {
			return nil, fmt.Errorf("SCD_JOINERY_DB_URLS or SCD_DB_NAME is required")
		}
		if pass == "" {
			return nil, fmt.Errorf("SCD_JOINERY_DB_URLS or SCD_DB_PASSWORD is required")
		}
		dbURLs = []string{fmt.Sprintf(
			"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
			host, port, name, user, pass,
		)}
	}

	cfg := &Config{
		JoineryDBURLs:           dbURLs,
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
		ConfigFile:              getEnv("SCD_CONFIG_FILE", "/etc/scrolldaddy/dns.json"),
		LogLevel:                getEnv("SCD_LOG_LEVEL", "info"),
		LogFile:                 getEnv("SCD_LOG_FILE", "stdout"),
		APIKey:                  getEnv("SCD_API_KEY", ""),
		PeerURL:                 getEnv("SCD_PEER_URL", ""),
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
