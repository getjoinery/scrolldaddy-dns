package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"scrolldaddy-dns/internal/db"
	"scrolldaddy-dns/internal/logger"
)

// ScheduledBlock holds the in-memory representation of a block (scheduled or always-on)
// and its rules. Always-on blocks (IsAlwaysOn=true) have no schedule and are treated
// as always-active by the resolver.
type ScheduledBlock struct {
	BlockID          int64
	Name             string
	IsAlwaysOn       bool
	ScheduleStart    string   // "HH:MM" (empty if IsAlwaysOn)
	ScheduleEnd      string   // "HH:MM" (empty if IsAlwaysOn)
	ScheduleDays     []string // ["mon","tue","wed"] (nil if IsAlwaysOn)
	ScheduleTimezone *time.Location
	BlockKeys        []string        // filter/service keys with action=0 (block)
	AllowKeys        []string        // filter/service keys with action=1 (allow)
	CustomBlocked    map[string]bool // domain rules with action=0
	CustomAllowed    map[string]bool // domain rules with action=1
}

// DeviceInfo holds the in-memory representation of a device.
type DeviceInfo struct {
	DeviceID        int64
	ResolverUID     string
	IsActive        bool
	LogQueries      bool
	Timezone        *time.Location
	ScheduledBlocks []ScheduledBlock
}

// CacheStats holds statistics for the /stats endpoint.
type CacheStats struct {
	Devices             int
	BlocklistCategories int
	BlocklistDomains    int
	LastLightReload     time.Time
	LastFullReload      time.Time
	UptimeSeconds       int64
}

// Cache is the in-memory store for all DNS resolution data.
// DNS query handlers hold a read lock; reloads swap pointers under a brief write lock.
type Cache struct {
	mu sync.RWMutex

	devices          map[string]*DeviceInfo     // resolver_uid -> DeviceInfo
	blocklistDomains map[string]map[string]bool // category_key -> domain set (shared across devices)

	lastLightReload      time.Time
	lastFullReload       time.Time
	startTime            time.Time
	lastBlocklistVersion string // last scrolldaddy_blocklist_version seen

	lsMu     sync.RWMutex
	lastSeen map[string]time.Time // resolver_uid -> last query time
}

// New creates an empty cache.
func New() *Cache {
	return &Cache{
		devices:          map[string]*DeviceInfo{},
		blocklistDomains: map[string]map[string]bool{},
		startTime:        time.Now(),
		lastSeen:         map[string]time.Time{},
	}
}

// RecordQuery records the current time as the last-seen time for the given resolver UID.
func (c *Cache) RecordQuery(uid string) {
	c.lsMu.Lock()
	c.lastSeen[uid] = time.Now()
	c.lsMu.Unlock()
}

// GetLastSeen returns the last time a query was seen for the given resolver UID.
// Returns zero time and false if the UID has never been seen since startup.
func (c *Cache) GetLastSeen(uid string) (time.Time, bool) {
	c.lsMu.RLock()
	t, ok := c.lastSeen[uid]
	c.lsMu.RUnlock()
	return t, ok
}

// GetDevice returns the DeviceInfo for a resolver UID, or nil if not found.
func (c *Cache) GetDevice(resolverUID string) *DeviceInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.devices[resolverUID]
}

// IsDomainBlocked checks if the domain (or any parent) is in the given category's blocklist.
func (c *Cache) IsDomainBlocked(domain, categoryKey string) bool {
	c.mu.RLock()
	domainSet, ok := c.blocklistDomains[categoryKey]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	return IsDomainInSet(domain, domainSet)
}

// Stats returns a snapshot of cache statistics.
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalDomains := 0
	for _, s := range c.blocklistDomains {
		totalDomains += len(s)
	}
	return CacheStats{
		Devices:             len(c.devices),
		BlocklistCategories: len(c.blocklistDomains),
		BlocklistDomains:    totalDomains,
		LastLightReload:     c.lastLightReload,
		LastFullReload:      c.lastFullReload,
		UptimeSeconds:       int64(time.Since(c.startTime).Seconds()),
	}
}

// LightReload reloads devices and all scheduled/always-on blocks from all DBs,
// unioning them into the in-memory cache. Device UIDs are globally unique across
// deployments, so the union is collision-free. Each DB's device IDs are scoped
// to that DB to avoid cross-deployment integer collisions.
func (c *Cache) LightReload(databases []*db.DB) error {
	newDevices := make(map[string]*DeviceInfo)
	totalBlocks := 0
	for _, database := range databases {
		partial, blocks, err := loadDevicesFromDB(database)
		if err != nil {
			return err
		}
		for uid, di := range partial {
			newDevices[uid] = di
		}
		totalBlocks += blocks
	}

	c.mu.Lock()
	c.devices = newDevices
	c.lastLightReload = time.Now()
	c.mu.Unlock()

	logger.Info("lightweight reload complete: %d devices, %d scheduled blocks", len(newDevices), totalBlocks)
	return nil
}

// loadDevicesFromDB loads devices and their scheduled blocks from a single DB.
// Returns (uid→DeviceInfo, totalBlocks, error).
// Device IDs stay scoped to this DB — callers merge by UID, not by device ID.
func loadDevicesFromDB(database *db.DB) (map[string]*DeviceInfo, int, error) {
	deviceRows, err := database.LoadDevices()
	if err != nil {
		return nil, 0, fmt.Errorf("loading devices: %w", err)
	}

	blockRows, err := database.LoadScheduledBlocks()
	if err != nil {
		return nil, 0, fmt.Errorf("loading scheduled blocks: %w", err)
	}

	blockFilterRules, err := database.LoadScheduledBlockFilterRules()
	if err != nil {
		return nil, 0, fmt.Errorf("loading scheduled block filter rules: %w", err)
	}

	blockServiceRules, err := database.LoadScheduledBlockServiceRules()
	if err != nil {
		return nil, 0, fmt.Errorf("loading scheduled block service rules: %w", err)
	}

	blockDomainRules, err := database.LoadScheduledBlockDomainRules()
	if err != nil {
		return nil, 0, fmt.Errorf("loading scheduled block domain rules: %w", err)
	}

	// Index scheduled block rules by block ID
	blockFiltersByID := map[int64][]*db.ScheduledBlockRuleRow{}
	for _, r := range blockFilterRules {
		blockFiltersByID[r.BlockID] = append(blockFiltersByID[r.BlockID], r)
	}
	blockServicesByID := map[int64][]*db.ScheduledBlockRuleRow{}
	for _, r := range blockServiceRules {
		blockServicesByID[r.BlockID] = append(blockServicesByID[r.BlockID], r)
	}
	blockDomainsByID := map[int64][]*db.ScheduledBlockRuleRow{}
	for _, r := range blockDomainRules {
		blockDomainsByID[r.BlockID] = append(blockDomainsByID[r.BlockID], r)
	}

	// Build scheduled blocks grouped by device ID (local to this DB)
	blocksByDevice := map[int64][]ScheduledBlock{}
	for _, b := range blockRows {
		sb := ScheduledBlock{
			BlockID:       b.BlockID,
			Name:          b.Name,
			IsAlwaysOn:    b.IsAlwaysOn,
			ScheduleStart: b.ScheduleStart.String,
			ScheduleEnd:   b.ScheduleEnd.String,
			ScheduleDays:  db.ParseScheduleDays(b.ScheduleDays),
			CustomBlocked: map[string]bool{},
			CustomAllowed: map[string]bool{},
		}

		// Parse schedule timezone
		if b.ScheduleTimezone.Valid && b.ScheduleTimezone.String != "" {
			loc, err := time.LoadLocation(b.ScheduleTimezone.String)
			if err != nil {
				logger.Warn("scheduled block %d: invalid timezone %q, using UTC", b.BlockID, b.ScheduleTimezone.String)
				loc = time.UTC
			}
			sb.ScheduleTimezone = loc
		}
		// Note: nil ScheduleTimezone will fall back to device timezone in resolver

		// Partition filter rules by action
		for _, r := range blockFiltersByID[b.BlockID] {
			if r.Action == 0 {
				sb.BlockKeys = append(sb.BlockKeys, r.Key)
			} else {
				sb.AllowKeys = append(sb.AllowKeys, r.Key)
			}
		}

		// TODO(scaling): Service domain expansion duplicates domain sets per profile/block.
		// At large user counts, consider storing ServiceDomains as a shared cache map
		// (like blocklistDomains) and resolving service keys at query time rather than
		// expanding them into per-profile/per-block CustomBlocked maps at build time.
		// This would make per-user memory cost O(1) for services instead of O(domains-per-service).
		// See: internal/cache/services.go for the domain lists.

		// Partition service rules by action; also expand block services to domains
		for _, r := range blockServicesByID[b.BlockID] {
			if r.Action == 0 {
				sb.BlockKeys = append(sb.BlockKeys, r.Key)
				// Expand service to its domains and add to CustomBlocked
				if domains, ok := ServiceDomains[r.Key]; ok {
					for _, domain := range domains {
						sb.CustomBlocked[strings.ToLower(domain)] = true
					}
				}
			} else {
				sb.AllowKeys = append(sb.AllowKeys, r.Key)
				// Expand service to its domains and add to CustomAllowed
				// so it overrides any base-profile service blocks for those domains
				if domains, ok := ServiceDomains[r.Key]; ok {
					for _, domain := range domains {
						sb.CustomAllowed[strings.ToLower(domain)] = true
					}
				}
			}
		}

		// Partition domain rules by action
		for _, r := range blockDomainsByID[b.BlockID] {
			domain := strings.ToLower(strings.TrimSpace(r.Key))
			if r.Action == 0 {
				sb.CustomBlocked[domain] = true
			} else {
				sb.CustomAllowed[domain] = true
			}
		}

		blocksByDevice[b.DeviceID] = append(blocksByDevice[b.DeviceID], sb)
	}

	// Build device map keyed by resolver UID (globally unique)
	devices := make(map[string]*DeviceInfo, len(deviceRows))
	for _, d := range deviceRows {
		loc, err := time.LoadLocation(d.Timezone)
		if err != nil {
			logger.Warn("device %d: invalid timezone %q, using UTC", d.DeviceID, d.Timezone)
			loc = time.UTC
		}
		devices[d.ResolverUID] = &DeviceInfo{
			DeviceID:        d.DeviceID,
			ResolverUID:     d.ResolverUID,
			IsActive:        d.IsActive,
			LogQueries:      d.LogQueries,
			Timezone:        loc,
			ScheduledBlocks: blocksByDevice[d.DeviceID],
		}
	}

	totalBlocks := 0
	for _, blocks := range blocksByDevice {
		totalBlocks += len(blocks)
	}
	return devices, totalBlocks, nil
}

// FullReload reloads blocklist domains from all DBs, unioning them.
// Skips the expensive table scans if all DB blocklist versions are unchanged.
// Both deployments share the same blocklist source, so the union is typically
// a no-op (identical data), but merging is correct even when they diverge.
func (c *Cache) FullReload(databases []*db.DB) error {
	// Collect versions from each DB and build a composite key.
	versions := make([]string, len(databases))
	allHaveVersion := true
	for i, database := range databases {
		versions[i] = database.GetBlocklistVersion()
		if versions[i] == "" {
			allHaveVersion = false
		}
	}
	compositeVersion := strings.Join(versions, "|")

	c.mu.RLock()
	lastVersion := c.lastBlocklistVersion
	c.mu.RUnlock()

	if allHaveVersion && compositeVersion == lastVersion {
		logger.Debug("blocklist data unchanged (version=%q), skipping full reload", compositeVersion)
		return nil
	}

	// Load and union domains from all DBs.
	mergedDomains := map[string]map[string]bool{}
	for _, database := range databases {
		newDomains, err := database.LoadBlocklistDomains()
		if err != nil {
			return fmt.Errorf("loading blocklist domains: %w", err)
		}
		for category, domains := range newDomains {
			if mergedDomains[category] == nil {
				mergedDomains[category] = map[string]bool{}
			}
			for domain, v := range domains {
				mergedDomains[category][domain] = v
			}
		}
	}

	totalDomains := 0
	for _, s := range mergedDomains {
		totalDomains += len(s)
	}

	c.mu.Lock()
	c.blocklistDomains = mergedDomains
	c.lastFullReload = time.Now()
	c.lastBlocklistVersion = compositeVersion
	c.mu.Unlock()

	logger.Info("full reload complete: %d blocklist domains across %d categories", totalDomains, len(mergedDomains))
	return nil
}

// LoadForTest directly loads data into the cache for unit testing.
func (c *Cache) LoadForTest(devices map[string]*DeviceInfo, blocklists map[string]map[string]bool) {
	if devices == nil {
		devices = map[string]*DeviceInfo{}
	}
	if blocklists == nil {
		blocklists = map[string]map[string]bool{}
	}
	c.mu.Lock()
	c.devices = devices
	c.blocklistDomains = blocklists
	c.mu.Unlock()
}

// IsDomainInSet checks if the domain or any parent domain (stopping before TLD) is in the set.
// Exported for use in tests and by the cache.
func IsDomainInSet(domain string, domainSet map[string]bool) bool {
	if domainSet[domain] {
		return true
	}
	parts := strings.Split(domain, ".")
	// Walk parent domains: start at index 1 (skip first label), stop before TLD-only
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if domainSet[parent] {
			return true
		}
	}
	return false
}
