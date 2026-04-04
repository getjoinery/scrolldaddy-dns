package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"scrolldaddy-dns/internal/db"
	"scrolldaddy-dns/internal/logger"
)

// ScheduledBlock holds the in-memory representation of a scheduled block and its rules.
type ScheduledBlock struct {
	BlockID          int64
	Name             string
	ScheduleStart    string   // "HH:MM"
	ScheduleEnd      string   // "HH:MM"
	ScheduleDays     []string // ["mon","tue","wed"]
	ScheduleTimezone *time.Location
	BlockKeys        []string        // filter/service keys with action=0 (block)
	AllowKeys        []string        // filter/service keys with action=1 (allow)
	CustomBlocked    map[string]bool // domain rules with action=0
	CustomAllowed    map[string]bool // domain rules with action=1
}

// DeviceInfo holds the in-memory representation of a device.
type DeviceInfo struct {
	DeviceID         int64
	ResolverUID      string
	PrimaryProfileID int64
	IsActive         bool
	Timezone         *time.Location
	ScheduledBlocks  []ScheduledBlock
}

// ProfileInfo holds the in-memory representation of a filtering profile.
type ProfileInfo struct {
	ProfileID         int64
	SafeSearch        bool
	SafeYouTube       bool
	EnabledCategories []string
	CustomBlocked     map[string]bool
	CustomAllowed     map[string]bool
}

// CacheStats holds statistics for the /stats endpoint.
type CacheStats struct {
	Devices             int
	Profiles            int
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
	profiles         map[int64]*ProfileInfo     // profile_id -> ProfileInfo
	blocklistDomains map[string]map[string]bool // category_key -> domain set (shared across profiles)

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
		profiles:         map[int64]*ProfileInfo{},
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

// GetProfile returns the ProfileInfo for a profile ID, or nil if not found.
func (c *Cache) GetProfile(profileID int64) *ProfileInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.profiles[profileID]
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
		Profiles:            len(c.profiles),
		BlocklistCategories: len(c.blocklistDomains),
		BlocklistDomains:    totalDomains,
		LastLightReload:     c.lastLightReload,
		LastFullReload:      c.lastFullReload,
		UptimeSeconds:       int64(time.Since(c.startTime).Seconds()),
	}
}

// LightReload reloads devices, profiles, filters, custom rules, and scheduled blocks from the DB.
// Does NOT reload blocklist domains (use FullReload for that).
func (c *Cache) LightReload(database *db.DB) error {
	deviceRows, err := database.LoadDevices()
	if err != nil {
		return fmt.Errorf("loading devices: %w", err)
	}

	filterMap, err := database.LoadFilters()
	if err != nil {
		return fmt.Errorf("loading filters: %w", err)
	}

	serviceMap, err := database.LoadServices()
	if err != nil {
		return fmt.Errorf("loading services: %w", err)
	}

	ruleMap, err := database.LoadRules()
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	// Load scheduled blocks and their rules
	blockRows, err := database.LoadScheduledBlocks()
	if err != nil {
		return fmt.Errorf("loading scheduled blocks: %w", err)
	}

	blockFilterRules, err := database.LoadScheduledBlockFilterRules()
	if err != nil {
		return fmt.Errorf("loading scheduled block filter rules: %w", err)
	}

	blockServiceRules, err := database.LoadScheduledBlockServiceRules()
	if err != nil {
		return fmt.Errorf("loading scheduled block service rules: %w", err)
	}

	blockDomainRules, err := database.LoadScheduledBlockDomainRules()
	if err != nil {
		return fmt.Errorf("loading scheduled block domain rules: %w", err)
	}

	// Build profile map (collect all referenced profile IDs first)
	profileIDs := map[int64]bool{}
	for _, d := range deviceRows {
		profileIDs[d.PrimaryProfileID] = true
	}

	newProfiles := make(map[int64]*ProfileInfo, len(profileIDs))
	for profileID := range profileIDs {
		pi := &ProfileInfo{
			ProfileID:     profileID,
			CustomBlocked: map[string]bool{},
			CustomAllowed: map[string]bool{},
		}
		if cats, ok := filterMap[profileID]; ok {
			pi.EnabledCategories = cats
		}
		if rules, ok := ruleMap[profileID]; ok {
			for _, r := range rules {
				domain := strings.ToLower(strings.TrimSpace(r.Hostname))
				if r.Action == 0 {
					pi.CustomBlocked[domain] = true
				} else {
					pi.CustomAllowed[domain] = true
				}
			}
		}
		// TODO(scaling): Same expansion issue as in the block service rules below —
		// each profile gets its own copy of the expanded service domain maps.
		if services, ok := serviceMap[profileID]; ok {
			for _, svcKey := range services {
				if domains, ok := ServiceDomains[svcKey]; ok {
					for _, domain := range domains {
						pi.CustomBlocked[strings.ToLower(domain)] = true
					}
				}
			}
		}
		newProfiles[profileID] = pi
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

	// Build scheduled blocks grouped by device ID
	blocksByDevice := map[int64][]ScheduledBlock{}
	for _, b := range blockRows {
		sb := ScheduledBlock{
			BlockID:       b.BlockID,
			Name:          b.Name,
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

	// Build device map, also setting SafeSearch/SafeYouTube on profile infos
	newDevices := make(map[string]*DeviceInfo, len(deviceRows))
	for _, d := range deviceRows {
		loc, err := time.LoadLocation(d.Timezone)
		if err != nil {
			logger.Warn("device %d: invalid timezone %q, using UTC", d.DeviceID, d.Timezone)
			loc = time.UTC
		}

		di := &DeviceInfo{
			DeviceID:         d.DeviceID,
			ResolverUID:      d.ResolverUID,
			PrimaryProfileID: d.PrimaryProfileID,
			IsActive:         d.IsActive,
			Timezone:         loc,
			ScheduledBlocks:  blocksByDevice[d.DeviceID],
		}

		// Set SafeSearch/SafeYouTube on the profile objects
		if pri, ok := newProfiles[d.PrimaryProfileID]; ok {
			if d.PrimarySafeSearch.Valid {
				pri.SafeSearch = d.PrimarySafeSearch.Bool
			}
			if d.PrimarySafeYouTube.Valid {
				pri.SafeYouTube = d.PrimarySafeYouTube.Bool
			}
		}

		newDevices[d.ResolverUID] = di
	}

	c.mu.Lock()
	c.devices = newDevices
	c.profiles = newProfiles
	c.lastLightReload = time.Now()
	c.mu.Unlock()

	totalBlocks := 0
	for _, blocks := range blocksByDevice {
		totalBlocks += len(blocks)
	}
	logger.Info("lightweight reload complete: %d devices, %d profiles, %d scheduled blocks", len(newDevices), len(newProfiles), totalBlocks)
	return nil
}

// FullReload reloads blocklist domains from the DB.
// Skips the expensive table scan if the blocklist version in stg_settings is unchanged.
func (c *Cache) FullReload(database *db.DB) error {
	currentVersion := database.GetBlocklistVersion()

	c.mu.RLock()
	lastVersion := c.lastBlocklistVersion
	c.mu.RUnlock()

	if currentVersion != "" && currentVersion == lastVersion {
		logger.Debug("blocklist data unchanged (version=%q), skipping full reload", currentVersion)
		return nil
	}

	newDomains, err := database.LoadBlocklistDomains()
	if err != nil {
		return fmt.Errorf("loading blocklist domains: %w", err)
	}

	totalDomains := 0
	for _, s := range newDomains {
		totalDomains += len(s)
	}

	c.mu.Lock()
	c.blocklistDomains = newDomains
	c.lastFullReload = time.Now()
	c.lastBlocklistVersion = currentVersion
	c.mu.Unlock()

	logger.Info("full reload complete: %d blocklist domains across %d categories", totalDomains, len(newDomains))
	return nil
}

// LoadForTest directly loads data into the cache for unit testing.
func (c *Cache) LoadForTest(devices map[string]*DeviceInfo, profiles map[int64]*ProfileInfo, blocklists map[string]map[string]bool) {
	if devices == nil {
		devices = map[string]*DeviceInfo{}
	}
	if profiles == nil {
		profiles = map[int64]*ProfileInfo{}
	}
	if blocklists == nil {
		blocklists = map[string]map[string]bool{}
	}
	c.mu.Lock()
	c.devices = devices
	c.profiles = profiles
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
