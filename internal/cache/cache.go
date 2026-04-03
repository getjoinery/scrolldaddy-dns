package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"scrolldaddy-dns/internal/db"
	"scrolldaddy-dns/internal/logger"
)

// DeviceInfo holds the in-memory representation of a device.
type DeviceInfo struct {
	DeviceID           int64
	ResolverUID        string
	PrimaryProfileID   int64
	SecondaryProfileID int64 // 0 if no secondary profile
	IsActive           bool
	Timezone           *time.Location

	// Schedule (evaluated against secondary profile's schedule fields)
	ScheduleStart    string   // "HH:MM"
	ScheduleEnd      string   // "HH:MM"
	ScheduleDays     []string // ["mon","tue","wed"]
	ScheduleTimezone *time.Location
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

	devices          map[string]*DeviceInfo    // resolver_uid → DeviceInfo
	profiles         map[int64]*ProfileInfo    // profile_id → ProfileInfo
	blocklistDomains map[string]map[string]bool // category_key → domain set (shared across profiles)

	lastLightReload time.Time
	lastFullReload  time.Time
	startTime       time.Time
}

// New creates an empty cache.
func New() *Cache {
	return &Cache{
		devices:          map[string]*DeviceInfo{},
		profiles:         map[int64]*ProfileInfo{},
		blocklistDomains: map[string]map[string]bool{},
		startTime:        time.Now(),
	}
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

// LightReload reloads devices, profiles, filters, and custom rules from the DB.
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

	ruleMap, err := database.LoadRules()
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	// Build profile map (collect all referenced profile IDs first)
	profileIDs := map[int64]bool{}
	for _, d := range deviceRows {
		profileIDs[d.PrimaryProfileID] = true
		if d.SecondaryProfileID.Valid {
			profileIDs[d.SecondaryProfileID.Int64] = true
		}
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
		newProfiles[profileID] = pi
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
		}

		if d.SecondaryProfileID.Valid {
			di.SecondaryProfileID = d.SecondaryProfileID.Int64
			di.ScheduleStart = d.ScheduleStart.String
			di.ScheduleEnd = d.ScheduleEnd.String
			di.ScheduleDays = db.ParseScheduleDays(d.ScheduleDays)

			if d.ScheduleTimezone.Valid && d.ScheduleTimezone.String != "" {
				schedLoc, err := time.LoadLocation(d.ScheduleTimezone.String)
				if err != nil {
					logger.Warn("device %d: invalid schedule timezone %q, using UTC", d.DeviceID, d.ScheduleTimezone.String)
					schedLoc = time.UTC
				}
				di.ScheduleTimezone = schedLoc
			} else {
				di.ScheduleTimezone = loc
			}
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
		if di.SecondaryProfileID != 0 {
			if sec, ok := newProfiles[di.SecondaryProfileID]; ok {
				if d.SecondarySafeSearch.Valid {
					sec.SafeSearch = d.SecondarySafeSearch.Bool
				}
				if d.SecondarySafeYouTube.Valid {
					sec.SafeYouTube = d.SecondarySafeYouTube.Bool
				}
			}
		}

		newDevices[d.ResolverUID] = di
	}

	c.mu.Lock()
	c.devices = newDevices
	c.profiles = newProfiles
	c.lastLightReload = time.Now()
	c.mu.Unlock()

	logger.Info("lightweight reload complete: %d devices, %d profiles", len(newDevices), len(newProfiles))
	return nil
}

// FullReload reloads blocklist domains from the DB.
func (c *Cache) FullReload(database *db.DB) error {
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
