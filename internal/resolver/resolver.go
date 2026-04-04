package resolver

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"scrolldaddy-dns/internal/cache"
	"scrolldaddy-dns/internal/dnscache"
	"scrolldaddy-dns/internal/logger"
	"scrolldaddy-dns/internal/querylog"
	"scrolldaddy-dns/internal/upstream"
)

// Result codes for ResolveResult.
const (
	ResultBlocked   = "BLOCKED"
	ResultForwarded = "FORWARDED"
	ResultRefused   = "REFUSED"
	ResultServFail  = "SERVFAIL"
	ResultFormErr   = "FORMERR"
)

// Reason codes for ResolveResult.
const (
	ReasonUnknownDevice    = "unknown_device"
	ReasonInactiveDevice   = "inactive_device"
	ReasonProfileNotFound  = "profile_not_found"
	ReasonNoQuestion       = "no_question"
	ReasonCustomBlockRule  = "custom_block_rule"
	ReasonCustomAllowRule  = "custom_allow_rule"
	ReasonCategoryBlocklist = "category_blocklist"
	ReasonSafeSearchRewrite = "safesearch_rewrite"
	ReasonSafeYouTubeRewrite = "safeyoutube_rewrite"
	ReasonNotBlocked       = "not_blocked"
	ReasonUpstreamFailed   = "upstream_failed"
)

// ResolveResult contains both the DNS response and diagnostic information.
type ResolveResult struct {
	DNSResponse          *dns.Msg
	Result               string
	Reason               string
	Category             string   // set when Reason == ReasonCategoryBlocklist
	MatchedRule          string   // set when a specific rule matched
	ActiveProfileID      int64
	ActiveScheduledBlocks []string // names of currently active scheduled blocks
}

// Resolver handles DNS resolution with per-device filtering.
type Resolver struct {
	cache             *cache.Cache
	dnsCache          *dnscache.Cache
	queryLog          *querylog.Logger
	upstreamPrimary   string
	upstreamSecondary string

	// passthrough is set to true during startup when the cache is not yet
	// loaded (fail_open mode). All queries are forwarded upstream without
	// filtering until the cache is ready.
	passthrough atomic.Bool
}

// SafeSearch CNAME rewrites keyed by query domain.
var safeSearchRewrites = map[string]string{
	"www.google.com":     "forcesafesearch.google.com",
	"www.google.co.uk":   "forcesafesearch.google.com",
	"www.google.ca":      "forcesafesearch.google.com",
	"www.google.com.au":  "forcesafesearch.google.com",
	"www.google.de":      "forcesafesearch.google.com",
	"www.google.fr":      "forcesafesearch.google.com",
	"www.google.es":      "forcesafesearch.google.com",
	"www.google.it":      "forcesafesearch.google.com",
	"www.google.nl":      "forcesafesearch.google.com",
	"www.google.co.in":   "forcesafesearch.google.com",
	"www.google.co.jp":   "forcesafesearch.google.com",
	"www.google.com.br":  "forcesafesearch.google.com",
	"www.bing.com":       "strict.bing.com",
	"duckduckgo.com":     "safe.duckduckgo.com",
	"www.duckduckgo.com": "safe.duckduckgo.com",
}

// SafeYouTube CNAME rewrites.
var safeYouTubeRewrites = map[string]string{
	"www.youtube.com":         "restrict.youtube.com",
	"youtube.com":             "restrict.youtube.com",
	"m.youtube.com":           "restrict.youtube.com",
	"youtubei.googleapis.com": "restrict.youtube.com",
}

// New creates a Resolver backed by the given cache and upstream servers.
// dc and ql may be nil to disable DNS response caching or query logging.
func New(c *cache.Cache, dc *dnscache.Cache, ql *querylog.Logger, primary, secondary string) *Resolver {
	return &Resolver{
		cache:             c,
		dnsCache:          dc,
		queryLog:          ql,
		upstreamPrimary:   primary,
		upstreamSecondary: secondary,
	}
}

// ForwardDirect forwards a query to upstream without any cache or filtering.
// Used as a last-resort fallback in panic recovery paths.
func (r *Resolver) ForwardDirect(query *dns.Msg) *dns.Msg {
	resp, err := upstream.Forward(query, r.upstreamPrimary, r.upstreamSecondary)
	if err != nil {
		return nil
	}
	return resp
}

// SetPassthrough enables or disables passthrough mode. When enabled, all
// queries are forwarded to upstream without any filtering. Used during
// startup when the cache is not yet loaded (fail_open mode).
func (r *Resolver) SetPassthrough(v bool) {
	r.passthrough.Store(v)
	if v {
		logger.Warn("passthrough mode ACTIVE — all queries forwarded unfiltered")
	} else {
		logger.Info("passthrough mode disabled — filtering active")
	}
}

// InPassthrough reports whether passthrough mode is currently active.
func (r *Resolver) InPassthrough() bool {
	return r.passthrough.Load()
}

// forwardWithCache checks the DNS response cache before forwarding to upstream.
// Returns the response, whether it was a cache hit, and any error.
func (r *Resolver) forwardWithCache(query *dns.Msg) (*dns.Msg, bool, error) {
	if r.dnsCache != nil {
		if cached := r.dnsCache.Get(query); cached != nil {
			return cached, true, nil
		}
	}
	resp, err := upstream.Forward(query, r.upstreamPrimary, r.upstreamSecondary)
	if err != nil {
		return nil, false, err
	}
	if r.dnsCache != nil {
		r.dnsCache.Set(query, resp)
	}
	return resp, false, nil
}

// Resolve processes a DNS query for the given resolver UID and returns a ResolveResult.
func (r *Resolver) Resolve(resolverUID string, query *dns.Msg) *ResolveResult {
	// 0. Passthrough mode: cache not yet loaded (fail_open startup).
	//    Forward all queries unfiltered until the cache is ready.
	if r.passthrough.Load() {
		resp, _, err := r.forwardWithCache(query)
		if err != nil {
			return &ResolveResult{
				DNSResponse: servFail(query),
				Result:      ResultServFail,
				Reason:      ReasonUpstreamFailed,
			}
		}
		return &ResolveResult{
			DNSResponse: resp,
			Result:      ResultForwarded,
			Reason:      "passthrough",
		}
	}

	// 1. Device lookup
	device := r.cache.GetDevice(resolverUID)
	if device == nil {
		return r.refused(query, ReasonUnknownDevice)
	}
	if !device.IsActive {
		return r.refused(query, ReasonInactiveDevice)
	}

	// 2. Load base profile
	activeProfileID := device.PrimaryProfileID
	profile := r.cache.GetProfile(activeProfileID)
	if profile == nil {
		logger.Warn("device %d: profile %d not found in cache", device.DeviceID, activeProfileID)
		resp := new(dns.Msg)
		resp.SetRcode(query, dns.RcodeServerFailure)
		resp.RecursionAvailable = true
		return &ResolveResult{
			DNSResponse:     resp,
			Result:          ResultServFail,
			Reason:          ReasonProfileNotFound,
			ActiveProfileID: activeProfileID,
		}
	}

	// Build effective filtering sets starting from the base profile
	effectiveCategories := make(map[string]bool, len(profile.EnabledCategories))
	for _, cat := range profile.EnabledCategories {
		effectiveCategories[cat] = true
	}
	effectiveCustomBlocked := make(map[string]bool, len(profile.CustomBlocked))
	for k, v := range profile.CustomBlocked {
		effectiveCustomBlocked[k] = v
	}
	effectiveCustomAllowed := make(map[string]bool, len(profile.CustomAllowed))
	for k, v := range profile.CustomAllowed {
		effectiveCustomAllowed[k] = v
	}

	// Evaluate scheduled blocks and merge active ones
	allowKeysToRemove := map[string]bool{}
	var activeBlockNames []string

	for i := range device.ScheduledBlocks {
		block := &device.ScheduledBlocks[i]
		if !isBlockActive(block, device.Timezone) {
			continue
		}
		activeBlockNames = append(activeBlockNames, block.Name)

		// Merge block keys (categories to block)
		for _, key := range block.BlockKeys {
			effectiveCategories[key] = true
		}

		// Track allow keys (categories to remove)
		for _, key := range block.AllowKeys {
			allowKeysToRemove[key] = true
		}

		// Merge custom domain rules
		for domain := range block.CustomBlocked {
			effectiveCustomBlocked[domain] = true
		}
		for domain := range block.CustomAllowed {
			effectiveCustomAllowed[domain] = true
		}
	}

	// Remove allowed categories
	for key := range allowKeysToRemove {
		delete(effectiveCategories, key)
	}

	// Convert effective categories back to slice
	effectiveCategorySlice := make([]string, 0, len(effectiveCategories))
	for cat := range effectiveCategories {
		effectiveCategorySlice = append(effectiveCategorySlice, cat)
	}

	base := &ResolveResult{
		ActiveProfileID:       activeProfileID,
		ActiveScheduledBlocks: activeBlockNames,
	}

	// 3. Extract query domain
	if len(query.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(query, dns.RcodeFormatError)
		resp.RecursionAvailable = true
		base.DNSResponse = resp
		base.Result = ResultFormErr
		base.Reason = ReasonNoQuestion
		return base
	}
	domain := strings.ToLower(strings.TrimSuffix(query.Question[0].Name, "."))

	// 4. Custom allow rules bypass all blocking
	if matched := matchDomain(domain, effectiveCustomAllowed); matched != "" {
		resp, cached, err := r.forwardWithCache(query)
		if err != nil {
			base.DNSResponse = servFail(query)
			base.Result = ResultServFail
			base.Reason = ReasonUpstreamFailed
			return base
		}
		base.DNSResponse = resp
		base.Result = ResultForwarded
		base.Reason = ReasonCustomAllowRule
		base.MatchedRule = matched
		r.recordQuery(device, resolverUID, domain, query, base, cached)
		return base
	}

	// 5. SafeSearch / SafeYouTube CNAME rewrites
	if profile.SafeSearch {
		if target, ok := safeSearchRewrites[domain]; ok {
			base.DNSResponse = r.buildCNAMEResponse(query, domain, target)
			base.Result = ResultForwarded
			base.Reason = ReasonSafeSearchRewrite
			r.recordQuery(device, resolverUID, domain, query, base, false)
			return base
		}
	}
	if profile.SafeYouTube {
		if target, ok := safeYouTubeRewrites[domain]; ok {
			base.DNSResponse = r.buildCNAMEResponse(query, domain, target)
			base.Result = ResultForwarded
			base.Reason = ReasonSafeYouTubeRewrite
			r.recordQuery(device, resolverUID, domain, query, base, false)
			return base
		}
	}

	// 6a. Custom block rules
	if matched := matchDomain(domain, effectiveCustomBlocked); matched != "" {
		resp := new(dns.Msg)
		resp.SetRcode(query, dns.RcodeNameError)
		resp.RecursionAvailable = true
		base.DNSResponse = resp
		base.Result = ResultBlocked
		base.Reason = ReasonCustomBlockRule
		base.MatchedRule = matched
		r.recordQuery(device, resolverUID, domain, query, base, false)
		return base
	}

	// 6b. Category blocklists (first match wins)
	for _, cat := range effectiveCategorySlice {
		if r.cache.IsDomainBlocked(domain, cat) {
			resp := new(dns.Msg)
			resp.SetRcode(query, dns.RcodeNameError)
			resp.RecursionAvailable = true
			base.DNSResponse = resp
			base.Result = ResultBlocked
			base.Reason = ReasonCategoryBlocklist
			base.Category = cat
			r.recordQuery(device, resolverUID, domain, query, base, false)
			return base
		}
	}

	// 7. Forward to upstream (via cache)
	resp, cached, err := r.forwardWithCache(query)
	if err != nil {
		base.DNSResponse = servFail(query)
		base.Result = ResultServFail
		base.Reason = ReasonUpstreamFailed
		return base
	}
	logger.Debug("uid=%s q=%s FORWARDED", resolverUID, domain)
	base.DNSResponse = resp
	base.Result = ResultForwarded
	base.Reason = ReasonNotBlocked
	r.recordQuery(device, resolverUID, domain, query, base, cached)
	return base
}

// recordQuery sends a query log entry if logging is enabled for the device.
func (r *Resolver) recordQuery(device *cache.DeviceInfo, uid, domain string, query *dns.Msg, result *ResolveResult, cached bool) {
	if !device.LogQueries || r.queryLog == nil {
		return
	}
	qtype := "UNKNOWN"
	if len(query.Question) > 0 {
		if s, ok := dns.TypeToString[query.Question[0].Qtype]; ok {
			qtype = s
		}
	}
	r.queryLog.Record(&querylog.Entry{
		ResolverUID: uid,
		Time:        time.Now(),
		Domain:      domain,
		QType:       qtype,
		Result:      result.Result,
		Reason:      result.Reason,
		Category:    result.Category,
		Cached:      cached,
	})
}

// isBlockActive returns true if the given scheduled block's schedule is currently active.
// loc is the device's timezone, used as fallback when the block has no explicit timezone.
func isBlockActive(block *cache.ScheduledBlock, loc *time.Location) bool {
	if len(block.ScheduleDays) == 0 || block.ScheduleStart == "" || block.ScheduleEnd == "" {
		return false
	}

	tzLoc := block.ScheduleTimezone
	if tzLoc == nil {
		tzLoc = loc
	}
	if tzLoc == nil {
		tzLoc = time.UTC
	}

	now := time.Now().In(tzLoc)
	todayAbbr := strings.ToLower(now.Weekday().String()[:3])
	yesterday := now.AddDate(0, 0, -1)
	yesterdayAbbr := strings.ToLower(yesterday.Weekday().String()[:3])

	startH, startM := parseHHMM(block.ScheduleStart)
	endH, endM := parseHHMM(block.ScheduleEnd)
	currentMins := now.Hour()*60 + now.Minute()
	startMins := startH*60 + startM
	endMins := endH*60 + endM

	if endMins < startMins {
		// Overnight schedule: e.g. 22:00-06:00
		// Active if today is scheduled AND time >= start
		todayMatch := false
		for _, d := range block.ScheduleDays {
			if d == todayAbbr {
				todayMatch = true
				break
			}
		}
		if todayMatch && currentMins >= startMins {
			return true
		}

		// Also active if yesterday was scheduled AND time < end (spillover)
		yesterdayMatch := false
		for _, d := range block.ScheduleDays {
			if d == yesterdayAbbr {
				yesterdayMatch = true
				break
			}
		}
		if yesterdayMatch && currentMins < endMins {
			return true
		}

		return false
	}

	// Normal (same-day) schedule
	todayMatch := false
	for _, d := range block.ScheduleDays {
		if d == todayAbbr {
			todayMatch = true
			break
		}
	}
	if !todayMatch {
		return false
	}

	return currentMins >= startMins && currentMins < endMins
}

// parseHHMM splits "HH:MM" into hours and minutes.
func parseHHMM(s string) (int, int) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, 0
	}
	h, _ := strconv.Atoi(parts[0])
	m, _ := strconv.Atoi(parts[1])
	return h, m
}

// matchDomain checks if domain or any parent (stopping before TLD) is in domainSet.
// Returns the matched rule string, or "" if no match.
func matchDomain(domain string, domainSet map[string]bool) string {
	if domainSet[domain] {
		return domain
	}
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if domainSet[parent] {
			return parent
		}
	}
	return ""
}

// buildCNAMEResponse constructs a CNAME response and resolves the target via upstream.
func (r *Resolver) buildCNAMEResponse(query *dns.Msg, domain, target string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.RecursionAvailable = true

	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: dns.Fqdn(target),
	})

	// Resolve the CNAME target to get A/AAAA records (via cache)
	targetQuery := new(dns.Msg)
	targetQuery.SetQuestion(dns.Fqdn(target), query.Question[0].Qtype)
	targetResp, _, err := r.forwardWithCache(targetQuery)
	if err == nil && targetResp != nil {
		resp.Answer = append(resp.Answer, targetResp.Answer...)
	}

	return resp
}

func (r *Resolver) refused(query *dns.Msg, reason string) *ResolveResult {
	resp := new(dns.Msg)
	resp.SetRcode(query, dns.RcodeRefused)
	resp.RecursionAvailable = true
	return &ResolveResult{DNSResponse: resp, Result: ResultRefused, Reason: reason}
}

func servFail(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(query, dns.RcodeServerFailure)
	resp.RecursionAvailable = true
	return resp
}

// IsBlockActive is exported for testing.
var IsBlockActive = isBlockActive
