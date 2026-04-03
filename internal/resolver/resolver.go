package resolver

import (
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"scrolldaddy-dns/internal/cache"
	"scrolldaddy-dns/internal/logger"
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
	DNSResponse     *dns.Msg
	Result          string
	Reason          string
	Category        string // set when Reason == ReasonCategoryBlocklist
	MatchedRule     string // set when a specific rule matched
	ActiveProfileID int64
	ProfileType     string // "primary" or "secondary"
	ScheduleActive  bool
}

// Resolver handles DNS resolution with per-device filtering.
type Resolver struct {
	cache             *cache.Cache
	upstreamPrimary   string
	upstreamSecondary string
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
func New(c *cache.Cache, primary, secondary string) *Resolver {
	return &Resolver{
		cache:             c,
		upstreamPrimary:   primary,
		upstreamSecondary: secondary,
	}
}

// Resolve processes a DNS query for the given resolver UID and returns a ResolveResult.
func (r *Resolver) Resolve(resolverUID string, query *dns.Msg) *ResolveResult {
	// 1. Device lookup
	device := r.cache.GetDevice(resolverUID)
	if device == nil {
		return r.refused(query, ReasonUnknownDevice)
	}
	if !device.IsActive {
		return r.refused(query, ReasonInactiveDevice)
	}

	// 2. Determine active profile
	activeProfileID := device.PrimaryProfileID
	profileType := "primary"
	scheduleActive := false

	if device.SecondaryProfileID != 0 && isScheduleActive(device) {
		activeProfileID = device.SecondaryProfileID
		profileType = "secondary"
		scheduleActive = true
	}

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
			ProfileType:     profileType,
			ScheduleActive:  scheduleActive,
		}
	}

	base := &ResolveResult{
		ActiveProfileID: activeProfileID,
		ProfileType:     profileType,
		ScheduleActive:  scheduleActive,
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
	if matched := matchDomain(domain, profile.CustomAllowed); matched != "" {
		resp, err := upstream.Forward(query, r.upstreamPrimary, r.upstreamSecondary)
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
		return base
	}

	// 5. SafeSearch / SafeYouTube CNAME rewrites
	if profile.SafeSearch {
		if target, ok := safeSearchRewrites[domain]; ok {
			base.DNSResponse = r.buildCNAMEResponse(query, domain, target)
			base.Result = ResultForwarded
			base.Reason = ReasonSafeSearchRewrite
			return base
		}
	}
	if profile.SafeYouTube {
		if target, ok := safeYouTubeRewrites[domain]; ok {
			base.DNSResponse = r.buildCNAMEResponse(query, domain, target)
			base.Result = ResultForwarded
			base.Reason = ReasonSafeYouTubeRewrite
			return base
		}
	}

	// 6a. Custom block rules
	if matched := matchDomain(domain, profile.CustomBlocked); matched != "" {
		resp := new(dns.Msg)
		resp.SetRcode(query, dns.RcodeNameError)
		resp.RecursionAvailable = true
		base.DNSResponse = resp
		base.Result = ResultBlocked
		base.Reason = ReasonCustomBlockRule
		base.MatchedRule = matched
		return base
	}

	// 6b. Category blocklists (first match wins)
	for _, cat := range profile.EnabledCategories {
		if r.cache.IsDomainBlocked(domain, cat) {
			resp := new(dns.Msg)
			resp.SetRcode(query, dns.RcodeNameError)
			resp.RecursionAvailable = true
			base.DNSResponse = resp
			base.Result = ResultBlocked
			base.Reason = ReasonCategoryBlocklist
			base.Category = cat
			return base
		}
	}

	// 7. Forward to upstream
	resp, err := upstream.Forward(query, r.upstreamPrimary, r.upstreamSecondary)
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
	return base
}

// isScheduleActive returns true if the device's secondary profile schedule is currently active.
func isScheduleActive(device *cache.DeviceInfo) bool {
	if len(device.ScheduleDays) == 0 || device.ScheduleStart == "" || device.ScheduleEnd == "" {
		return false
	}

	loc := device.ScheduleTimezone
	if loc == nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)
	// "mon", "tue", etc.
	dayAbbr := strings.ToLower(now.Weekday().String()[:3])

	dayMatch := false
	for _, d := range device.ScheduleDays {
		if d == dayAbbr {
			dayMatch = true
			break
		}
	}
	if !dayMatch {
		return false
	}

	startH, startM := parseHHMM(device.ScheduleStart)
	endH, endM := parseHHMM(device.ScheduleEnd)
	currentMins := now.Hour()*60 + now.Minute()
	startMins := startH*60 + startM
	endMins := endH*60 + endM

	if endMins < startMins {
		// Overnight: active if >= start OR < end
		return currentMins >= startMins || currentMins < endMins
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

	// Resolve the CNAME target to get A/AAAA records
	targetQuery := new(dns.Msg)
	targetQuery.SetQuestion(dns.Fqdn(target), query.Question[0].Qtype)
	targetResp, err := upstream.Forward(targetQuery, r.upstreamPrimary, r.upstreamSecondary)
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

// IsScheduleActive is exported for testing.
var IsScheduleActive = isScheduleActive
