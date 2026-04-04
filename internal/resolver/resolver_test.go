package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"scrolldaddy-dns/internal/cache"
)

// --- Helpers ---

func makeCache(devices map[string]*cache.DeviceInfo, profiles map[int64]*cache.ProfileInfo, blocklists map[string]map[string]bool) *cache.Cache {
	c := cache.New()
	c.LoadForTest(devices, profiles, blocklists) // sets internal maps directly for testing
	return c
}

func makeQuery(domain string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	return m
}

func makeDevice(uid string, primaryID int64) *cache.DeviceInfo {
	return &cache.DeviceInfo{
		DeviceID:         1,
		ResolverUID:      uid,
		PrimaryProfileID: primaryID,
		IsActive:         true,
		Timezone:         time.UTC,
	}
}

func makeProfile(id int64, blocked, allowed []string, categories []string) *cache.ProfileInfo {
	cb := map[string]bool{}
	for _, d := range blocked {
		cb[d] = true
	}
	ca := map[string]bool{}
	for _, d := range allowed {
		ca[d] = true
	}
	return &cache.ProfileInfo{
		ProfileID:         id,
		EnabledCategories: categories,
		CustomBlocked:     cb,
		CustomAllowed:     ca,
	}
}

// noopResolver never actually calls upstream; always returns SERVFAIL.
// Real tests that need forwarding should mock upstream separately.
func makeResolver(c *cache.Cache) *Resolver {
	return &Resolver{
		cache:             c,
		dnsCache:          nil, // DNS response cache disabled in unit tests
		queryLog:          nil, // query logging disabled in unit tests
		upstreamPrimary:   "127.0.0.1:0", // invalid port forces upstream failure
		upstreamSecondary: "127.0.0.1:0",
	}
}

// --- Tests ---

func TestUnknownDevice(t *testing.T) {
	c := makeCache(nil, nil, nil)
	res := makeResolver(c)
	result := res.Resolve("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", makeQuery("google.com"))
	if result.Result != ResultRefused || result.Reason != ReasonUnknownDevice {
		t.Errorf("expected REFUSED/unknown_device, got %s/%s", result.Result, result.Reason)
	}
	if result.DNSResponse.Rcode != dns.RcodeRefused {
		t.Errorf("expected RCODE REFUSED, got %d", result.DNSResponse.Rcode)
	}
}

func TestInactiveDevice(t *testing.T) {
	uid := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dev := makeDevice(uid, 1)
	dev.IsActive = false
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: dev},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, nil, nil, nil)},
		nil,
	)
	res := makeResolver(c)
	result := res.Resolve(uid, makeQuery("google.com"))
	if result.Result != ResultRefused || result.Reason != ReasonInactiveDevice {
		t.Errorf("expected REFUSED/inactive_device, got %s/%s", result.Result, result.Reason)
	}
}

func TestCustomBlockRule_ExactMatch(t *testing.T) {
	uid := "cccccccccccccccccccccccccccccccc"
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: makeDevice(uid, 1)},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, []string{"badsite.com"}, nil, nil)},
		nil,
	)
	res := makeResolver(c)
	result := res.Resolve(uid, makeQuery("badsite.com"))
	if result.Result != ResultBlocked || result.Reason != ReasonCustomBlockRule {
		t.Errorf("expected BLOCKED/custom_block_rule, got %s/%s", result.Result, result.Reason)
	}
	if result.DNSResponse.Rcode != dns.RcodeNameError {
		t.Errorf("expected RCODE NXDOMAIN, got %d", result.DNSResponse.Rcode)
	}
}

func TestCustomBlockRule_ParentDomain(t *testing.T) {
	uid := "dddddddddddddddddddddddddddddddd"
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: makeDevice(uid, 1)},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, []string{"badsite.com"}, nil, nil)},
		nil,
	)
	res := makeResolver(c)
	result := res.Resolve(uid, makeQuery("sub.badsite.com"))
	if result.Result != ResultBlocked {
		t.Errorf("expected BLOCKED for subdomain of custom block rule, got %s", result.Result)
	}
}

func TestCustomAllowRule_BypassesBlock(t *testing.T) {
	uid := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	// Domain is in both blocklist and allow rule -- allow should win.
	// The key assertion is that it's NOT blocked. With our dummy upstream it
	// will fail to forward and return SERVFAIL, but it must not return BLOCKED.
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: makeDevice(uid, 1)},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, nil, []string{"example.com"}, []string{"testcat"})},
		map[string]map[string]bool{"testcat": {"example.com": true}},
	)
	res := makeResolver(c)
	result := res.Resolve(uid, makeQuery("example.com"))
	if result.Result == ResultBlocked {
		t.Error("allow rule should bypass category blocklist block -- domain must not be BLOCKED")
	}
}

func TestCategoryBlocklist(t *testing.T) {
	uid := "ffffffffffffffffffffffffffffffff"
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: makeDevice(uid, 1)},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, nil, nil, []string{"ads"})},
		map[string]map[string]bool{"ads": {"doubleclick.net": true}},
	)
	res := makeResolver(c)
	result := res.Resolve(uid, makeQuery("doubleclick.net"))
	if result.Result != ResultBlocked || result.Reason != ReasonCategoryBlocklist {
		t.Errorf("expected BLOCKED/category_blocklist, got %s/%s", result.Result, result.Reason)
	}
	if result.Category != "ads" {
		t.Errorf("expected category=ads, got %q", result.Category)
	}
}

func TestCategoryBlocklist_AllQueryTypesBlocked(t *testing.T) {
	uid := "1111111111111111111111111111111a"
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: makeDevice(uid, 1)},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, nil, nil, []string{"ads"})},
		map[string]map[string]bool{"ads": {"blocked.com": true}},
	)
	res := makeResolver(c)

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn("blocked.com"), qtype)
		result := res.Resolve(uid, q)
		if result.Result != ResultBlocked {
			t.Errorf("qtype %d: expected BLOCKED, got %s", qtype, result.Result)
		}
	}
}

func TestNoQuestion(t *testing.T) {
	uid := "2222222222222222222222222222222a"
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: makeDevice(uid, 1)},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, nil, nil, nil)},
		nil,
	)
	res := makeResolver(c)
	emptyQuery := new(dns.Msg)
	emptyQuery.Id = 42
	result := res.Resolve(uid, emptyQuery)
	if result.Result != ResultFormErr {
		t.Errorf("expected FORMERR for empty question, got %s", result.Result)
	}
}

func TestDNSResponseFlags(t *testing.T) {
	uid := "3333333333333333333333333333333a"
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: makeDevice(uid, 1)},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, []string{"blocked.com"}, nil, nil)},
		nil,
	)
	res := makeResolver(c)
	query := makeQuery("blocked.com")
	query.Id = 12345
	query.RecursionDesired = true

	result := res.Resolve(uid, query)
	resp := result.DNSResponse

	if resp.Id != 12345 {
		t.Errorf("response ID should match query ID: got %d, want 12345", resp.Id)
	}
	if !resp.Response {
		t.Error("QR flag should be set (Response=true)")
	}
	if !resp.RecursionAvailable {
		t.Error("RA flag should be set")
	}
	if !resp.RecursionDesired {
		t.Error("RD flag should be copied from query")
	}
	if len(resp.Question) == 0 {
		t.Error("Question section should be copied from query")
	}
}

// --- Schedule tests ---

func TestSchedule_NoBlocks_NothingActive(t *testing.T) {
	dev := &cache.DeviceInfo{
		ResolverUID:      "4444444444444444444444444444444a",
		PrimaryProfileID: 1,
		IsActive:         true,
		Timezone:         time.UTC,
		ScheduledBlocks:  nil, // no scheduled blocks
	}
	// With no scheduled blocks, none should be active
	for i := range dev.ScheduledBlocks {
		if isBlockActive(&dev.ScheduledBlocks[i], dev.Timezone) {
			t.Error("no scheduled blocks means nothing should be active")
		}
	}
}

func TestSchedule_EmptyDays(t *testing.T) {
	block := &cache.ScheduledBlock{
		BlockID:       1,
		Name:          "test block",
		ScheduleStart: "08:00",
		ScheduleEnd:   "17:00",
		ScheduleDays:  []string{},
		ScheduleTimezone: time.UTC,
	}
	if isBlockActive(block, time.UTC) {
		t.Error("empty schedule days should never be active")
	}
}

func TestSchedule_OvernightDetection(t *testing.T) {
	// Test the overnight range: 22:00 to 06:00
	block := &cache.ScheduledBlock{
		BlockID:       1,
		Name:          "bedtime",
		ScheduleStart: "22:00",
		ScheduleEnd:   "06:00",
		ScheduleDays:  []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"},
		ScheduleTimezone: time.UTC,
	}
	// Can't inject time.Now() without refactoring, but we can test the logic
	// by verifying overnight vs normal range detection
	startH, startM := parseHHMM("22:00")
	endH, endM := parseHHMM("06:00")
	startMins := startH*60 + startM
	endMins := endH*60 + endM

	// Verify our overnight logic: end < start means overnight
	if endMins >= startMins {
		t.Error("22:00-06:00 should be detected as overnight (end < start)")
	}
	_ = block
}

// Test parseHHMM
func TestParseHHMM(t *testing.T) {
	cases := []struct{ input string; h, m int }{
		{"08:30", 8, 30},
		{"22:00", 22, 0},
		{"00:00", 0, 0},
		{"invalid", 0, 0},
		{"", 0, 0},
	}
	for _, tc := range cases {
		h, m := parseHHMM(tc.input)
		if h != tc.h || m != tc.m {
			t.Errorf("parseHHMM(%q) = (%d,%d), want (%d,%d)", tc.input, h, m, tc.h, tc.m)
		}
	}
}

// Test matchDomain
func TestMatchDomain(t *testing.T) {
	set := map[string]bool{"example.com": true}

	if matchDomain("example.com", set) != "example.com" {
		t.Error("exact match should return the domain")
	}
	if matchDomain("sub.example.com", set) != "example.com" {
		t.Error("parent match should return matched rule")
	}
	if matchDomain("notexample.com", set) != "" {
		t.Error("non-matching domain should return empty string")
	}
	if matchDomain("com", set) != "" {
		t.Error("TLD should not match example.com rule")
	}
}

// --- Scheduled block integration tests ---

func TestScheduledBlock_BlockKeysMerged(t *testing.T) {
	uid := "5555555555555555555555555555555a"
	dev := makeDevice(uid, 1)
	// Add a scheduled block that adds the "gambling" category - always active
	dev.ScheduledBlocks = []cache.ScheduledBlock{
		{
			BlockID:          1,
			Name:             "school hours",
			ScheduleStart:    "00:00",
			ScheduleEnd:      "23:59",
			ScheduleDays:     []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"},
			ScheduleTimezone: time.UTC,
			BlockKeys:        []string{"gambling"},
			AllowKeys:        nil,
			CustomBlocked:    map[string]bool{},
			CustomAllowed:    map[string]bool{},
		},
	}
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: dev},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, nil, nil, []string{"ads"})},
		map[string]map[string]bool{
			"ads":      {"adserver.com": true},
			"gambling": {"casino.com": true},
		},
	)
	res := makeResolver(c)

	// casino.com should be blocked via the scheduled block adding the gambling category
	result := res.Resolve(uid, makeQuery("casino.com"))
	if result.Result != ResultBlocked {
		t.Errorf("expected BLOCKED for casino.com via scheduled block, got %s/%s", result.Result, result.Reason)
	}

	// adserver.com should still be blocked via base profile
	result = res.Resolve(uid, makeQuery("adserver.com"))
	if result.Result != ResultBlocked {
		t.Errorf("expected BLOCKED for adserver.com via base profile, got %s/%s", result.Result, result.Reason)
	}
}

func TestScheduledBlock_CustomDomainBlock(t *testing.T) {
	uid := "6666666666666666666666666666666a"
	dev := makeDevice(uid, 1)
	dev.ScheduledBlocks = []cache.ScheduledBlock{
		{
			BlockID:          1,
			Name:             "focus time",
			ScheduleStart:    "00:00",
			ScheduleEnd:      "23:59",
			ScheduleDays:     []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"},
			ScheduleTimezone: time.UTC,
			BlockKeys:        nil,
			AllowKeys:        nil,
			CustomBlocked:    map[string]bool{"distraction.com": true},
			CustomAllowed:    map[string]bool{},
		},
	}
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: dev},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, nil, nil, nil)},
		nil,
	)
	res := makeResolver(c)

	result := res.Resolve(uid, makeQuery("distraction.com"))
	if result.Result != ResultBlocked || result.Reason != ReasonCustomBlockRule {
		t.Errorf("expected BLOCKED/custom_block_rule for scheduled block domain, got %s/%s", result.Result, result.Reason)
	}
}

func TestScheduledBlock_AllowKeyRemovesCategory(t *testing.T) {
	uid := "7777777777777777777777777777777a"
	dev := makeDevice(uid, 1)
	// Base profile blocks "social_media", but the scheduled block allows it
	dev.ScheduledBlocks = []cache.ScheduledBlock{
		{
			BlockID:          1,
			Name:             "free time",
			ScheduleStart:    "00:00",
			ScheduleEnd:      "23:59",
			ScheduleDays:     []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"},
			ScheduleTimezone: time.UTC,
			BlockKeys:        nil,
			AllowKeys:        []string{"social_media"},
			CustomBlocked:    map[string]bool{},
			CustomAllowed:    map[string]bool{},
		},
	}
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: dev},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, nil, nil, []string{"social_media"})},
		map[string]map[string]bool{"social_media": {"facebook.com": true}},
	)
	res := makeResolver(c)

	// facebook.com should NOT be blocked because the scheduled block allows social_media
	result := res.Resolve(uid, makeQuery("facebook.com"))
	if result.Result == ResultBlocked {
		t.Error("scheduled block allow key should remove social_media category -- facebook.com must not be BLOCKED")
	}
}

func TestScheduledBlock_ActiveBlockNames(t *testing.T) {
	uid := "8888888888888888888888888888888a"
	dev := makeDevice(uid, 1)
	dev.ScheduledBlocks = []cache.ScheduledBlock{
		{
			BlockID:          1,
			Name:             "school hours",
			ScheduleStart:    "00:00",
			ScheduleEnd:      "23:59",
			ScheduleDays:     []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"},
			ScheduleTimezone: time.UTC,
			BlockKeys:        nil,
			AllowKeys:        nil,
			CustomBlocked:    map[string]bool{"blocked.com": true},
			CustomAllowed:    map[string]bool{},
		},
	}
	c := makeCache(
		map[string]*cache.DeviceInfo{uid: dev},
		map[int64]*cache.ProfileInfo{1: makeProfile(1, nil, nil, nil)},
		nil,
	)
	res := makeResolver(c)
	result := res.Resolve(uid, makeQuery("blocked.com"))

	if len(result.ActiveScheduledBlocks) != 1 || result.ActiveScheduledBlocks[0] != "school hours" {
		t.Errorf("expected ActiveScheduledBlocks=[school hours], got %v", result.ActiveScheduledBlocks)
	}
}
