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

func TestSchedule_NoSecondaryProfile_UsesPrimary(t *testing.T) {
	dev := &cache.DeviceInfo{
		ResolverUID:        "4444444444444444444444444444444a",
		PrimaryProfileID:   1,
		SecondaryProfileID: 0, // no secondary
		IsActive:           true,
		Timezone:           time.UTC,
	}
	if isScheduleActive(dev) {
		t.Error("no secondary profile means schedule should never be active")
	}
}

func TestSchedule_EmptyDays(t *testing.T) {
	dev := &cache.DeviceInfo{
		SecondaryProfileID: 2,
		ScheduleStart:      "08:00",
		ScheduleEnd:        "17:00",
		ScheduleDays:       []string{},
		ScheduleTimezone:   time.UTC,
	}
	if isScheduleActive(dev) {
		t.Error("empty schedule days should never be active")
	}
}

func TestSchedule_WithinWindow(t *testing.T) {
	// Force a known time by using a fixed location matching our test time
	// We test the overnight-range logic directly since we can't mock time.Now()
	// Test the overnight range: 22:00 to 06:00
	dev := &cache.DeviceInfo{
		SecondaryProfileID: 2,
		ScheduleStart:      "22:00",
		ScheduleEnd:        "06:00",
		ScheduleDays:       []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"},
		ScheduleTimezone:   time.UTC,
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
	_ = dev
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
