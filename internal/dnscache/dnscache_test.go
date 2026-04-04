package dnscache

import (
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- Helpers ---

func makeQuery(domain string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	return m
}

func makeResponse(query *dns.Msg, rcode int, ttl uint32) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Rcode = rcode
	resp.RecursionAvailable = true

	if rcode == dns.RcodeSuccess && ttl > 0 {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   query.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: []byte{93, 184, 216, 34},
		})
	}

	if rcode == dns.RcodeNameError {
		// NXDOMAIN with SOA in authority section
		resp.Ns = append(resp.Ns, &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Refresh: 3600,
			Retry:   900,
			Expire:  86400,
			Minttl:  300,
		})
	}

	return resp
}

// --- Tests ---

func TestCacheHit(t *testing.T) {
	c := New(100)
	q := makeQuery("google.com", dns.TypeA)
	q.Id = 1
	resp := makeResponse(q, dns.RcodeSuccess, 300)

	c.Set(q, resp)

	q2 := makeQuery("google.com", dns.TypeA)
	q2.Id = 2
	got := c.Get(q2)
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	if got.Id != 2 {
		t.Errorf("expected response ID=2 (query ID), got %d", got.Id)
	}
	if len(got.Answer) != 1 {
		t.Errorf("expected 1 answer RR, got %d", len(got.Answer))
	}
}

func TestCacheMiss(t *testing.T) {
	c := New(100)
	q := makeQuery("example.com", dns.TypeA)
	got := c.Get(q)
	if got != nil {
		t.Error("expected nil for uncached domain, got response")
	}
}

func TestTTLDecrement(t *testing.T) {
	c := New(100)
	q := makeQuery("example.com", dns.TypeA)
	resp := makeResponse(q, dns.RcodeSuccess, 300)

	// Manually insert an entry with a back-dated storedAt to simulate elapsed time
	key := cacheKey(q.Question[0])
	c.mu.Lock()
	c.entries[key] = &entry{
		msg:      resp.Copy(),
		storedAt: time.Now().Add(-100 * time.Second), // 100 seconds ago
		ttl:      300 * time.Second,
	}
	c.mu.Unlock()

	got := c.Get(q)
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	rrTTL := got.Answer[0].Header().Ttl
	// Should be ~200 (300 - 100), allow ±2 for timing
	if rrTTL < 198 || rrTTL > 202 {
		t.Errorf("expected decremented TTL ~200, got %d", rrTTL)
	}
}

func TestTTLFloor(t *testing.T) {
	c := New(100)
	q := makeQuery("example.com", dns.TypeA)
	resp := makeResponse(q, dns.RcodeSuccess, 5)

	// Store entry 10 seconds ago so it would be negative after decrement
	key := cacheKey(q.Question[0])
	c.mu.Lock()
	c.entries[key] = &entry{
		msg:      resp.Copy(),
		storedAt: time.Now().Add(-4 * time.Second), // 4 seconds ago, TTL=5 → still valid, 1s remaining
		ttl:      5 * time.Second,
	}
	c.mu.Unlock()

	got := c.Get(q)
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	rrTTL := got.Answer[0].Header().Ttl
	if rrTTL < 1 {
		t.Errorf("TTL should never be below 1, got %d", rrTTL)
	}
}

func TestTTLExpiry(t *testing.T) {
	c := New(100)
	q := makeQuery("expired.com", dns.TypeA)
	resp := makeResponse(q, dns.RcodeSuccess, 1)

	// Store an already-expired entry
	key := cacheKey(q.Question[0])
	c.mu.Lock()
	c.entries[key] = &entry{
		msg:      resp.Copy(),
		storedAt: time.Now().Add(-2 * time.Second), // 2 seconds ago, TTL=1s → expired
		ttl:      1 * time.Second,
	}
	c.mu.Unlock()

	got := c.Get(q)
	if got != nil {
		t.Error("expected nil for expired entry, got response")
	}

	// Verify the entry was lazily deleted
	c.mu.RLock()
	_, exists := c.entries[key]
	c.mu.RUnlock()
	if exists {
		t.Error("expired entry should have been removed from cache")
	}
}

func TestQueryIDRewrite(t *testing.T) {
	c := New(100)
	q := makeQuery("example.com", dns.TypeA)
	q.Id = 999
	resp := makeResponse(q, dns.RcodeSuccess, 300)
	c.Set(q, resp)

	q2 := makeQuery("example.com", dns.TypeA)
	q2.Id = 12345
	got := c.Get(q2)
	if got == nil {
		t.Fatal("expected cache hit")
	}
	if got.Id != 12345 {
		t.Errorf("expected ID=12345, got %d", got.Id)
	}
}

func TestSeparateQtypes(t *testing.T) {
	c := New(100)

	qA := makeQuery("example.com", dns.TypeA)
	respA := makeResponse(qA, dns.RcodeSuccess, 300)
	c.Set(qA, respA)

	// AAAA query should be a miss since we only stored A
	qAAAA := makeQuery("example.com", dns.TypeAAAA)
	got := c.Get(qAAAA)
	if got != nil {
		t.Error("AAAA query should miss when only A was cached")
	}

	// A query should still hit
	gotA := c.Get(qA)
	if gotA == nil {
		t.Error("A query should hit after storing A response")
	}
}

func TestCaseInsensitive(t *testing.T) {
	c := New(100)

	q := makeQuery("Google.COM", dns.TypeA)
	resp := makeResponse(q, dns.RcodeSuccess, 300)
	c.Set(q, resp)

	// Lowercase variant should hit
	qLower := makeQuery("google.com", dns.TypeA)
	got := c.Get(qLower)
	if got == nil {
		t.Error("lowercase lookup should hit when stored with mixed case")
	}
}

func TestNXDOMAINCached(t *testing.T) {
	c := New(100)
	q := makeQuery("nonexistent.example.com", dns.TypeA)
	resp := makeResponse(q, dns.RcodeNameError, 300)
	c.Set(q, resp)

	got := c.Get(q)
	if got == nil {
		t.Error("NXDOMAIN response should be cached")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN rcode, got %d", got.Rcode)
	}
}

func TestSERVFAILNotCached(t *testing.T) {
	c := New(100)
	q := makeQuery("example.com", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetRcode(q, dns.RcodeServerFailure)
	c.Set(q, resp)

	got := c.Get(q)
	if got != nil {
		t.Error("SERVFAIL response should not be cached")
	}
}

func TestZeroTTLNotCached(t *testing.T) {
	c := New(100)
	q := makeQuery("example.com", dns.TypeA)
	resp := makeResponse(q, dns.RcodeSuccess, 0) // zero TTL
	c.Set(q, resp)

	got := c.Get(q)
	if got != nil {
		t.Error("zero-TTL response should not be cached")
	}
}

func TestEviction(t *testing.T) {
	maxSize := 3
	c := New(maxSize)

	// Fill to capacity with entries that expire in the future
	domains := []string{"a.com", "b.com", "c.com"}
	for _, d := range domains {
		q := makeQuery(d, dns.TypeA)
		resp := makeResponse(q, dns.RcodeSuccess, 300)
		c.Set(q, resp)
	}

	c.mu.RLock()
	if len(c.entries) != maxSize {
		t.Errorf("expected %d entries, got %d", maxSize, len(c.entries))
	}
	c.mu.RUnlock()

	// Adding a 4th entry should evict the oldest
	q4 := makeQuery("d.com", dns.TypeA)
	resp4 := makeResponse(q4, dns.RcodeSuccess, 300)
	c.Set(q4, resp4)

	c.mu.RLock()
	if len(c.entries) != maxSize {
		t.Errorf("after eviction, expected %d entries, got %d", maxSize, len(c.entries))
	}
	c.mu.RUnlock()

	// d.com should be in cache
	if c.Get(q4) == nil {
		t.Error("newly inserted d.com should be in cache after eviction")
	}
}

func TestEvictionPrefersExpired(t *testing.T) {
	maxSize := 2
	c := New(maxSize)

	// Store one entry that is already expired
	qExpired := makeQuery("expired.com", dns.TypeA)
	respExpired := makeResponse(qExpired, dns.RcodeSuccess, 1)
	key := cacheKey(qExpired.Question[0])
	c.mu.Lock()
	c.entries[key] = &entry{
		msg:      respExpired.Copy(),
		storedAt: time.Now().Add(-5 * time.Second),
		ttl:      1 * time.Second,
	}
	c.mu.Unlock()

	// Store one fresh entry
	qFresh := makeQuery("fresh.com", dns.TypeA)
	respFresh := makeResponse(qFresh, dns.RcodeSuccess, 300)
	c.Set(qFresh, respFresh)

	// Cache is at capacity. Adding another should evict expired.com (not fresh.com).
	qNew := makeQuery("new.com", dns.TypeA)
	respNew := makeResponse(qNew, dns.RcodeSuccess, 300)
	c.Set(qNew, respNew)

	// fresh.com should still be in cache
	if c.Get(qFresh) == nil {
		t.Error("fresh.com should not have been evicted when expired.com was available")
	}
	// new.com should be in cache
	if c.Get(qNew) == nil {
		t.Error("new.com should be in cache")
	}
}

func TestFlush(t *testing.T) {
	c := New(100)
	for _, d := range []string{"a.com", "b.com", "c.com"} {
		q := makeQuery(d, dns.TypeA)
		c.Set(q, makeResponse(q, dns.RcodeSuccess, 300))
	}

	c.Flush()

	c.mu.RLock()
	size := len(c.entries)
	c.mu.RUnlock()
	if size != 0 {
		t.Errorf("after Flush, expected 0 entries, got %d", size)
	}

	q := makeQuery("a.com", dns.TypeA)
	if c.Get(q) != nil {
		t.Error("Get after Flush should return nil")
	}
}

func TestStats(t *testing.T) {
	c := New(100)

	q := makeQuery("example.com", dns.TypeA)
	resp := makeResponse(q, dns.RcodeSuccess, 300)
	c.Set(q, resp)

	// One hit
	c.Get(q)
	// One miss
	c.Get(makeQuery("notcached.com", dns.TypeA))

	s := c.Stats()
	if s.Hits != 1 {
		t.Errorf("expected 1 hit, got %d", s.Hits)
	}
	if s.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", s.Misses)
	}
	if s.Size != 1 {
		t.Errorf("expected size=1, got %d", s.Size)
	}
	if s.MaxSize != 100 {
		t.Errorf("expected maxSize=100, got %d", s.MaxSize)
	}
	if s.HitRate != 0.5 {
		t.Errorf("expected hit rate=0.5, got %f", s.HitRate)
	}
}

func TestStatsNilCache(t *testing.T) {
	var c *Cache
	s := c.Stats()
	if s.Hits != 0 || s.Misses != 0 || s.Size != 0 {
		t.Error("nil cache stats should be all zeros")
	}
}

func TestNilCacheSafe(t *testing.T) {
	var c *Cache
	q := makeQuery("example.com", dns.TypeA)
	resp := makeResponse(q, dns.RcodeSuccess, 300)

	// None of these should panic
	c.Set(q, resp)
	got := c.Get(q)
	if got != nil {
		t.Error("nil cache Get should return nil")
	}
	c.Flush()
}

func TestZeroSizeCacheDisabled(t *testing.T) {
	c := New(0)
	q := makeQuery("example.com", dns.TypeA)
	resp := makeResponse(q, dns.RcodeSuccess, 300)
	c.Set(q, resp)
	if c.Get(q) != nil {
		t.Error("zero-size cache should not store anything")
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(1000)
	domains := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := domains[i%len(domains)]
			q := makeQuery(d, dns.TypeA)
			resp := makeResponse(q, dns.RcodeSuccess, 300)
			c.Set(q, resp)
			c.Get(q)
			c.Stats()
		}(i)
	}
	wg.Wait()
}

func TestOriginalNotMutated(t *testing.T) {
	c := New(100)
	q := makeQuery("example.com", dns.TypeA)
	resp := makeResponse(q, dns.RcodeSuccess, 300)
	origTTL := resp.Answer[0].Header().Ttl

	c.Set(q, resp)

	// Simulate elapsed time
	key := cacheKey(q.Question[0])
	c.mu.Lock()
	c.entries[key].storedAt = time.Now().Add(-100 * time.Second)
	c.mu.Unlock()

	c.Get(q)

	// Original response TTL should not have changed
	if resp.Answer[0].Header().Ttl != origTTL {
		t.Errorf("original response was mutated: TTL changed from %d to %d",
			origTTL, resp.Answer[0].Header().Ttl)
	}
}
