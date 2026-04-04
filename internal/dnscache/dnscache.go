package dnscache

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Cache is a TTL-aware DNS response cache.
// It stores upstream responses keyed by (qname, qtype, qclass) and expires
// entries based on the minimum TTL across all resource records in the response.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*entry
	maxSize int

	hits   atomic.Int64
	misses atomic.Int64
}

type entry struct {
	msg      *dns.Msg      // deep copy of the upstream response
	storedAt time.Time     // when the entry was cached
	ttl      time.Duration // minimum TTL from all RRs at store time
}

// Stats holds cache performance metrics.
type Stats struct {
	Size    int
	MaxSize int
	Hits    int64
	Misses  int64
	HitRate float64
}

// New creates a DNS response cache with the given maximum number of entries.
// If maxSize <= 0, the cache stores nothing (all Gets return nil).
func New(maxSize int) *Cache {
	if maxSize < 0 {
		maxSize = 0
	}
	return &Cache{
		entries: make(map[string]*entry, maxSize),
		maxSize: maxSize,
	}
}

// Get looks up a cached response for the query.
// Returns nil on a miss or if the entry has expired.
// On a hit, returns a copy of the cached message with TTLs decremented by
// elapsed time and the message ID set to match the query.
func (c *Cache) Get(query *dns.Msg) *dns.Msg {
	if c == nil || c.maxSize == 0 || len(query.Question) == 0 {
		return nil
	}
	key := cacheKey(query.Question[0])

	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil
	}

	elapsed := time.Since(e.storedAt)
	if elapsed >= e.ttl {
		// Expired — remove lazily under write lock
		c.mu.Lock()
		if e2, still := c.entries[key]; still && e2 == e {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		c.misses.Add(1)
		return nil
	}

	c.hits.Add(1)
	return copyWithDecrementedTTL(e.msg, query.Id, elapsed)
}

// Set stores a DNS response in the cache.
// Only NOERROR and NXDOMAIN responses with at least one RR having TTL > 0 are
// cached. Silently ignores responses that should not be cached.
func (c *Cache) Set(query *dns.Msg, resp *dns.Msg) {
	if c == nil || c.maxSize == 0 || len(query.Question) == 0 || resp == nil {
		return
	}

	// Only cache NOERROR and NXDOMAIN
	rcode := resp.Rcode
	if rcode != dns.RcodeSuccess && rcode != dns.RcodeNameError {
		return
	}

	minTTL := minResponseTTL(resp)
	if minTTL == 0 {
		return // zero-TTL means "do not cache"
	}

	key := cacheKey(query.Question[0])

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict expired entries if at capacity
	if len(c.entries) >= c.maxSize {
		c.evictExpired()
	}
	// If still at capacity, evict the oldest entry
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &entry{
		msg:      resp.Copy(),
		storedAt: time.Now(),
		ttl:      time.Duration(minTTL) * time.Second,
	}
}

// Stats returns a snapshot of cache performance metrics.
func (c *Cache) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.RLock()
	size := len(c.entries)
	c.mu.RUnlock()

	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return Stats{
		Size:    size,
		MaxSize: c.maxSize,
		Hits:    hits,
		Misses:  misses,
		HitRate: hitRate,
	}
}

// Flush removes all entries from the cache. Thread-safe.
func (c *Cache) Flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[string]*entry, c.maxSize)
	c.mu.Unlock()
}

// cacheKey builds a lookup key from a DNS question.
// qname is lowercased for case-insensitive matching.
func cacheKey(q dns.Question) string {
	return fmt.Sprintf("%s\x00%d\x00%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

// minResponseTTL returns the minimum TTL across all RR sections.
// Returns 0 if there are no RRs or all have TTL 0.
func minResponseTTL(msg *dns.Msg) uint32 {
	var min uint32
	first := true

	check := func(rrs []dns.RR) {
		for _, rr := range rrs {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue // skip EDNS OPT pseudo-RR
			}
			if first || hdr.Ttl < min {
				min = hdr.Ttl
				first = false
			}
		}
	}

	check(msg.Answer)
	check(msg.Ns)
	check(msg.Extra)

	if first {
		return 0
	}
	return min
}

// copyWithDecrementedTTL returns a deep copy of msg with all RR TTLs reduced
// by elapsed and the message ID set to queryID.
func copyWithDecrementedTTL(msg *dns.Msg, queryID uint16, elapsed time.Duration) *dns.Msg {
	resp := msg.Copy()
	resp.Id = queryID

	elapsedSecs := uint32(elapsed.Seconds())
	decrementRRs(resp.Answer, elapsedSecs)
	decrementRRs(resp.Ns, elapsedSecs)
	decrementRRs(resp.Extra, elapsedSecs)

	return resp
}

// decrementRRs reduces the TTL of each RR by elapsed seconds, flooring at 1.
func decrementRRs(rrs []dns.RR, elapsed uint32) {
	for _, rr := range rrs {
		hdr := rr.Header()
		if hdr.Rrtype == dns.TypeOPT {
			continue
		}
		if hdr.Ttl > elapsed {
			hdr.Ttl -= elapsed
		} else {
			hdr.Ttl = 1 // floor at 1 — never return TTL=0 from cache
		}
	}
}

// evictExpired removes all expired entries. Must be called with c.mu held (write).
func (c *Cache) evictExpired() {
	now := time.Now()
	for key, e := range c.entries {
		if now.Sub(e.storedAt) >= e.ttl {
			delete(c.entries, key)
		}
	}
}

// evictOldest removes the single oldest entry. Must be called with c.mu held (write).
func (c *Cache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, e := range c.entries {
		if first || e.storedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = e.storedAt
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
	}
}
