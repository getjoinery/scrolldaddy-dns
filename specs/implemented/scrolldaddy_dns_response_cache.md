# ScrollDaddy DNS Response Cache

## Overview

Add a TTL-aware DNS response cache to the ScrollDaddy DNS server that eliminates redundant upstream roundtrips for recently-resolved domains. The cache sits between the resolver's filtering logic and the `upstream.Forward()` call, so only allowed (non-blocked) queries are cached and served from cache.

## Motivation

Currently every forwarded DNS query makes a fresh UDP roundtrip to Cloudflare (1.1.1.1) or Google (8.8.8.8), even for domains that were resolved seconds ago. A local in-memory cache turns repeated lookups from ~5-15ms network roundtrips into ~1us map lookups — a ~10,000x speedup per cache hit. For household/family DNS traffic, popular domains (google.com, youtube.com, etc.) are queried repeatedly across multiple devices, making the expected hit rate 40-70%.

Secondary benefits:
- **Reliability**: cached answers survive brief upstream outages
- **Reduced upstream traffic**: fewer queries to external resolvers
- **Lower latency variance**: cached responses have consistent sub-microsecond latency

## Architecture

### New Package: `internal/dnscache`

A standalone package with no dependency on the existing `cache` package (which handles device/profile/blocklist data). The dnscache package deals exclusively with DNS wire-format responses.

### Files

| File | Purpose |
|---|---|
| `internal/dnscache/dnscache.go` | Cache implementation |
| `internal/dnscache/dnscache_test.go` | Unit tests |

### Core Data Structures

```go
package dnscache

type Cache struct {
    mu       sync.RWMutex
    entries  map[string]*entry
    maxSize  int
    hits     atomic.Int64
    misses   atomic.Int64
}

type entry struct {
    msg      *dns.Msg      // deep copy of the upstream response
    storedAt time.Time     // when cached
    ttl      time.Duration // minimum TTL from all RRs at store time
}

type Stats struct {
    Size     int
    MaxSize  int
    Hits     int64
    Misses   int64
    HitRate  float64 // computed: hits / (hits + misses)
}
```

### Cache Key

`qname + "\x00" + qtype + "\x00" + qclass` — lowercase qname for case-insensitive matching. This ensures A and AAAA queries for the same domain are cached separately.

### TTL Handling

**On store:**
- Extract the minimum TTL across all RRs in Answer, Authority, and Additional sections (skipping OPT pseudo-RRs)
- If minimum TTL is 0, do not cache (zero-TTL means "do not cache")
- Store a deep copy of the response via `msg.Copy()`

**On lookup:**
- Compute `elapsed = time.Since(storedAt)`
- If `elapsed >= ttl`, the entry is expired: delete it, return miss
- Otherwise, return a copy of the message with:
  - `msg.Id` set to match the current query ID
  - All RR TTLs decremented by `elapsed` seconds
  - Floor TTLs at 1 second (never return TTL=0 in a cached response)

### What Gets Cached

Only responses from `upstream.Forward()` that have:
- Rcode `NOERROR` or `NXDOMAIN`
- At least one RR with TTL > 0

NOT cached:
- `SERVFAIL`, `REFUSED`, `FORMERR` responses
- Responses with no RRs (empty answers with zero-TTL SOA)
- Blocked responses (these never reach upstream)
- SafeSearch/SafeYouTube CNAME rewrites (these are synthetic, not upstream responses — and the CNAME target resolution IS cached since it goes through `forwardWithCache`)

### Eviction Strategy

Simple approach suitable for the expected scale (household DNS, <10K active entries):

1. When at capacity and a new entry arrives, first sweep and remove all expired entries
2. If still at capacity, evict the oldest entry (by `storedAt`)
3. Default max size: 10,000 entries (~5-10MB memory at typical DNS response sizes)

No LRU tracking needed — TTL expiry handles most eviction naturally, and the oldest-entry fallback prevents unbounded growth.

## Integration Points

### 1. Resolver (`internal/resolver/resolver.go`)

Add a `dnsCache *dnscache.Cache` field to the `Resolver` struct. Add a helper method:

```go
func (r *Resolver) forwardWithCache(query *dns.Msg) (*dns.Msg, error) {
    if r.dnsCache != nil {
        if cached := r.dnsCache.Get(query); cached != nil {
            return cached, nil
        }
    }
    resp, err := upstream.Forward(query, r.upstreamPrimary, r.upstreamSecondary)
    if err != nil {
        return nil, err
    }
    if r.dnsCache != nil {
        r.dnsCache.Set(query, resp)
    }
    return resp, nil
}
```

Replace all three `upstream.Forward()` calls in `resolver.go` with `r.forwardWithCache()`:
- Line 193: custom allow rule forward
- Line 252: not-blocked forward
- Line 382: CNAME target resolution in `buildCNAMEResponse()`

Update `resolver.New()` signature to accept `*dnscache.Cache`.

### 2. Config (`internal/config/config.go`)

Add one new environment variable:

| Env Var | Default | Description |
|---|---|---|
| `SCD_DNS_CACHE_SIZE` | `10000` | Maximum entries in the DNS response cache. Set to 0 to disable. |

Add to the `Config` struct:
```go
DNSCacheSize int
```

### 3. Main (`cmd/dns/main.go`)

Create the cache and pass it to the resolver:

```go
var dnsCache *dnscache.Cache
if cfg.DNSCacheSize > 0 {
    dnsCache = dnscache.New(cfg.DNSCacheSize)
    logger.Info("DNS response cache enabled (max %d entries)", cfg.DNSCacheSize)
} else {
    logger.Info("DNS response cache disabled")
}
res := resolver.New(c, dnsCache, cfg.UpstreamPrimary, cfg.UpstreamSecondary)
```

### 4. Stats Endpoint (`internal/doh/handler.go`)

Add DNS cache stats to the existing `/stats` response:

```json
{
  "devices": 5,
  "profiles": 3,
  "dns_cache_size": 847,
  "dns_cache_max_size": 10000,
  "dns_cache_hits": 15234,
  "dns_cache_misses": 8901,
  "dns_cache_hit_rate": 0.631,
  ...
}
```

Pass the `*dnscache.Cache` (which may be nil) to the DoH handler. If nil, omit the dns_cache fields or show zeros.

### 5. Cache Flush

Add a `POST /cache/flush` endpoint (API-key protected) that calls `dnsCache.Flush()`. Useful for debugging and after upstream changes.

### 6. Resolver Result Tracking

Add a new reason constant to distinguish cache hits in logging/diagnostics:

```go
const ReasonCacheHit = "cache_hit"
```

The `forwardWithCache` method should set this on the `ResolveResult` when serving from cache. This requires a small change: `forwardWithCache` returns an additional boolean indicating cache hit, and the caller sets the reason accordingly. Alternatively, this can be tracked purely via the stats counters without changing `ResolveResult`.

**Decision: use stats counters only.** The `ResolveResult.Reason` should reflect _why_ the domain was allowed/blocked, not _how_ it was resolved. Cache hits are an implementation detail, not a filtering decision. The `/stats` endpoint provides visibility into cache performance.

### 7. Existing Tests

Update `makeResolver()` in `resolver_test.go` to pass `nil` for the DNS cache (disabling it in existing tests):

```go
func makeResolver(c *cache.Cache) *Resolver {
    return &Resolver{
        cache:             c,
        dnsCache:          nil, // no DNS response cache in unit tests
        upstreamPrimary:   "127.0.0.1:0",
        upstreamSecondary: "127.0.0.1:0",
    }
}
```

All existing tests continue to pass unchanged since they test filtering logic, not upstream forwarding.

## Public API

### `dnscache.New(maxSize int) *Cache`
Creates a new cache. If maxSize <= 0, effectively no entries are stored.

### `(*Cache).Get(query *dns.Msg) *dns.Msg`
Returns a cached response with decremented TTLs, or nil on miss/expiry.

### `(*Cache).Set(query *dns.Msg, resp *dns.Msg)`
Stores a cacheable response. Silently ignores uncacheable responses.

### `(*Cache).Stats() Stats`
Returns current size, hits, misses, hit rate.

### `(*Cache).Flush()`
Removes all entries. Thread-safe.

## Unit Tests (`internal/dnscache/dnscache_test.go`)

| Test | What it verifies |
|---|---|
| `TestCacheHit` | Store a response, retrieve it, verify answer matches and TTLs are decremented |
| `TestCacheMiss` | Query for uncached domain returns nil |
| `TestTTLExpiry` | Store a response with low TTL, wait, verify it expires |
| `TestTTLDecrement` | Store response with TTL=300, retrieve after 100s, verify TTL=200 on all RRs |
| `TestTTLFloor` | Verify TTLs never go below 1 in cached responses |
| `TestQueryIDRewrite` | Cached response has the querying message's ID, not the original |
| `TestSeparateQtypes` | A and AAAA for same domain are cached separately |
| `TestCaseInsensitive` | `Google.COM` and `google.com` share the same cache entry |
| `TestNXDOMAINCached` | NXDOMAIN responses are cached (with SOA TTL) |
| `TestSERVFAILNotCached` | SERVFAIL responses are not stored |
| `TestZeroTTLNotCached` | Responses with all-zero TTLs are not stored |
| `TestEviction` | Cache at max size evicts expired, then oldest |
| `TestFlush` | Flush empties the cache, subsequent Gets return nil |
| `TestStats` | Hits/misses/size counters are accurate |
| `TestConcurrentAccess` | Parallel Gets and Sets don't race (run with `-race`) |
| `TestNilCacheSafe` | Calling Get/Set/Stats/Flush on nil cache doesn't panic (if we support nil receiver) |

## Deployment

No database changes. No configuration changes required (defaults are sensible). The cache is enabled by default with 10,000 max entries.

**To disable:** Set `SCD_DNS_CACHE_SIZE=0` in the service environment.

**To verify after deploy:**
```bash
# Check stats endpoint
curl -s http://localhost:8053/stats | jq '.dns_cache_size, .dns_cache_hit_rate'

# Flush cache if needed
curl -s -X POST -H "X-API-Key: $KEY" http://localhost:8053/cache/flush
```

## Future Considerations (Not In Scope)

- **Serve-stale**: Return expired cache entries when upstream is down (RFC 8767). Could be added later with a `stale_ttl` config.
- **Prefetch**: Proactively refresh entries nearing expiry for frequently-queried domains.
- **Per-domain metrics**: Track which domains are most frequently cached/evicted.
- **Negative cache tuning**: Separate max TTL for NXDOMAIN responses to avoid caching stale negative answers too long.
