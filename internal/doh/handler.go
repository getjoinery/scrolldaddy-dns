package doh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"scrolldaddy-dns/internal/cache"
	"scrolldaddy-dns/internal/db"
	"scrolldaddy-dns/internal/dnscache"
	"scrolldaddy-dns/internal/logger"
	"scrolldaddy-dns/internal/querylog"
	"scrolldaddy-dns/internal/resolver"
)

// dbHealthCheckInterval is how often the background goroutine pings the DB.
// dbHealthCheckTimeout is how long each ping is allowed to take before being
// reported as unhealthy. Short timeout is essential: a half-open TCP connection
// to the DB host (e.g. dropped by a firewall mid-session) will never naturally
// error, and /health must not block waiting on it.
const (
	dbHealthCheckInterval = 5 * time.Second
	dbHealthCheckTimeout  = 500 * time.Millisecond
)

// Handler holds all state needed by the DoH HTTP handlers.
type Handler struct {
	resolver      *resolver.Resolver
	cache         *cache.Cache
	dnsCache      *dnscache.Cache
	queryLog      *querylog.Logger
	reloadTrigger chan struct{}
	apiKey        string
	peerURL       string // base URL of peer DNS server for log merging (blank = disabled)

	dbMu     sync.RWMutex
	database *db.DB // may be nil during fail_open startup

	// dbHealthy is updated by a background goroutine that pings the DB with a
	// bounded timeout. /health reads from this atomic and never calls Ping
	// directly, so the endpoint cannot wedge even if the DB connection is stuck.
	dbHealthy atomic.Bool
}

// New creates a Handler. dc, ql, and database may be nil if features are disabled
// or not yet available (fail_open startup). Call SetDatabase once connected.
// peerURL is the base URL of a peer DNS server for cross-instance log merging
// (e.g. "http://10.0.0.2:8053"). Leave blank to disable peer features.
func New(res *resolver.Resolver, c *cache.Cache, dc *dnscache.Cache, ql *querylog.Logger, database *db.DB, reloadTrigger chan struct{}, apiKey string, peerURL string) *Handler {
	h := &Handler{
		resolver:      res,
		cache:         c,
		dnsCache:      dc,
		queryLog:      ql,
		database:      database,
		reloadTrigger: reloadTrigger,
		apiKey:        apiKey,
		peerURL:       strings.TrimRight(peerURL, "/"),
	}
	go h.dbHealthLoop()
	return h
}

// SetDatabase updates the database connection used by the health endpoint.
// Called once the DB becomes available in fail_open mode.
func (h *Handler) SetDatabase(d *db.DB) {
	h.dbMu.Lock()
	h.database = d
	h.dbMu.Unlock()
	// Refresh health status immediately so /health reflects the new DB without
	// waiting for the next tick.
	h.checkDBHealth()
}

// dbHealthLoop runs for the lifetime of the process, periodically pinging the
// database with a bounded timeout and updating h.dbHealthy. /health reads that
// atomic instead of calling Ping itself, so a stuck DB connection cannot block
// the HTTP handler — a deliberately separate goroutine absorbs the wait.
//
// Each check runs in its own goroutine so a single stuck Ping can never block
// the next tick. The checkDBHealth implementation also races the Ping against
// a hard cap so a driver that ignores context deadlines can't pin the atomic
// to a stale value.
func (h *Handler) dbHealthLoop() {
	ticker := time.NewTicker(dbHealthCheckInterval)
	defer ticker.Stop()
	h.checkDBHealth() // prime the value before the first tick
	for range ticker.C {
		go h.checkDBHealth()
	}
}

// checkDBHealth pings the current database with a short deadline and stores
// the result in h.dbHealthy. Safe to call from any goroutine and guaranteed
// to return within dbHealthCheckTimeout * 2, even if the driver ignores the
// context deadline (lib/pq has historically been unreliable about this for
// half-open TCP connections).
func (h *Handler) checkDBHealth() {
	h.dbMu.RLock()
	database := h.database
	h.dbMu.RUnlock()
	if database == nil {
		h.dbHealthy.Store(false)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbHealthCheckTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- database.PingContext(ctx)
	}()
	select {
	case err := <-done:
		prev := h.dbHealthy.Swap(err == nil)
		if err != nil && prev {
			logger.Warn("db health check failed: %v", err)
		} else if err == nil && !prev {
			logger.Info("db health check recovered")
		}
	case <-time.After(dbHealthCheckTimeout * 2):
		// Ping didn't honor the context deadline — still leaking a goroutine
		// until the driver gives up, but we unblock and report unhealthy.
		prev := h.dbHealthy.Swap(false)
		if prev {
			logger.Warn("db health check timed out past hard cap — reporting degraded")
		}
	}
}

// RegisterRoutes sets up all HTTP routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /resolve/{uid}", h.doHGet)
	mux.HandleFunc("POST /resolve/{uid}", h.doHPost)
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /device/{uid}/seen", h.requireAPIKey(h.deviceSeen))
	mux.HandleFunc("GET /stats", localhostOnly(h.stats))
	mux.HandleFunc("POST /reload", h.requireAPIKey(h.reload))
	mux.HandleFunc("POST /cache/flush", h.requireAPIKey(h.cacheFlush))
	mux.HandleFunc("GET /device/{uid}/log", h.requireAPIKey(h.deviceLog))
	mux.HandleFunc("POST /device/{uid}/log/purge", h.requireAPIKey(h.deviceLogPurge))
	mux.HandleFunc("GET /test", h.requireAPIKey(h.test))
}

// doHGet handles GET /resolve/{uid}?dns=<base64url>
func (h *Handler) doHGet(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !isValidUID(uid) {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	encoded := r.URL.Query().Get("dns")
	if encoded == "" {
		http.Error(w, "Missing dns parameter", http.StatusBadRequest)
		return
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		http.Error(w, "Invalid dns parameter", http.StatusBadRequest)
		return
	}

	h.handleDNSQuery(w, uid, data)
}

// doHPost handles POST /resolve/{uid} with application/dns-message body
func (h *Handler) doHPost(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !isValidUID(uid) {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	data, err := io.ReadAll(io.LimitReader(r.Body, 65535))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	h.handleDNSQuery(w, uid, data)
}

func (h *Handler) handleDNSQuery(w http.ResponseWriter, uid string, data []byte) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Error("panic in DNS query handler uid=%s: %v — forwarding upstream", uid, rec)
			// Best-effort upstream forward so the client gets a response
			var q dns.Msg
			if err := q.Unpack(data); err == nil {
				if result := h.resolver.ForwardDirect(&q); result != nil {
					if packed, err := result.Pack(); err == nil {
						w.Header().Set("Content-Type", "application/dns-message")
						w.Header().Set("Cache-Control", "no-cache, no-store")
						w.WriteHeader(http.StatusOK)
						w.Write(packed)
						return
					}
				}
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}()

	var query dns.Msg
	if err := query.Unpack(data); err != nil {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	h.cache.RecordQuery(uid)
	result := h.resolver.Resolve(uid, &query)

	packed, err := result.DNSResponse.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(packed)

	if result.Result == resolver.ResultBlocked {
		logger.Debug("uid=%s q=%s BLOCKED cat=%s reason=%s", uid,
			queryDomain(&query), result.Category, result.Reason)
	}
}

// health returns service health status. Open to all (no localhost restriction).
func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	// Read DB status from the atomic updated by the background health loop.
	// Never call Ping here — a stuck DB connection would block this handler
	// indefinitely and in turn wedge every caller behind dbMu.RLock.
	dbOK := h.dbHealthy.Load()
	stats := h.cache.Stats()

	status := "ok"
	httpStatus := http.StatusOK
	if !dbOK {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         status,
		"db_connected":   dbOK,
		"uptime_seconds": stats.UptimeSeconds,
		"last_reload":    stats.LastLightReload.UTC().Format(time.RFC3339),
	})
}

// stats returns cache statistics. Localhost only.
func (h *Handler) stats(w http.ResponseWriter, r *http.Request) {
	s := h.cache.Stats()
	out := map[string]interface{}{
		"devices":                 s.Devices,
		"profiles":                s.Profiles,
		"blocklist_categories":    s.BlocklistCategories,
		"blocklist_domains_total": s.BlocklistDomains,
		"last_light_reload":       s.LastLightReload.UTC().Format(time.RFC3339),
		"last_full_reload":        s.LastFullReload.UTC().Format(time.RFC3339),
		"uptime_seconds":          s.UptimeSeconds,
	}
	if h.dnsCache != nil {
		ds := h.dnsCache.Stats()
		out["dns_cache_size"] = ds.Size
		out["dns_cache_max_size"] = ds.MaxSize
		out["dns_cache_hits"] = ds.Hits
		out["dns_cache_misses"] = ds.Misses
		out["dns_cache_hit_rate"] = ds.HitRate
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// cacheFlush flushes the DNS response cache. API-key protected.
func (h *Handler) cacheFlush(w http.ResponseWriter, r *http.Request) {
	if h.dnsCache != nil {
		h.dnsCache.Flush()
		logger.Info("DNS response cache flushed via API")
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "flushed"})
}

// deviceLog returns the last N lines of a device's query log. API-key protected.
// When a peer URL is configured and this is not already a peer request, fetches
// the peer's logs and merges them chronologically with the local logs.
func (h *Handler) deviceLog(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !isValidUID(uid) {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if h.queryLog == nil {
		http.Error(w, "Query logging is not enabled", http.StatusNotFound)
		return
	}

	n := 100
	if v := r.URL.Query().Get("lines"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}

	lines, err := h.queryLog.ReadTail(uid, n)
	if err != nil {
		http.Error(w, "Failed to read log", http.StatusInternalServerError)
		return
	}

	// Merge with peer logs if configured and this isn't already a peer request
	isPeerReq := r.URL.Query().Get("peer") == "0"
	if h.peerURL != "" && !isPeerReq {
		peerLines := h.fetchPeerLog(uid, n)
		if len(peerLines) > 0 {
			lines = mergeLogLines(lines, peerLines, n)
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
}

// deviceLogPurge truncates a device's query log. API-key protected.
// When a peer URL is configured and this is not already a peer request,
// also forwards the purge to the peer.
func (h *Handler) deviceLogPurge(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !isValidUID(uid) {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if h.queryLog == nil {
		http.Error(w, "Query logging is not enabled", http.StatusNotFound)
		return
	}

	if err := h.queryLog.Purge(uid); err != nil {
		logger.Warn("query log purge failed for %s: %v", uid, err)
		http.Error(w, "Failed to purge log", http.StatusInternalServerError)
		return
	}

	// Forward purge to peer if configured and not a peer request
	isPeerReq := r.URL.Query().Get("peer") == "0"
	if h.peerURL != "" && !isPeerReq {
		go h.forwardPeerPurge(uid)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "purged"})
}

// reload triggers an immediate full cache reload. Localhost only.
func (h *Handler) reload(w http.ResponseWriter, r *http.Request) {
	select {
	case h.reloadTrigger <- struct{}{}:
	default:
		// Already pending, that's fine
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reload_triggered"})
}

// test shows what would happen for a given uid+domain without making a real DNS query. Localhost only.
func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
	uid := r.URL.Query().Get("uid")
	domain := r.URL.Query().Get("domain")

	if uid == "" || domain == "" {
		http.Error(w, "uid and domain parameters required", http.StatusBadRequest)
		return
	}

	// Build a minimal A query for the domain
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(strings.ToLower(domain)), dns.TypeA)

	result := h.resolver.Resolve(uid, query)

	resp := map[string]interface{}{
		"uid":                     uid,
		"domain":                  domain,
		"result":                  result.Result,
		"reason":                  result.Reason,
		"active_profile_id":       result.ActiveProfileID,
		"active_scheduled_blocks": result.ActiveScheduledBlocks,
	}
	if result.Category != "" {
		resp["category"] = result.Category
	}
	if result.MatchedRule != "" {
		resp["matched_rule"] = result.MatchedRule
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// deviceSeen returns the last-seen time for a resolver UID.
func (h *Handler) deviceSeen(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	if !isValidUID(uid) {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if t, ok := h.cache.GetLastSeen(uid); ok {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"uid":       uid,
			"seen":      true,
			"last_seen": t.UTC().Format(time.RFC3339),
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"uid":       uid,
			"seen":      false,
			"last_seen": nil,
		})
	}
}

// requireAPIKey is middleware that checks for a valid API key if one is configured.
// The key may be passed as the X-API-Key header or the api_key query parameter.
// If no API key is configured on the server, all requests are allowed through.
func (h *Handler) requireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.apiKey != "" {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				key = r.URL.Query().Get("api_key")
			}
			if key != h.apiKey {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// localhostOnly is middleware that restricts a handler to localhost connections.
func localhostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || (host != "127.0.0.1" && host != "::1") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// fetchPeerLog fetches query log lines from the peer server.
// Returns nil on any error (timeout, unreachable, etc).
func (h *Handler) fetchPeerLog(uid string, n int) []string {
	url := fmt.Sprintf("%s/device/%s/log?lines=%d&peer=0", h.peerURL, uid, n)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Debug("peer log request build failed: %v", err)
		return nil
	}
	if h.apiKey != "" {
		req.Header.Set("X-API-Key", h.apiKey)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Debug("peer log fetch failed for %s: %v", uid, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Debug("peer log fetch returned %d for %s", resp.StatusCode, uid)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		logger.Debug("peer log read failed for %s: %v", uid, err)
		return nil
	}

	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

// forwardPeerPurge sends a log purge request to the peer server.
// Errors are logged but not propagated.
func (h *Handler) forwardPeerPurge(uid string) {
	url := fmt.Sprintf("%s/device/%s/log/purge?peer=0", h.peerURL, uid)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		logger.Debug("peer purge request build failed: %v", err)
		return
	}
	if h.apiKey != "" {
		req.Header.Set("X-API-Key", h.apiKey)
	}
	req.Header.Set("Content-Length", "0")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Debug("peer purge failed for %s: %v", uid, err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Debug("peer purge returned %d for %s", resp.StatusCode, uid)
	}
}

// mergeLogLines merges two chronologically-ordered log line slices and returns
// the last n lines. Lines are sorted by the RFC3339 timestamp prefix (the text
// before the first tab character). Lines with unparseable timestamps sort last.
func mergeLogLines(local, peer []string, n int) []string {
	merged := make([]string, 0, len(local)+len(peer))
	i, j := 0, 0
	for i < len(local) && j < len(peer) {
		tl := logTimestamp(local[i])
		tp := logTimestamp(peer[j])
		if tl <= tp {
			merged = append(merged, local[i])
			i++
		} else {
			merged = append(merged, peer[j])
			j++
		}
	}
	merged = append(merged, local[i:]...)
	merged = append(merged, peer[j:]...)

	if len(merged) > n {
		merged = merged[len(merged)-n:]
	}
	return merged
}

// logTimestamp extracts the timestamp prefix from a tab-separated log line.
// Returns the raw string up to the first tab, or a high-sort value for
// lines without a tab (so they sort to the end).
func logTimestamp(line string) string {
	if idx := strings.IndexByte(line, '\t'); idx > 0 {
		return line[:idx]
	}
	return "\xff"
}

// isValidUID checks that uid is exactly 32 lowercase hex characters.
func isValidUID(uid string) bool {
	if len(uid) != 32 {
		return false
	}
	for _, c := range uid {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func queryDomain(query *dns.Msg) string {
	if len(query.Question) > 0 {
		return strings.TrimSuffix(query.Question[0].Name, ".")
	}
	return ""
}

// Server starts the DoH HTTP server and blocks until it returns.
func Server(port int, h *Handler) error {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	addr := fmt.Sprintf(":%d", port)
	logger.Info("DoH server listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}
