package doh

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"scrolldaddy-dns/internal/cache"
	"scrolldaddy-dns/internal/db"
	"scrolldaddy-dns/internal/logger"
	"scrolldaddy-dns/internal/resolver"
)

// Handler holds all state needed by the DoH HTTP handlers.
type Handler struct {
	resolver      *resolver.Resolver
	cache         *cache.Cache
	database      *db.DB
	reloadTrigger chan struct{}
	apiKey        string
}

// New creates a Handler.
func New(res *resolver.Resolver, c *cache.Cache, database *db.DB, reloadTrigger chan struct{}, apiKey string) *Handler {
	return &Handler{
		resolver:      res,
		cache:         c,
		database:      database,
		reloadTrigger: reloadTrigger,
		apiKey:        apiKey,
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
	dbOK := h.database.Ping() == nil
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"devices":                  s.Devices,
		"profiles":                 s.Profiles,
		"blocklist_categories":     s.BlocklistCategories,
		"blocklist_domains_total":  s.BlocklistDomains,
		"last_light_reload":        s.LastLightReload.UTC().Format(time.RFC3339),
		"last_full_reload":         s.LastFullReload.UTC().Format(time.RFC3339),
		"uptime_seconds":           s.UptimeSeconds,
	})
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
		"uid":              uid,
		"domain":           domain,
		"result":           result.Result,
		"reason":           result.Reason,
		"active_profile_id": result.ActiveProfileID,
		"profile_type":     result.ProfileType,
		"schedule_active":  result.ScheduleActive,
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
