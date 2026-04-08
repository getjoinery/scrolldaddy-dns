# ScrollDaddy DNS Per-Device Query Logging

## Overview

Add opt-in, per-device query logging to the ScrollDaddy DNS server. When enabled for a device, every DNS query is appended as a tab-separated line to a flat file named by resolver UID. Logging is off by default and has zero cost for devices that don't use it.

## Motivation

Users want visibility into what domains their devices are querying — for debugging filter rules, monitoring children's activity, or understanding network behavior. A flat file per device is the simplest approach: no database schema, no migrations, no cross-server dependencies. Files can be tailed, grepped, or served via API.

## Design

### Log File Layout

```
/var/log/scrolldaddy/queries/{resolver_uid}.log
```

One file per device. Each line is a single query record, tab-separated:

```
{timestamp}\t{domain}\t{qtype}\t{result}\t{reason}\t{category}\t{cached}
```

Example lines:
```
2026-04-04T19:23:45Z	google.com	A	FORWARDED	not_blocked		no
2026-04-04T19:23:46Z	doubleclick.net	A	BLOCKED	category_blocklist	ads	no
2026-04-04T19:23:47Z	www.youtube.com	AAAA	FORWARDED	not_blocked		yes
2026-04-04T19:23:48Z	malware.example.com	A	BLOCKED	custom_block_rule		no
```

**Field definitions:**

| Field | Example | Notes |
|---|---|---|
| timestamp | `2026-04-04T19:23:45Z` | UTC, RFC3339 |
| domain | `google.com` | Lowercased, trailing dot stripped |
| qtype | `A`, `AAAA`, `MX`, `TXT` | String name from `dns.TypeToString` |
| result | `FORWARDED`, `BLOCKED`, `REFUSED` | Existing `Result` constants |
| reason | `not_blocked`, `category_blocklist` | Existing `Reason` constants |
| category | `ads`, `gambling` | Empty string if not a category block |
| cached | `yes`, `no` | Whether served from DNS response cache |

Tab-separated was chosen over JSON for speed (~200-500ns faster per entry), smaller file size, and grep-friendliness. None of the fields can contain tabs or newlines, so no escaping is needed.

### Per-Device Toggle

Add a `LogQueries bool` field to `cache.DeviceInfo`. This is loaded from a new `sdd_log_queries` column on the `sdd_devices` table (managed by the PHP data class — add to `$field_specifications`).

Default: `false`. Toggled via the ScrollDaddy device admin UI on the Joinery side.

### Hot Path Cost

**Logging OFF (default):**
```go
if device.LogQueries {  // one boolean check — branch predicted, ~1ns
    // skipped
}
```

**Logging ON:**
```go
if device.LogQueries {
    querylog.Record(entry)  // non-blocking channel send — ~10ns
}
```

The channel send is non-blocking with a `select/default`. If the buffer is full (writer goroutine is behind), the entry is silently dropped. DNS resolution is never delayed.

## Architecture

### New Package: `internal/querylog`

```
internal/querylog/
    querylog.go       — Logger implementation
    querylog_test.go  — Unit tests
```

### Core Struct

```go
type Entry struct {
    ResolverUID string
    Time        time.Time
    Domain      string
    QType       string
    Result      string
    Reason      string
    Category    string
    Cached      bool
}

type openFile struct {
    f    *os.File
    size int64   // current file size, updated on each write
}

type Logger struct {
    dir         string               // base directory for log files
    maxFileSize int64                // max bytes per log file before rotation
    ch          chan *Entry           // buffered channel
    mu          sync.Mutex           // protects open file handles
    files       map[string]*openFile // resolver_uid -> open file handle + size
    done        chan struct{}         // shutdown signal
}
```

// TODO(perf): If profiling shows GC pressure from Entry allocations at high
// query rates, two optimizations to consider:
// 1. Use sync.Pool for Entry structs to avoid per-query heap allocation
// 2. Format the log line on the caller side into a pooled []byte buffer,
//    send pre-formatted bytes through the channel, and have the writer
//    just do file.Write — eliminates both struct allocation and writer-side
//    fmt.Fprintf. See BenchmarkRecord to measure.

### Public API

#### `querylog.New(dir string, bufferSize int, maxFileSize int64) *Logger`
Creates the logger. Creates `dir` if it doesn't exist. Starts the background writer goroutine. `maxFileSize` is the per-file rotation threshold in bytes (0 means no limit).

#### `(*Logger).Record(entry *Entry)`
Non-blocking send to the channel. Drops the entry if the buffer is full.

#### `(*Logger).Close()`
Drains remaining entries, closes all open file handles, stops the background goroutine.

#### `(*Logger).ReadTail(resolverUID string, n int) ([]string, error)`
Returns the last `n` lines from a device's log file. Used by the API endpoint. Reads from the end of the file to avoid scanning the whole thing.

**Implementation note:** This requires seeking to the end of the file and reading backward in chunks (e.g., 4KB at a time) until `n` newlines are found. This is ~30-40 lines of fiddly but well-understood code. Edge cases to handle: file shorter than n lines (return everything), empty file (return empty slice), file doesn't exist (return empty slice, no error).

#### `(*Logger).Purge(resolverUID string) error`
Truncates a device's log file. Used by the API endpoint.

### Background Writer Goroutine

```go
func (l *Logger) writer() {
    for entry := range l.ch {
        of := l.getOrOpenFile(entry.ResolverUID)
        n, _ := fmt.Fprintf(of.f, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
            entry.Time.UTC().Format(time.RFC3339),
            entry.Domain,
            entry.QType,
            entry.Result,
            entry.Reason,
            entry.Category,
            boolToYesNo(entry.Cached),
        )
        of.size += int64(n)
        if l.maxFileSize > 0 && of.size >= l.maxFileSize {
            l.rotateFile(entry.ResolverUID)
        }
    }
}
```

**`rotateFile(uid)`**: closes the current handle, renames `{uid}.log` to `{uid}.log.1`, removes the entry from the `files` map so the next write opens a fresh file.

File handles are kept open in a map and reused across writes to the same device. This avoids open/close overhead on every log line. Handles are closed on `Close()`.

### File Handle Management

- Open file handles are cached in `l.files` map
- Files are opened with `O_APPEND|O_CREATE|O_WRONLY` and mode `0644`
- On `Close()`, all handles are flushed and closed
- If a file open fails (permissions, disk full), log a warning via the existing `logger` package and skip the entry

### File Size Management

Managed entirely within the Go server — no external tools like `logrotate` required.

Each open file handle tracks its current size (via `Stat()` on open, then incrementing by bytes written). When a file exceeds `maxFileSize`, the writer goroutine:

1. Closes the current file handle
2. Renames `{uid}.log` to `{uid}.log.1` (overwrites any previous backup)
3. Opens a fresh `{uid}.log`

This gives at most **2x `maxFileSize` disk usage per device**: the active log plus one rotated backup. With a 2MB default, that's 4MB worst case per logging-enabled device.

**Default max file size:** 2MB (`SCD_QUERY_LOG_MAX_SIZE`). At ~100 bytes per line, that's roughly 20K queries per file. A typical household device generates 5K-10K queries/day, so one file covers 2-4 days and the active + backup pair covers roughly **5-10 days** — appropriate for a troubleshooting tool, not long-term storage.

**Size tracking:**
```go
type openFile struct {
    f    *os.File
    size int64
}
```

The `size` field is initialized from `os.Stat()` when the file is opened (handles server restart with an existing log) and incremented by `n` after each `fmt.Fprintf` call. This avoids a `Stat()` syscall on every write.

## Config File

### Overview

A small JSON config file provides runtime-toggleable settings for features like DNS response caching and query logging. The file is read at startup and re-read on every reload (SIGHUP or `POST /reload`), so features can be toggled without restarting the DNS server.

Environment variables remain the primary configuration for infrastructure concerns (database credentials, ports, TLS certs). The config file handles feature flags and tuning knobs that operators may want to change at runtime.

### File Location

Set via environment variable:

| Env Var | Default | Description |
|---|---|---|
| `SCD_CONFIG_FILE` | `/etc/scrolldaddy/dns.json` | Path to the JSON config file. Empty string disables (all defaults apply). |

If the file doesn't exist at startup, the server logs a warning and uses defaults. If it exists but is invalid JSON, the server refuses to start.

On reload, if the file has become invalid JSON, the reload fails with an error log and the previous config is retained.

### File Format

```json
{
  "dns_cache": {
    "enabled": true,
    "max_size": 10000
  },
  "query_log": {
    "enabled": true,
    "dir": "/var/log/scrolldaddy/queries",
    "buffer_size": 4096,
    "max_file_size": 2097152
  }
}
```

All fields are optional. Missing fields use defaults. This means an empty `{}` file is valid and uses all defaults.

### Defaults

| Field | Default | Notes |
|---|---|---|
| `dns_cache.enabled` | `true` | Set `false` to disable response caching |
| `dns_cache.max_size` | `10000` | Maximum cache entries |
| `query_log.enabled` | `true` | Set `false` to disable query logging globally (per-device flags are ignored) |
| `query_log.dir` | `/var/log/scrolldaddy/queries` | Directory for per-device log files |
| `query_log.buffer_size` | `4096` | Channel buffer size |
| `query_log.max_file_size` | `2097152` | Per-file rotation threshold (2MB) |

### Precedence

Environment variables override config file values. This lets deployment tooling (Docker, systemd) force specific values while the config file provides convenient defaults.

Resolution order: env var (if set and non-empty) > config file value > compiled default.

### Implementation

#### New package: `internal/config`

Extend the existing `config.go` to support the config file:

```go
type FeatureConfig struct {
    DNSCache  DNSCacheConfig  `json:"dns_cache"`
    QueryLog  QueryLogConfig  `json:"query_log"`
}

type DNSCacheConfig struct {
    Enabled bool `json:"enabled"`
    MaxSize int  `json:"max_size"`
}

type QueryLogConfig struct {
    Enabled     bool   `json:"enabled"`
    Dir         string `json:"dir"`
    BufferSize  int    `json:"buffer_size"`
    MaxFileSize int64  `json:"max_file_size"`
}
```

#### `LoadFeatureConfig(path string) (*FeatureConfig, error)`

Reads and parses the JSON file. Applies defaults for missing fields. Returns a config struct with all values resolved.

#### `MergeEnvOverrides(fc *FeatureConfig)`

Checks env vars (`SCD_DNS_CACHE_SIZE`, `SCD_QUERY_LOG_DIR`, etc.) and overrides the corresponding config file values if set. This is called after `LoadFeatureConfig` so env vars always win.

### Hot Reload Behavior

On SIGHUP or `POST /reload`, the reload sequence becomes:

1. Re-read and parse the config file
2. Apply env var overrides
3. **DNS cache**: if `dns_cache.enabled` changed from true to false, flush and nil out the cache. If changed from false to true, create a new cache. If `max_size` changed, create a new cache with the new size (old entries are lost — acceptable since they'd expire via TTL anyway).
4. **Query log**: if `query_log.enabled` changed from true to false, close the logger (drains buffer, closes files). If changed from false to true, create a new logger. Dir and max_file_size changes take effect on the new logger.
5. Proceed with the existing device/profile/blocklist reload.

### Validation

- File must be valid JSON (or absent)
- `max_size` must be >= 0
- `buffer_size` must be > 0 if query_log is enabled
- `max_file_size` must be >= 0
- `dir` must be writable if query_log is enabled

### Tests

| Test | What it verifies |
|---|---|
| `TestLoadFeatureConfig` | Parses valid JSON, all fields populated |
| `TestLoadFeatureConfigDefaults` | Empty `{}` file uses all defaults |
| `TestLoadFeatureConfigMissing` | Missing file returns defaults, no error |
| `TestLoadFeatureConfigInvalid` | Invalid JSON returns error |
| `TestMergeEnvOverrides` | Env vars override config file values |
| `TestPartialConfig` | File with only some fields uses defaults for the rest |

## Integration Points

### 1. DeviceInfo (`internal/cache/cache.go`)

Add field:
```go
type DeviceInfo struct {
    // ... existing fields ...
    LogQueries bool
}
```

### 2. DB Loading (`internal/db/db.go`)

Add `sdd_log_queries` to the `LoadDevices()` query and the `ValidateSchema()` expected columns:

```sql
COALESCE(d.sdd_log_queries, false) AS log_queries
```

### 3. Cache Build (`internal/cache/cache.go`)

In `LightReload()`, map the new DB field to `DeviceInfo.LogQueries`.

### 4. Resolver (`internal/resolver/resolver.go`)

At the end of `Resolve()`, after the result is determined but before returning:

```go
if device.LogQueries && r.queryLog != nil {
    r.queryLog.Record(&querylog.Entry{
        ResolverUID: resolverUID,
        Time:        time.Now(),
        Domain:      domain,
        QType:       dns.TypeToString[query.Question[0].Qtype],
        Result:      base.Result,
        Reason:      base.Reason,
        Category:    base.Category,
        Cached:      cached,
    })
}
```

The `cached` bool comes from `forwardWithCache()` — it needs to return whether the response was a cache hit. Adjust its signature to `forwardWithCache(query *dns.Msg) (*dns.Msg, bool, error)` where the bool indicates a cache hit.

**Note:** The DNS response cache spec has already been implemented with `forwardWithCache` returning `(*dns.Msg, error)`. This change updates all three call sites in `Resolve()`:
- Line ~215: custom allow rule forward
- Line ~274: not-blocked forward
- Line ~404: CNAME target resolution in `buildCNAMEResponse()`

Each call site needs to capture the new `cached` bool. For the two forwarding paths inside `Resolve()`, the bool feeds directly into the log entry. For `buildCNAMEResponse()`, the cached status is less meaningful (the CNAME itself is synthetic) — pass `false` for the log entry in that case.

Add `queryLog *querylog.Logger` field to `Resolver`. Update `New()` signature.

### 5. Config (`internal/config/config.go`)

**Note:** The DNS response cache spec already added `DNSCacheSize` to the `Config` struct and `SCD_DNS_CACHE_SIZE` to env var loading, and main.go already creates the cache based on that. The config file approach supersedes this — refactor main.go to read feature config from the JSON file first, then apply env var overrides (including `SCD_DNS_CACHE_SIZE`). The existing `Config` struct keeps the env var field for override purposes, but the primary source becomes the config file.

Add `SCD_CONFIG_FILE` to the existing env var loading. Query log and DNS cache settings come from the config file (see Config File section above), with env var overrides:

| Env Var | Overrides config field | Description |
|---|---|---|
| `SCD_CONFIG_FILE` | — | Path to JSON config file (default `/etc/scrolldaddy/dns.json`) |
| `SCD_DNS_CACHE_SIZE` | `dns_cache.max_size` | Also implicitly sets `dns_cache.enabled` to false if 0 |
| `SCD_QUERY_LOG_DIR` | `query_log.dir` | Empty string disables query logging |
| `SCD_QUERY_LOG_BUFFER` | `query_log.buffer_size` | Channel buffer size |
| `SCD_QUERY_LOG_MAX_SIZE` | `query_log.max_file_size` | Per-file rotation threshold |

### 6. Main (`cmd/dns/main.go`)

```go
fc, err := config.LoadFeatureConfig(cfg.ConfigFile)
if err != nil {
    log.Fatalf("FATAL config file: %v", err)
}
config.MergeEnvOverrides(fc)

var dc *dnscache.Cache
if fc.DNSCache.Enabled && fc.DNSCache.MaxSize > 0 {
    dc = dnscache.New(fc.DNSCache.MaxSize)
    logger.Info("DNS response cache enabled (max %d entries)", fc.DNSCache.MaxSize)
}

var ql *querylog.Logger
if fc.QueryLog.Enabled && fc.QueryLog.Dir != "" {
    ql = querylog.New(fc.QueryLog.Dir, fc.QueryLog.BufferSize, fc.QueryLog.MaxFileSize)
    defer ql.Close()
    logger.Info("query logging enabled (dir=%s, buffer=%d, max_size=%d)",
        fc.QueryLog.Dir, fc.QueryLog.BufferSize, fc.QueryLog.MaxFileSize)
}

res := resolver.New(c, dc, ql, cfg.UpstreamPrimary, cfg.UpstreamSecondary)
```

### 7. API Endpoints (`internal/doh/handler.go`)

Two new endpoints:

**`GET /device/{uid}/log?lines=100`** (API-key protected)
Returns the last N lines of the device's query log as `text/plain`. Defaults to 100 lines.

**`POST /device/{uid}/log/purge`** (API-key protected)
Truncates the device's log file. Returns `{"status": "purged"}`.

### 8. PHP Data Class (`plugins/scrolldaddy-html5/data/devices_class.php`)

Add to `$field_specifications`:
```php
'sdd_log_queries' => array('type' => 'boolean', 'default' => 'false'),
```

This creates the column automatically when the plugin is activated.

### 9. PHP Device Admin UI

Add a checkbox toggle for "Enable query logging" on the device edit page. This sets `sdd_log_queries` on the device record.

## Unit Tests (`internal/querylog/querylog_test.go`)

| Test | What it verifies |
|---|---|
| `TestRecordWritesLine` | Record an entry, verify the file exists and contains the expected tab-separated line |
| `TestMultipleDevices` | Entries for different UIDs go to different files |
| `TestFileReuse` | Multiple entries for the same UID reuse the same file handle (don't reopen) |
| `TestBufferFullDrops` | Fill the channel, verify Record doesn't block and the entry is dropped |
| `TestRotation` | Write entries exceeding maxFileSize, verify `.log.1` backup created and active `.log` is small |
| `TestRotationOverwritesBackup` | Trigger rotation twice, verify only one `.log.1` exists (no `.log.2`) |
| `TestSizeTrackingAcrossRestart` | Write entries, close logger, create new logger, verify size is correct from `Stat()` |
| `TestZeroMaxSizeDisablesRotation` | With maxFileSize=0, file grows without rotation |
| `TestReadTail` | Write N lines, ReadTail(5) returns the last 5 |
| `TestReadTailEmpty` | ReadTail on a nonexistent file returns empty slice, no error |
| `TestPurge` | Write entries, Purge, verify file is truncated |
| `TestClose` | Close drains the channel and closes all file handles |
| `TestNilLoggerSafe` | Calling Record on nil logger doesn't panic |
| `TestConcurrentWrites` | Parallel Records from multiple goroutines don't race (run with `-race`) |
| `BenchmarkRecord` | Baseline allocation measurement via `b.ReportAllocs()` for future optimization |

## Deployment

1. Create the config file (optional — defaults apply without it):
   ```bash
   mkdir -p /etc/scrolldaddy
   cat > /etc/scrolldaddy/dns.json <<'EOF'
   {
     "dns_cache": { "enabled": true, "max_size": 10000 },
     "query_log": { "enabled": true }
   }
   EOF
   ```
2. Add `sdd_log_queries` field to the PHP device data class, then deactivate/activate the plugin to create the column
3. Create the log directory: `mkdir -p /var/log/scrolldaddy/queries && chown scrolldaddy:scrolldaddy /var/log/scrolldaddy/queries`
4. Deploy the new DNS server binary

No database migrations on the Go side. No new Go dependencies. No external tools required — file rotation is handled internally.

To toggle features at runtime, edit `/etc/scrolldaddy/dns.json` and send SIGHUP or `POST /reload`.

## Ancillary Fix: DoT `RecordQuery` Call

The DoT handler in `internal/dot/server.go` calls `res.Resolve(uid, &query)` but does not call `cache.RecordQuery(uid)` — unlike the DoH handler which calls it before every resolve. The query log will work correctly (it's inside `Resolve()`), but the last-seen tracking for DoT connections is broken.

**Fix while we're here:** Pass the `*cache.Cache` to the DoT server and add `cache.RecordQuery(uid)` before the `res.Resolve()` call in `handleConn()`, matching what DoH does.

## Future Considerations (Not In Scope)

- **PHP log viewer page**: a device dashboard tab that calls the `/device/{uid}/log` API endpoint and displays recent queries in a table
- **Log streaming via WebSocket**: real-time query feed for debugging
- **Aggregation**: periodic summarization (top domains, block counts per day) for dashboard widgets
- **Per-device retention settings**: different max age or max size per device
