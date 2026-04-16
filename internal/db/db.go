package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// errWriter is where schema warnings are written. Points to stderr by default;
// tests can redirect it to suppress output.
var errWriter = os.Stderr

// DB wraps the PostgreSQL connection.
type DB struct {
	conn *sql.DB

	// Optional feature columns detected at startup via ValidateSchema.
	// If a column is absent (older schema), the feature is silently disabled
	// and the service continues running. Add new optional columns here as
	// features are introduced, so the DNS server can be deployed before the
	// web app has run its schema migration.
	HasLogQueriesCol bool
}

// DeviceRow holds raw data from the device query.
type DeviceRow struct {
	DeviceID    int64
	ResolverUID string
	IsActive    bool
	Timezone    string
	LogQueries  bool
}

// ScheduledBlockRow holds raw data from the scheduled blocks query.
// An always-on block (IsAlwaysOn=true) has no schedule and is active 24/7;
// the resolver short-circuits isBlockActive() when this is set.
type ScheduledBlockRow struct {
	BlockID          int64
	DeviceID         int64
	Name             string
	IsAlwaysOn       bool
	ScheduleStart    sql.NullString
	ScheduleEnd      sql.NullString
	ScheduleDays     sql.NullString
	ScheduleTimezone sql.NullString
}

// ScheduledBlockRuleRow holds a filter/service/domain rule for a scheduled block.
type ScheduledBlockRuleRow struct {
	BlockID int64
	Key     string
	Action  int
}

// Connect opens and verifies a PostgreSQL connection.
func Connect(host, port, dbname, user, password string) (*DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		host, port, dbname, user, password,
	)
	conn, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(5)
	conn.SetMaxIdleConns(2)
	conn.SetConnMaxLifetime(5 * time.Minute)

	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, err
	}
	return &DB{conn: conn}, nil
}

// Ping checks the database connection is alive.
func (db *DB) Ping() error {
	return db.conn.Ping()
}

// PingContext checks the database connection with a deadline. Callers should
// always provide a short timeout so a half-open TCP connection can't wedge
// the caller waiting for bytes that will never arrive.
func (db *DB) PingContext(ctx context.Context) error {
	return db.conn.PingContext(ctx)
}

// Close closes the database connection.
func (db *DB) Close() {
	db.conn.Close()
}

// columnExists reports whether a column exists in a table.
func (db *DB) columnExists(table, column string) bool {
	var n int
	err := db.conn.QueryRow(
		`SELECT COUNT(*) FROM information_schema.columns WHERE table_name=$1 AND column_name=$2`,
		table, column,
	).Scan(&n)
	return err == nil && n > 0
}

// ValidateSchema checks that all required tables and columns exist, and probes
// for optional feature columns introduced in newer schema versions.
//
// Required columns: fatal if missing — the service cannot function without them.
// Optional columns: if absent, the feature is disabled and a warning is logged.
//   The query in LoadDevices adapts based on which optional columns are present,
//   so the DNS server can be deployed before the web app has run its migration.
//
// When adding a new optional column:
//   1. Add it to optionalCols below (not required).
//   2. Add a HasXxxCol bool field to DB.
//   3. Set it in the loop below.
//   4. Use it in the relevant Load* method to build a conditional query.
func (db *DB) ValidateSchema() error {
	// logger is the package-level logger; import it here for warnings.
	// We use fmt.Fprintf to stderr to avoid a circular import with logger package.
	expected := map[string][]string{
		"sdd_devices": {
			"sdd_device_id", "sdd_resolver_uid",
			"sdd_is_active", "sdd_timezone", "sdd_delete_time",
		},
		"bld_blocklist_domains": {
			"bld_category_key", "bld_domain",
		},
		"sdb_scheduled_blocks": {
			"sdb_scheduled_block_id", "sdb_sdd_device_id", "sdb_name",
			"sdb_is_always_on",
			"sdb_schedule_start", "sdb_schedule_end", "sdb_schedule_days",
			"sdb_schedule_timezone", "sdb_is_active", "sdb_delete_time",
		},
		"sbf_scheduled_block_filters": {
			"sbf_scheduled_block_filter_id", "sbf_sdb_scheduled_block_id",
			"sbf_filter_key", "sbf_action",
		},
		"sbs_scheduled_block_services": {
			"sbs_scheduled_block_service_id", "sbs_sdb_scheduled_block_id",
			"sbs_service_key", "sbs_action",
		},
		"sbr_scheduled_block_rules": {
			"sbr_scheduled_block_rule_id", "sbr_sdb_scheduled_block_id",
			"sbr_hostname", "sbr_is_active", "sbr_action",
		},
	}

	var errs []string
	for table, cols := range expected {
		rows, err := db.conn.Query(
			`SELECT column_name FROM information_schema.columns WHERE table_name = $1`,
			table,
		)
		if err != nil {
			return fmt.Errorf("schema validation query failed for %s: %w", table, err)
		}

		existing := map[string]bool{}
		for rows.Next() {
			var col string
			if err := rows.Scan(&col); err != nil {
				rows.Close()
				return err
			}
			existing[col] = true
		}
		rows.Close()

		if len(existing) == 0 {
			errs = append(errs, fmt.Sprintf("  - Table %s: not found", table))
			continue
		}
		for _, col := range cols {
			if !existing[col] {
				errs = append(errs, fmt.Sprintf("  - Table %s: missing column %q", table, col))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("schema validation failed:\n%s", strings.Join(errs, "\n"))
	}

	// Probe optional feature columns. Missing = feature disabled, not fatal.
	db.HasLogQueriesCol = db.columnExists("sdd_devices", "sdd_log_queries")
	if !db.HasLogQueriesCol {
		fmt.Fprintf(errWriter, "WARN  sdd_devices.sdd_log_queries not found — per-device query logging disabled until schema is updated\n")
	}

	return nil
}

// LoadDevices loads all active devices with primary profile info.
func (db *DB) LoadDevices() ([]*DeviceRow, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("SET TRANSACTION READ ONLY"); err != nil {
		return nil, err
	}

	// Build query conditionally: if the optional sdd_log_queries column is
	// absent (older schema), substitute a literal false so the rest of the
	// code path works unchanged.
	logQueriesExpr := "false"
	if db.HasLogQueriesCol {
		logQueriesExpr = "COALESCE(d.sdd_log_queries, false)"
	}
	query := fmt.Sprintf(`
		SELECT
			d.sdd_device_id,
			d.sdd_resolver_uid,
			COALESCE(d.sdd_is_active, false),
			COALESCE(d.sdd_timezone, 'UTC'),
			%s
		FROM sdd_devices d
		WHERE d.sdd_delete_time IS NULL
		  AND d.sdd_is_active = TRUE
		  AND d.sdd_resolver_uid IS NOT NULL
		  AND d.sdd_resolver_uid != ''
	`, logQueriesExpr)

	rows, err := tx.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*DeviceRow
	for rows.Next() {
		d := &DeviceRow{}
		if err := rows.Scan(
			&d.DeviceID,
			&d.ResolverUID,
			&d.IsActive,
			&d.Timezone,
			&d.LogQueries,
		); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tx.Commit()
	return devices, nil
}

// LoadBlocklistDomains streams all blocklist domains from the DB.
// Returns map[categoryKey]map[domain]bool.
func (db *DB) LoadBlocklistDomains() (map[string]map[string]bool, error) {
	const query = `SELECT bld_category_key, bld_domain FROM bld_blocklist_domains`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[string]map[string]bool{}
	for rows.Next() {
		var category, domain string
		if err := rows.Scan(&category, &domain); err != nil {
			return nil, err
		}
		if result[category] == nil {
			result[category] = map[string]bool{}
		}
		result[category][domain] = true
	}
	return result, rows.Err()
}

// GetBlocklistVersion returns the current scrolldaddy_blocklist_version from stg_settings.
// Returns an empty string if the setting does not exist or the query fails.
func (db *DB) GetBlocklistVersion() string {
	var version string
	err := db.conn.QueryRow(
		`SELECT stg_value FROM stg_settings WHERE stg_name = 'scrolldaddy_blocklist_version' LIMIT 1`,
	).Scan(&version)
	if err != nil {
		return ""
	}
	return version
}

// LoadScheduledBlocks loads all active, non-deleted scheduled blocks.
// Always-on blocks (sdb_is_always_on = true) have no schedule and are treated as
// always-active by the resolver. Every device has exactly one.
func (db *DB) LoadScheduledBlocks() ([]*ScheduledBlockRow, error) {
	const query = `
		SELECT
			sdb_scheduled_block_id,
			sdb_sdd_device_id,
			COALESCE(sdb_name, ''),
			COALESCE(sdb_is_always_on, false),
			sdb_schedule_start,
			sdb_schedule_end,
			sdb_schedule_days,
			sdb_schedule_timezone
		FROM sdb_scheduled_blocks
		WHERE sdb_is_active = TRUE
		  AND sdb_delete_time IS NULL
	`
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []*ScheduledBlockRow
	for rows.Next() {
		b := &ScheduledBlockRow{}
		if err := rows.Scan(
			&b.BlockID,
			&b.DeviceID,
			&b.Name,
			&b.IsAlwaysOn,
			&b.ScheduleStart,
			&b.ScheduleEnd,
			&b.ScheduleDays,
			&b.ScheduleTimezone,
		); err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
	}
	return blocks, rows.Err()
}

// LoadScheduledBlockFilterRules loads all filter rules for active scheduled blocks.
func (db *DB) LoadScheduledBlockFilterRules() ([]*ScheduledBlockRuleRow, error) {
	const query = `
		SELECT
			sbf_sdb_scheduled_block_id,
			sbf_filter_key,
			sbf_action
		FROM sbf_scheduled_block_filters
		JOIN sdb_scheduled_blocks ON sdb_scheduled_block_id = sbf_sdb_scheduled_block_id
		WHERE sdb_is_active = TRUE
		  AND sdb_delete_time IS NULL
	`
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*ScheduledBlockRuleRow
	for rows.Next() {
		r := &ScheduledBlockRuleRow{}
		if err := rows.Scan(&r.BlockID, &r.Key, &r.Action); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// LoadScheduledBlockServiceRules loads all service rules for active scheduled blocks.
func (db *DB) LoadScheduledBlockServiceRules() ([]*ScheduledBlockRuleRow, error) {
	const query = `
		SELECT
			sbs_sdb_scheduled_block_id,
			sbs_service_key,
			sbs_action
		FROM sbs_scheduled_block_services
		JOIN sdb_scheduled_blocks ON sdb_scheduled_block_id = sbs_sdb_scheduled_block_id
		WHERE sdb_is_active = TRUE
		  AND sdb_delete_time IS NULL
	`
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*ScheduledBlockRuleRow
	for rows.Next() {
		r := &ScheduledBlockRuleRow{}
		if err := rows.Scan(&r.BlockID, &r.Key, &r.Action); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// LoadScheduledBlockDomainRules loads all domain rules for active scheduled blocks.
func (db *DB) LoadScheduledBlockDomainRules() ([]*ScheduledBlockRuleRow, error) {
	const query = `
		SELECT
			sbr_sdb_scheduled_block_id,
			sbr_hostname,
			sbr_action
		FROM sbr_scheduled_block_rules
		JOIN sdb_scheduled_blocks ON sdb_scheduled_block_id = sbr_sdb_scheduled_block_id
		WHERE sbr_is_active = 1
		  AND sdb_is_active = TRUE
		  AND sdb_delete_time IS NULL
	`
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*ScheduledBlockRuleRow
	for rows.Next() {
		r := &ScheduledBlockRuleRow{}
		if err := rows.Scan(&r.BlockID, &r.Key, &r.Action); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// ParseScheduleDays parses the schedule_days JSON field (e.g. ["mon","tue","wed"]).
func ParseScheduleDays(raw sql.NullString) []string {
	if !raw.Valid || raw.String == "" {
		return nil
	}
	var days []string
	if err := json.Unmarshal([]byte(raw.String), &days); err != nil {
		return nil
	}
	return days
}
