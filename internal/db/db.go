package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// DB wraps the PostgreSQL connection.
type DB struct {
	conn *sql.DB
}

// DeviceRow holds raw data from the device+profile join query.
type DeviceRow struct {
	DeviceID             int64
	ResolverUID          string
	PrimaryProfileID     int64
	SecondaryProfileID   sql.NullInt64
	IsActive             bool
	Timezone             string
	ScheduleStart        sql.NullString
	ScheduleEnd          sql.NullString
	ScheduleDays         sql.NullString // JSON array: ["mon","tue"]
	ScheduleTimezone     sql.NullString
	PrimarySafeSearch    sql.NullBool
	PrimarySafeYouTube   sql.NullBool
	SecondarySafeSearch  sql.NullBool
	SecondarySafeYouTube sql.NullBool
}

// RuleRow holds a single custom DNS rule.
type RuleRow struct {
	ProfileID int64
	Hostname  string
	Action    int // 0=block, 1=allow
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

// Close closes the database connection.
func (db *DB) Close() {
	db.conn.Close()
}

// ValidateSchema checks that all required tables and columns exist.
// Returns a descriptive error listing every missing table/column.
func (db *DB) ValidateSchema() error {
	expected := map[string][]string{
		"cdd_ctlddevices": {
			"cdd_ctlddevice_id", "cdd_resolver_uid",
			"cdd_cdp_ctldprofile_id_primary", "cdd_cdp_ctldprofile_id_secondary",
			"cdd_is_active", "cdd_timezone", "cdd_delete_time",
		},
		"cdp_ctldprofiles": {
			"cdp_ctldprofile_id", "cdp_schedule_start", "cdp_schedule_end",
			"cdp_schedule_days", "cdp_schedule_timezone",
			"cdp_safesearch", "cdp_safeyoutube",
		},
		"cdf_ctldfilters": {
			"cdf_cdp_ctldprofile_id", "cdf_filter_pk", "cdf_is_active",
		},
		"cdr_ctldrules": {
			"cdr_cdp_ctldprofile_id", "cdr_rule_hostname", "cdr_rule_action", "cdr_is_active",
		},
		"bld_blocklist_domains": {
			"bld_category_key", "bld_domain",
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
	return nil
}

// LoadDevices loads all active devices with profile and schedule info.
func (db *DB) LoadDevices() ([]*DeviceRow, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("SET TRANSACTION READ ONLY"); err != nil {
		return nil, err
	}

	const query = `
		SELECT
			d.cdd_ctlddevice_id,
			d.cdd_resolver_uid,
			d.cdd_cdp_ctldprofile_id_primary,
			d.cdd_cdp_ctldprofile_id_secondary,
			COALESCE(d.cdd_is_active, false),
			COALESCE(d.cdd_timezone, 'UTC'),
			p2.cdp_schedule_start,
			p2.cdp_schedule_end,
			p2.cdp_schedule_days,
			p2.cdp_schedule_timezone,
			p1.cdp_safesearch,
			p1.cdp_safeyoutube,
			p2.cdp_safesearch,
			p2.cdp_safeyoutube
		FROM cdd_ctlddevices d
		JOIN cdp_ctldprofiles p1
			ON d.cdd_cdp_ctldprofile_id_primary = p1.cdp_ctldprofile_id
		LEFT JOIN cdp_ctldprofiles p2
			ON d.cdd_cdp_ctldprofile_id_secondary = p2.cdp_ctldprofile_id
		WHERE d.cdd_delete_time IS NULL
		  AND d.cdd_is_active = TRUE
		  AND d.cdd_resolver_uid IS NOT NULL
		  AND d.cdd_resolver_uid != ''
	`

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
			&d.PrimaryProfileID,
			&d.SecondaryProfileID,
			&d.IsActive,
			&d.Timezone,
			&d.ScheduleStart,
			&d.ScheduleEnd,
			&d.ScheduleDays,
			&d.ScheduleTimezone,
			&d.PrimarySafeSearch,
			&d.PrimarySafeYouTube,
			&d.SecondarySafeSearch,
			&d.SecondarySafeYouTube,
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

// LoadFilters loads all active filter assignments, keyed by profile ID.
// Note: cdf_cdp_ctldprofile_id is varchar in the schema but stores integer values.
func (db *DB) LoadFilters() (map[int64][]string, error) {
	const query = `
		SELECT
			cdf_cdp_ctldprofile_id::bigint AS profile_id,
			cdf_filter_pk AS category_key
		FROM cdf_ctldfilters
		WHERE cdf_is_active = 1
		  AND cdf_cdp_ctldprofile_id ~ '^[0-9]+$'
	`
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[int64][]string{}
	for rows.Next() {
		var profileID int64
		var categoryKey string
		if err := rows.Scan(&profileID, &categoryKey); err != nil {
			return nil, err
		}
		result[profileID] = append(result[profileID], categoryKey)
	}
	return result, rows.Err()
}

// LoadRules loads all active custom rules, keyed by profile ID.
// Note: cdr_cdp_ctldprofile_id is varchar in the schema but stores integer values.
func (db *DB) LoadRules() (map[int64][]*RuleRow, error) {
	const query = `
		SELECT
			cdr_cdp_ctldprofile_id::bigint AS profile_id,
			cdr_rule_hostname AS hostname,
			cdr_rule_action AS action
		FROM cdr_ctldrules
		WHERE cdr_is_active = 1
		  AND cdr_cdp_ctldprofile_id ~ '^[0-9]+$'
	`
	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[int64][]*RuleRow{}
	for rows.Next() {
		r := &RuleRow{}
		if err := rows.Scan(&r.ProfileID, &r.Hostname, &r.Action); err != nil {
			return nil, err
		}
		result[r.ProfileID] = append(result[r.ProfileID], r)
	}
	return result, rows.Err()
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

// ParseScheduleDays parses the cdp_schedule_days JSON field (e.g. ["mon","tue","wed"]).
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
