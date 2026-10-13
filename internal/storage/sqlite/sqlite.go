// Package sqlite stores reports in a local SQLite file and implements scraper.Store.
package sqlite

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

const schema = `
CREATE TABLE IF NOT EXISTS reports (
	report_id INTEGER PRIMARY KEY,
	cwe       TEXT NOT NULL DEFAULT '',
	title     TEXT NOT NULL,
	cve       TEXT NOT NULL DEFAULT '[]',
	url       TEXT NOT NULL,
	program   TEXT NOT NULL DEFAULT '',
	markdown  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_reports_program ON reports(program);`

// Open opens (or creates) the database and makes sure the schema exists.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite allows one writer at a time

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	return db, nil
}
