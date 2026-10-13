package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"hacktivity-scraper/internal/report"
)

type ReportStore struct {
	db *sql.DB
}

func NewReportStore(db *sql.DB) *ReportStore {
	return &ReportStore{db: db}
}

func (s *ReportStore) Exists(ctx context.Context, id int) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM reports WHERE report_id = ?)`, id,
	).Scan(&exists)
	return exists, err
}

// Insert saves a report. If the ID already exists it does nothing.
func (s *ReportStore) Insert(ctx context.Context, r report.Report) error {
	cve := r.CVE
	if cve == nil {
		cve = []string{} // store "[]" rather than "null"
	}
	cveJSON, err := json.Marshal(cve)
	if err != nil {
		return fmt.Errorf("encoding cve list: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO reports (report_id, cwe, title, cve, url, program, markdown)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(report_id) DO NOTHING`,
		r.ID, r.CWE, r.Title, string(cveJSON), r.URL, r.Program, r.Markdown,
	)
	return err
}
