// Package report holds the core domain type shared by the other packages.
package report

type Report struct {
	ID       int
	Title    string
	CVE      []string
	CWE      string
	URL      string
	Program  string
	Markdown string
}
