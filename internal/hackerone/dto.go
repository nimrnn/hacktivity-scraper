package hackerone

import "hacktivity-scraper/internal/report"

// These structs mirror the API's JSON. They stay private to this package;
// callers only ever see report.Report.

type parentData struct {
	Data []data `json:"data"`
}

type data struct {
	ID            int           `json:"id"`
	Attributes    attributes    `json:"attributes"`
	Relationships relationships `json:"relationships"`
}

type attributes struct {
	Title string   `json:"title"`
	URL   string   `json:"url"`
	CVE   []string `json:"cve_ids"`
	CWE   string   `json:"cwe"`
}

type relationships struct {
	Program programRel `json:"program"`
}

type programRel struct {
	Data programData `json:"data"`
}

type programData struct {
	Attributes programAttributes `json:"attributes"`
}

type programAttributes struct {
	Handle string `json:"handle"`
}

func (d data) toReport() report.Report {
	return report.Report{
		ID:      d.ID,
		Title:   d.Attributes.Title,
		CVE:     d.Attributes.CVE,
		CWE:     d.Attributes.CWE,
		URL:     d.Attributes.URL,
		Program: d.Relationships.Program.Data.Attributes.Handle,
	}
}

type reportContent struct {
	VulnInfo string `json:"vulnerability_information"`
}
