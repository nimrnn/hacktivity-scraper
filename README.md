# hacktivity-scraper

Downloads disclosed HackerOne reports (metadata + markdown body) into a local SQLite database. Re-running is safe: reports already stored are skipped.

The point is not the scrape, it's what the data is for: feeding an AI agent that mines real reports for a specific bug class and turns them into a hunting skill - checklists, techniques, edge cases, and bypasses grounded in what researchers actually did. `cwe` is the main pivot, so an IDOR skill only reads IDOR reports.

See [SKILL.md](SKILL.md) for the agent workflow that does this (database discovery, CWE filtering, sampling, extraction, and output format).

## Requirements

- Go 1.26+
- A HackerOne API token (create one at <https://hackerone.com/settings/api_token>)

The scraper uses the HackerOne API, so your account needs API access. CVE/CWE data comes from the hacktivity feed.

## Install

    git clone https://github.com/nimrnn/hacktivity-scraper.git
    cd hacktivity-scraper
    go mod download

## Run

    export H1_USERNAME=your-username
    export H1_TOKEN=your-api-token
    go run ./cmd/scraper -from-date 2024-01-01

Or build a binary:

    make build
    ./bin/scraper -from-date 2024-01-01

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-username` | `$H1_USERNAME` | HackerOne username |
| `-token` | `$H1_TOKEN` | HackerOne API token |
| `-from-date` | `2020-01-01` | Only fetch reports disclosed on or after this date (`yyyy-mm-dd`) |
| `-workers` | `5` | Number of concurrent page fetchers |
| `-rate` | `5` | Max hacktivity API requests per second |
| `-db` | `reports.sqlite` | Path to the SQLite database file |

Press Ctrl+C to stop; already-fetched reports stay in the database.

## Output

Reports are written to the `reports` table:

| Column | Type | Notes |
| --- | --- | --- |
| `report_id` | INTEGER | Primary key |
| `cwe` | TEXT | Human-readable label, e.g. `Insecure Direct Object Reference (IDOR)`. Empty when unclassified |
| `title` | TEXT | Report title |
| `cve` | TEXT | JSON array of CVE IDs, e.g. `["CVE-2024-1234"]`, `[]` when none |
| `url` | TEXT | Public report URL |
| `program` | TEXT | Program handle |
| `markdown` | TEXT | Full `vulnerability_information` body, may be empty |

`cwe` is a name, not a number, and XSS is split into variants (`Reflected`, `Stored`, `DOM`, `Generic`). Discover the exact labels before filtering:

    sqlite3 -header -column reports.sqlite \
      "SELECT cwe, COUNT(*) AS n FROM reports WHERE cwe != '' GROUP BY cwe ORDER BY n DESC LIMIT 40;"

Filter by bug class:

    # IDOR / BOLA
    sqlite3 reports.sqlite \
      "SELECT report_id, program, title FROM reports
       WHERE cwe LIKE '%IDOR%' OR cwe LIKE '%Insecure Direct Object%'
       ORDER BY report_id DESC LIMIT 50;"

    # every XSS variant
    sqlite3 reports.sqlite \
      "SELECT cwe, COUNT(*) FROM reports WHERE cwe LIKE '%Cross-site Scripting%' GROUP BY cwe;"

Pull report bodies for analysis (keep output bounded - bodies reach 80 KB):

    sqlite3 reports.sqlite \
      "SELECT report_id, title, markdown FROM reports
       WHERE cwe LIKE '%Server-Side Request Forgery%' AND length(markdown) > 800
       ORDER BY report_id DESC LIMIT 10;"

For read-only access without touching the file:

    sqlite3 'file:reports.sqlite?mode=ro' "SELECT COUNT(*) FROM reports;"

## Building a hunting skill from the data

The intended consumer is an AI agent. `SKILL.md` describes the full loop: find or build the database, resolve the bug class to real CWE labels, sample reports without flooding context, extract techniques and edge cases with `report_id` evidence, then write a new skill from them.

Typical request to give the agent:

> Build me a skill for finding IDOR. Use the existing reports.sqlite, don't re-scrape.

The agent queries the database directly; you do not need to export anything.

## How it works

- `internal/hackerone` - API client (`scraper.Source`): paged hacktivity listing plus per-report markdown fetch, with rate limiting and 429 retry handling.
- `internal/scraper` - fetch pipeline: concurrent page workers feed a single writer goroutine, so SQLite only ever has one writer. Stops on the last page, auth errors, or cancellation.
- `internal/storage/sqlite` - schema and `scraper.Store` implementation.
- `internal/report` - shared `Report` domain type.

Rate limiting is per client: `-rate` for the hacktivity listing, a fixed 2 req/s for report bodies. `429` responses are retried up to 5 times using the `Retry-After` header.

## Development

    make vet     # go build ./... && go vet ./...
    make run     # go run ./cmd/scraper

## Notes

- The database file and build artifacts are gitignored.
- Report content belongs to the respective programs and researchers; respect HackerOne's terms and rate limits.
