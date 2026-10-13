# hacktivity-scraper

Downloads disclosed HackerOne reports (metadata + markdown body) into a local SQLite database. Re-running is safe: reports already stored are skipped.

## Requirements

- Go 1.26+
- A HackerOne API token (create one at <https://hackerone.com/settings/api_token>)

The scraper uses the HackerOne API, so your account needs API access. CVE/CWE data comes from the hacktivity feed.

## Install

    git clone https://github.com/yuzaaone/hacktivity-scraper.git
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
| `cwe` | TEXT | CWE identifier, may be empty |
| `title` | TEXT | Report title |
| `cve` | TEXT | JSON array of CVE IDs, e.g. `["CVE-2024-1234"]` |
| `url` | TEXT | Public report URL |
| `program` | TEXT | Program handle |
| `markdown` | TEXT | Full `vulnerability_information` body |

Example query:

    sqlite3 reports.sqlite \
      "SELECT report_id, program, title FROM reports ORDER BY report_id DESC LIMIT 20;"

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
