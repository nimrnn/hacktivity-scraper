package hackerone

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"hacktivity-scraper/internal/report"
	"hacktivity-scraper/internal/scraper"
)

const hacktivityURL = "https://api.hackerone.com/v1/hackers/hacktivity"
const pageSize = 25

// ListPage fetches one page of disclosed reports between from and to (inclusive).
func (c *Client) ListPage(ctx context.Context, page int, from, to time.Time) ([]report.Report, error) {
	if err := c.listLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	u, err := url.Parse(hacktivityURL)
	if err != nil {
		return nil, fmt.Errorf("parsing url: %w", err)
	}

	// Dates come from time.Time, never raw strings, so the query can't be tampered with.
	query := u.Query()
	query.Set("queryString", fmt.Sprintf(
		"disclosed:true AND disclosed_at:>=%s AND disclosed_at:<=%s",
		from.Format(time.DateOnly), to.Format(time.DateOnly),
	))
	query.Set("page[number]", strconv.Itoa(page))
	query.Set("page[size]", strconv.Itoa(pageSize))
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.username, c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting page %d: %w", page, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// continue below
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, scraper.ErrUnauthorized
	case http.StatusTooManyRequests:
		return nil, scraper.RateLimitError{RetryAfter: retryAfter(resp)}
	default:
		return nil, fmt.Errorf("page %d: status %s, body: %s", page, resp.Status, body)
	}

	var parsed parentData
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("unmarshalling page %d: %w", page, err)
	}
	if len(parsed.Data) == 0 {
		return nil, scraper.ErrNoMorePages
	}

	reports := make([]report.Report, 0, len(parsed.Data))
	for _, d := range parsed.Data {
		reports = append(reports, d.toReport())
	}
	return reports, nil
}
