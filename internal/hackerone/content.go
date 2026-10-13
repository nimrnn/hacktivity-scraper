package hackerone

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"hacktivity-scraper/internal/scraper"
)

// ReportMarkdown fetches the markdown body of a report by appending ".json" to its URL.
func (c *Client) ReportMarkdown(ctx context.Context, reportURL string) (string, error) {
	if err := c.contentLimiter.Wait(ctx); err != nil {
		return "", err
	}

	u := reportURL + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("building request for %s: %w", u, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting %s: %w", u, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue below
	case http.StatusTooManyRequests:
		return "", scraper.RateLimitError{RetryAfter: retryAfter(resp)}
	default:
		return "", fmt.Errorf("request to %s failed with status: %s", u, resp.Status)
	}

	var content reportContent
	if err := json.NewDecoder(resp.Body).Decode(&content); err != nil {
		return "", fmt.Errorf("decoding %s: %w", u, err)
	}
	return content.VulnInfo, nil
}
