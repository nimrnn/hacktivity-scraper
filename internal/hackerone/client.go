// Package hackerone talks to the HackerOne API and implements scraper.Source.
package hackerone

import (
	"net/http"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

type Client struct {
	username       string
	token          string
	httpClient     *http.Client
	listLimiter    *rate.Limiter // for the hacktivity API
	contentLimiter *rate.Limiter // for the per-report .json pages
}

func NewClient(username, token string, requestsPerSecond int) *Client {
	return &Client{
		username:       username,
		token:          token,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		listLimiter:    rate.NewLimiter(rate.Limit(requestsPerSecond), 1),
		contentLimiter: rate.NewLimiter(rate.Limit(2), 1),
	}
}

// retryAfter reads the Retry-After header, defaulting to 30 seconds.
func retryAfter(resp *http.Response) time.Duration {
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
		return time.Duration(s) * time.Second
	}
	return 30 * time.Second
}
