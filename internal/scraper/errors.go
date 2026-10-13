package scraper

import (
	"errors"
	"fmt"
	"time"
)

// These errors are part of the Source contract: any Source implementation
// returns them so the scraper can react without knowing about HTTP.
var (
	ErrUnauthorized = errors.New("authentication/authorization failed")
	ErrNoMorePages  = errors.New("no more pages")
)

type RateLimitError struct {
	RetryAfter time.Duration
}

func (e RateLimitError) Error() string {
	return fmt.Sprintf("rate limited, retry after %v", e.RetryAfter)
}
