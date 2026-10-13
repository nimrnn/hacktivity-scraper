// Package config parses command-line flags and environment variables.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

type Config struct {
	Username  string
	Token     string
	Workers   int
	RateLimit int
	DBPath    string
	FromDate  time.Time
}

// Load reads flags (with env vars as defaults for credentials) and validates them.
func Load() (Config, error) {
	var (
		c        Config
		fromDate string
	)

	flag.StringVar(&c.Username, "username", os.Getenv("H1_USERNAME"), "HackerOne username (or set H1_USERNAME)")
	flag.StringVar(&c.Token, "token", os.Getenv("H1_TOKEN"), "HackerOne API token (or set H1_TOKEN)")
	flag.IntVar(&c.Workers, "workers", 5, "number of concurrent page workers")
	flag.IntVar(&c.RateLimit, "rate", 5, "maximum API requests per second")
	flag.StringVar(&c.DBPath, "db", "reports.sqlite", "path to the SQLite database file")
	flag.StringVar(&fromDate, "from-date", "2020-01-01", "only fetch reports disclosed on or after this date (yyyy-mm-dd)")
	flag.Parse()

	if c.Username == "" || c.Token == "" {
		return Config{}, errors.New("HackerOne username and API token are required")
	}
	if c.Workers < 1 {
		return Config{}, errors.New("-workers must be at least 1")
	}
	if c.RateLimit < 1 {
		return Config{}, errors.New("-rate must be at least 1")
	}

	t, err := time.Parse(time.DateOnly, fromDate)
	if err != nil {
		return Config{}, fmt.Errorf("invalid -from-date %q: expected yyyy-mm-dd", fromDate)
	}
	c.FromDate = t

	return c, nil
}
